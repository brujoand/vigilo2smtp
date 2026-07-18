#!/usr/bin/env python3
"""
Re-authentication web UI for vigilo-notify.

The OAuth client is Vigilo's Android app, whose registered redirect URI is the
custom scheme ``app://ch-parent-android.vigilo.no``. A browser cannot follow
that, so this UI cannot be the callback: instead the user completes the login,
the browser fails to navigate to the ``app://`` URL, and the user pastes that
failed URL (or just the code) back into the form here.

If Vigilo ever registers an https redirect for us, set VIGILO_REDIRECT_URI to
it and ``GET /oauth/callback`` handles the flow automatically -- no code change.

Endpoints:
    GET  /                 status page, login link, paste form
    POST /reauth           exchange a pasted code (or full redirect URL)
    GET  /oauth/callback   automatic callback, only reachable with an https redirect
    GET  /healthz          liveness -- always 200 while the server is serving
    GET  /status           JSON status (booleans and timestamps only)

Nothing here logs or renders token material.
"""

import base64
import hashlib
import html
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlparse

import poller

# The login happens on Vigilo's site, possibly via BankID on a second device,
# so "as long as the login takes" is not a couple of minutes. 15 was too tight:
# the form expired while the user was still authenticating.
PENDING_TTL = 60 * 60
MAX_PENDING = 5
# Auth codes are single-use; a double-submitted form would otherwise show a
# confusing invalid_grant right after a success.
RECENT_SUCCESS_WINDOW = 30

# PKCE is OFF by default, which is not the usual advice and needs the reason
# recorded. This client is confidential (it authenticates the token call with a
# client secret) and the flow is a manual paste, so PKCE buys little. Against
# that: the bare-code paste path carries no state, so there is no way to know
# which verifier belongs to the pasted code -- any guess that misses turns a
# working exchange into invalid_grant. The known-good reference flow for this
# client sent no challenge at all. Opt in with VIGILO_USE_PKCE=1 if Vigilo ever
# starts requiring it, and drop the bare-code path at the same time.
USE_PKCE = os.environ.get("VIGILO_USE_PKCE", "").lower() in ("1", "true", "yes")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def _fmt_time(ts: float | None) -> str:
    if not ts:
        return "never"
    delta = int(time.time() - ts)
    if delta < 60:
        rel = f"{delta}s ago"
    elif delta < 3600:
        rel = f"{delta // 60}m ago"
    elif delta < 86400:
        rel = f"{delta // 3600}h ago"
    else:
        rel = f"{delta // 86400}d ago"
    return f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} ({rel})"


def extract_code(raw: str) -> str:
    """Pull an auth code out of whatever the user pasted.

    Accepts a full redirect URL or a bare code. The bare-code path exists
    because Chrome and Safari frequently clear the address bar when a custom
    scheme fails to open, leaving the user with only what they can scrape out
    of devtools.
    """
    raw = raw.strip()
    if not raw:
        return ""
    if "code=" in raw:
        query = urlparse(raw).query or raw.split("?", 1)[-1]
        codes = parse_qs(query).get("code")
        if codes:
            return codes[0]
    return raw


def extract_state(raw: str) -> str:
    raw = raw.strip()
    if "state=" not in raw:
        return ""
    query = urlparse(raw).query or raw.split("?", 1)[-1]
    values = parse_qs(query).get("state")
    return values[0] if values else ""


class PendingAuths:
    """Short-lived ``state`` -> PKCE verifier map, persisted across restarts.

    Persisting matters because the pod may well restart between the user
    clicking 'log in' and pasting the result back.
    """

    def __init__(self, path) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._entries = json.loads(self._path.read_text())
            except (OSError, ValueError):
                self._entries = {}
        self._prune()

    def _prune(self) -> None:
        now = time.time()
        self._entries = {
            k: v
            for k, v in self._entries.items()
            if now - v.get("created", 0) < PENDING_TTL
        }
        if len(self._entries) > MAX_PENDING:
            newest = sorted(
                self._entries.items(), key=lambda kv: kv[1].get("created", 0)
            )[-MAX_PENDING:]
            self._entries = dict(newest)

    def _persist(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._entries))
        except OSError:
            pass  # non-fatal: the flow still works within this process

    def create(self) -> tuple[str, str]:
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(24)
        self._prune()
        self._entries[state] = {"verifier": verifier, "created": time.time()}
        self._persist()
        return state, challenge

    def peek(self, state: str) -> dict | None:
        """Look up an entry without consuming it."""
        self._prune()
        return self._entries.get(state)

    def consume(self, state: str) -> None:
        """Drop an entry once its code has actually been redeemed.

        Deliberately not done on lookup: if the exchange fails, consuming here
        would make the *next* attempt fail with a misleading "state mismatch"
        instead of the real reason, which is how a one-off error turns into a
        loop the user cannot read their way out of.
        """
        if self._entries.pop(state, None) is not None:
            self._persist()


class CsrfTokens:
    """One-shot tokens binding a POST to a page this server rendered.

    /reauth overwrites the stored credentials, so it must not be reachable by a
    cross-site form auto-submitted from an already-authenticated browser. Any
    authenticating proxy in front of this app authenticates the browser, not the
    request's origin, so it does not stop that by itself.

    Persisted, for the same reason the pending auths are: the user leaves this
    page to go and log in elsewhere, and a restart in the meantime (an image
    bump, a reschedule) would otherwise reject the form they come back to with
    a misleading "this form expired".
    """

    def __init__(self, path) -> None:
        self._path = path
        self._tokens: dict[str, float] = {}
        if self._path.exists():
            try:
                self._tokens = json.loads(self._path.read_text())
            except (OSError, ValueError):
                self._tokens = {}
        self._prune()

    def _prune(self) -> None:
        now = time.time()
        self._tokens = {
            t: created
            for t, created in self._tokens.items()
            if now - created < PENDING_TTL
        }

    def _persist(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._tokens))
        except OSError:
            pass  # non-fatal: the flow still works within this process

    def issue(self) -> str:
        self._prune()
        token = secrets.token_urlsafe(32)
        self._tokens[token] = time.time()
        self._persist()
        return token

    def check(self, token: str) -> bool:
        self._prune()
        # Consumed on use; every rendered page carries a fresh one, so a retry
        # after an error still works.
        ok = self._tokens.pop(token, None) is not None
        if ok:
            self._persist()
        return ok


PAGE = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigilo notify</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 46rem; margin: 2rem auto;
         padding: 0 1rem; line-height: 1.5; color: #1a1a1a; background: #fff; }}
  h1 {{ font-size: 1.4rem; }}
  h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
  .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
  .ok {{ border-left: 4px solid #2e7d32; }}
  .bad {{ border-left: 4px solid #c62828; }}
  .msg-ok {{ background: #e8f5e9; border-left: 4px solid #2e7d32; }}
  .msg-err {{ background: #ffebee; border-left: 4px solid #c62828; }}
  dt {{ font-weight: 600; margin-top: .5rem; }}
  dd {{ margin: 0 0 0 1rem; }}
  a.btn {{ display: inline-block; background: #1565c0; color: #fff; padding: .6rem 1rem;
           border-radius: 6px; text-decoration: none; }}
  input[type=text] {{ width: 100%; padding: .5rem; font-family: monospace;
                      box-sizing: border-box; }}
  button {{ margin-top: .5rem; padding: .5rem 1rem; }}
  code {{ background: #f4f4f4; padding: .1rem .3rem; border-radius: 3px; }}
  ol li {{ margin-bottom: .4rem; }}
  @media (prefers-color-scheme: dark) {{
    body {{ color: #eee; background: #121212; }}
    .card {{ border-color: #333; }}
    .msg-ok {{ background: #1b3d1e; }}
    .msg-err {{ background: #3d1b1b; }}
    code {{ background: #222; }}
    input[type=text] {{ background: #1e1e1e; color: #eee; border: 1px solid #444; }}
  }}
</style>

<h1>Vigilo notify</h1>
{message}

<div class="card {health_class}">
  <dl>
    <dt>State</dt><dd>{state_text}</dd>
    <dt>Last successful poll</dt><dd>{last_poll}</dd>
    <dt>Last attempt</dt><dd>{last_attempt}</dd>
    <dt>Last error</dt><dd>{last_error}</dd>
    <dt>Messages forwarded</dt><dd>{emails_total}</dd>
  </dl>
</div>

<h2>Re-authenticate</h2>
<p>Use <strong>desktop Firefox</strong>. It is the only browser that reliably
keeps the failed <code>app://</code> URL in the address bar where you can copy
it. Do <strong>not</strong> use a phone &mdash; the Vigilo app will intercept
the redirect and swallow the code.</p>

<ol>
  <li>Open <a class="btn" href="{authorize_url}" target="_blank"
      rel="noopener">Log in to Vigilo</a> in a new tab.</li>
  <li>Complete the login. The browser will then fail with
      <em>unknown protocol</em> on an <code>app://ch-parent-android.vigilo.no?...</code>
      address &mdash; that failure is expected and means it worked.</li>
  <li>Copy that whole failed URL from the address bar and paste it below.
      You have about a minute before the code expires.</li>
</ol>

<form method="post" action="/reauth">
  <input type="hidden" name="csrf" value="{csrf}">
  <input type="text" name="redirect_url" autofocus
         placeholder="app://ch-parent-android.vigilo.no?code=..." >
  <button type="submit">Save tokens</button>
</form>

<details>
  <summary>The address bar was empty / I only have the code</summary>
  <p>Chrome and Safari often clear the address bar when a custom scheme fails.
  Before clicking log in, open DevTools &rarr; Network and tick
  <em>Preserve log</em>; the failed <code>app://</code> request stays visible
  there with its full query string. Pasting just the bare <code>code</code>
  value into the field above also works.</p>
</details>
"""


def render_page(
    state: poller.AppState, authorize_url: str, csrf: str, message: str = ""
) -> bytes:
    snap = state.snapshot()
    needs_reauth = bool(snap.get("needs_reauth"))
    body = PAGE.format(
        message=message,
        csrf=html.escape(csrf, quote=True),
        health_class="bad" if needs_reauth else "ok",
        state_text=(
            "Re-authentication required &mdash; polling is paused"
            if needs_reauth
            else "Polling normally"
        ),
        last_poll=html.escape(_fmt_time(snap.get("last_successful_poll"))),
        last_attempt=html.escape(_fmt_time(snap.get("last_poll_attempt"))),
        last_error=html.escape(str(snap.get("last_error") or "none")),
        emails_total=snap.get("emails_sent_total", 0),
        authorize_url=html.escape(authorize_url, quote=True),
    )
    return body.encode("utf-8")


def make_handler(
    cfg: poller.Config,
    state: poller.AppState,
    pending: PendingAuths,
    csrf: CsrfTokens,
):
    class Handler(BaseHTTPRequestHandler):
        server_version = "vigilo-notify"

        def log_message(self, fmt, *args):
            # Default logging writes the full path, which on the callback route
            # would put an auth code in the pod logs.
            print(
                f"{self.command} {urlparse(self.path).path} {args[1] if len(args) > 1 else ''}"
            )

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _authorize_url(self) -> str:
            oauth_state, challenge = pending.create()
            params = {
                "client_id": poller.CLIENT_ID,
                "redirect_uri": poller.REDIRECT_URI,
                "response_type": "code",
                "scope": poller.SCOPE,
                "state": oauth_state,
                "prompt": "login",
                "display": "touch",
            }
            if USE_PKCE:
                params["code_challenge"] = challenge
                params["code_challenge_method"] = "S256"
            # quote_via=quote so the scope separator encodes as %20 rather than
            # '+', byte-for-byte matching the authorize URL this client is known
            # to accept.
            return (
                f"{poller.AUTH_BASE}/connect/authorize?"
                f"{urlencode(params, quote_via=quote)}"
            )

        def _page(self, message: str = "", code: int = 200) -> None:
            self._send(
                code,
                render_page(state, self._authorize_url(), csrf.issue(), message),
                "text/html; charset=utf-8",
            )

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            path = urlparse(self.path).path
            if path == "/healthz":
                # Liveness must never depend on token validity: a failing probe
                # would kill the pod exactly when the re-auth UI is needed.
                self._send(200, b"ok\n", "text/plain; charset=utf-8")
            elif path == "/status":
                snap = state.snapshot()
                payload = {
                    "needs_reauth": bool(snap.get("needs_reauth")),
                    "last_successful_poll": snap.get("last_successful_poll"),
                    "last_poll_attempt": snap.get("last_poll_attempt"),
                    "last_error": snap.get("last_error"),
                    "emails_sent_total": snap.get("emails_sent_total", 0),
                }
                self._send(
                    200,
                    json.dumps(payload, indent=2).encode(),
                    "application/json; charset=utf-8",
                )
            elif path == "/oauth/callback":
                self._handle_callback()
            elif path == "/":
                self._page()
            elif path == "/reauth":
                # The form is POST-only; landing here with a GET means a manual
                # navigation or a refresh. Send them to the form rather than a
                # dead-end 404.
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")

        def _handle_callback(self) -> None:
            """Only reachable when VIGILO_REDIRECT_URI is an https URL."""
            query = parse_qs(urlparse(self.path).query)
            code = (query.get("code") or [""])[0]
            oauth_state = (query.get("state") or [""])[0]
            if not code:
                err = (query.get("error") or ["missing code"])[0]
                self._page(
                    f'<div class="card msg-err">Login failed: {html.escape(err)}</div>',
                    400,
                )
                return
            self._complete(code, oauth_state, require_state=True)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if urlparse(self.path).path != "/reauth":
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
                return

            length = int(self.headers.get("Content-Length") or 0)
            if length > 8192:
                self._page('<div class="card msg-err">Input too large.</div>', 400)
                return
            raw = self.rfile.read(length).decode("utf-8", "replace")
            fields = parse_qs(raw)

            if not csrf.check((fields.get("csrf") or [""])[0]):
                print("Re-auth rejected: missing or stale CSRF token.")
                self._page(
                    '<div class="card msg-err">This form expired or did not come '
                    "from this page. Reload and try again.</div>",
                    400,
                )
                return

            pasted = (fields.get("redirect_url") or [""])[0]
            code = extract_code(pasted)
            if not code:
                self._page(
                    '<div class="card msg-err">Nothing usable in that input. '
                    "Paste the whole failed URL, or just the code.</div>",
                    400,
                )
                return
            # No state in a bare-code paste, so it cannot be required here.
            self._complete(code, extract_state(pasted), require_state=False)

        def _exchange(self, code: str, verifier: str | None) -> dict:
            """Redeem the code, retrying once without PKCE on invalid_grant.

            A verifier that does not match the authorize request fails as
            invalid_grant, which is indistinguishable from an expired code. The
            retry costs one request and turns a dead end into a working login;
            the code is single-use, so if the first attempt really did redeem
            it, the retry simply fails the same way.
            """
            try:
                return poller.exchange_code(code, verifier)
            except Exception as e:
                response = getattr(e, "response", None)
                if not verifier or response is None:
                    raise
                if "invalid_grant" not in (response.text or ""):
                    raise
                print("Exchange failed with PKCE verifier; retrying without it.")
                return poller.exchange_code(code, None)

        def _complete(self, code: str, oauth_state: str, require_state: bool) -> None:
            snap = state.snapshot()
            last_ok = snap.get("reauth_completed_at") or 0
            if time.time() - last_ok < RECENT_SUCCESS_WINDOW:
                # Almost certainly a double-submit of a now-consumed code.
                self._page(
                    '<div class="card msg-ok">Tokens already saved. Polling has resumed.</div>'
                )
                return

            verifier = None
            if oauth_state:
                entry = pending.peek(oauth_state)
                if entry is None:
                    print("Re-auth rejected: unknown or expired state parameter.")
                    self._page(
                        '<div class="card msg-err">Unrecognised or expired login attempt '
                        "(state mismatch). Start over with the button above.</div>",
                        400,
                    )
                    return
                verifier = entry.get("verifier") if USE_PKCE else None
            elif require_state:
                self._page(
                    '<div class="card msg-err">Missing state parameter.</div>', 400
                )
                return

            try:
                tokens = self._exchange(code, verifier)
            except Exception as e:
                detail = ""
                response = getattr(e, "response", None)
                if response is not None:
                    detail = response.text[:400]
                # The user sees this on the page, but the operator needs it in
                # the log too -- an exchange that fails silently server-side is
                # the hardest thing to diagnose remotely.
                print(f"Re-auth token exchange failed: {e} {detail}")
                self._page(
                    '<div class="card msg-err"><strong>Token exchange failed.</strong>'
                    f"<br>{html.escape(str(e))}<br><code>{html.escape(detail)}</code>"
                    "<br>Auth codes expire in about a minute and work only once "
                    "&mdash; start over with the button above.</div>",
                    400,
                )
                return

            if not tokens.get("refresh_token"):
                print("Re-auth failed: response contained no refresh_token.")
                self._page(
                    '<div class="card msg-err">Vigilo returned no refresh token. '
                    "The <code>offline_access</code> scope may have been declined.</div>",
                    400,
                )
                return

            try:
                with state.lock:
                    poller.save_tokens(cfg.token_file, tokens)
                    state.update(
                        needs_reauth=False,
                        last_error=None,
                        reauth_completed_at=time.time(),
                        reauth_notified_at=0,
                    )
            except OSError as e:
                print(f"Re-auth got tokens but could not persist them: {e}")
                self._page(
                    '<div class="card msg-err">Got valid tokens but could not '
                    f"write them to disk: {html.escape(str(e))}</div>",
                    500,
                )
                return

            if oauth_state:
                pending.consume(oauth_state)
            print("Re-authentication complete; tokens saved.")
            self._page(
                '<div class="card msg-ok"><strong>Tokens saved.</strong> '
                "Polling resumes on the next cycle.</div>"
            )

    return Handler


def serve(cfg: poller.Config, state: poller.AppState) -> ThreadingHTTPServer:
    pending = PendingAuths(cfg.token_file.parent / "pending_auth.json")
    csrf = CsrfTokens(cfg.token_file.parent / "csrf_tokens.json")
    port = int(os.environ.get("HTTP_PORT", "8080"))
    handler = make_handler(cfg, state, pending, csrf)
    return ThreadingHTTPServer(("", port), handler)
