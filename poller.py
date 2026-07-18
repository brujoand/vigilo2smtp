#!/usr/bin/env python3
"""
Vigilo message poller.

Reads credentials from environment variables, polls for new message threads,
and forwards them via SMTP. Tracks seen thread IDs in a statefile to avoid
duplicate emails. Attachments are downloaded and included in the email.

Runs as a long-lived loop alongside the re-authentication web UI (see web.py);
main.py wires the two together. When the refresh token expires the loop does
NOT exit -- it flips ``needs_reauth`` and keeps running so the UI stays
reachable, which is precisely when it is needed.

Environment variables required:
    VIGILO_CLIENT_ID      - OAuth client ID (extracted from Android APK)
    VIGILO_CLIENT_SECRET  - OAuth client secret (extracted from Android APK)
    VIGILO_ACCESS_TOKEN   - current OAuth access token (only used if no token file)
    VIGILO_REFRESH_TOKEN  - OAuth refresh token (only used if no token file)
    SMTP_HOST             - SMTP relay host (default: localhost)
    SMTP_PORT             - SMTP relay port (default: 25)
    SMTP_FROM             - sender address (required)
    SMTP_TO               - recipient address (required)
    STATE_FILE            - path to seen-IDs statefile (default: /data/seen.json)
    TOKEN_FILE            - path to persist refreshed tokens (default: /data/tokens.json)
    STATUS_FILE           - path to persist poll status (default: /data/status.json)
    POLL_INTERVAL         - seconds between poll cycles (default: 300)
    PUBLIC_URL            - external base URL of the re-auth UI, used in alert emails
"""

import base64
import json
import os
import smtplib
import sys
import threading
import time
from dataclasses import dataclass, field
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import httpx

CLIENT_ID = os.environ.get("VIGILO_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("VIGILO_CLIENT_SECRET", "")
AUTH_BASE = "https://auth.prod.vigilo-oas.no"
API_BASE = "https://api-gw-parent-app.prod.vigilo-oas.no"
APP_VERSION = "Android 3.1.4-15"

# The OAuth client is the Android app, whose registered redirect is a custom
# scheme a browser cannot follow. Overridable so that an https redirect can be
# switched on without a code change if Vigilo ever registers one for us.
REDIRECT_URI = os.environ.get(
    "VIGILO_REDIRECT_URI", "app://ch-parent-android.vigilo.no"
)
SCOPE = "openid vigiloprofile offline_access"

# Re-send the "please re-authenticate" mail at most this often. The poll loop
# runs every 5 minutes; without this it would mail on every cycle.
REAUTH_EMAIL_INTERVAL = 24 * 60 * 60

# How often a persistent condition (paused, refresh still failing) may re-log.
# Long enough not to bury real events, short enough to see in a log tail.
LOG_THROTTLE_INTERVAL = 30 * 60


@dataclass
class Config:
    smtp_host: str
    smtp_port: int
    smtp_from: str
    smtp_to: str
    state_file: Path
    token_file: Path
    status_file: Path
    poll_interval: int
    public_url: str

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            smtp_host=os.environ.get("SMTP_HOST", "localhost"),
            smtp_port=int(os.environ.get("SMTP_PORT", "25")),
            smtp_from=os.environ.get("SMTP_FROM", ""),
            smtp_to=os.environ.get("SMTP_TO", ""),
            state_file=Path(os.environ.get("STATE_FILE", "/data/seen.json")),
            token_file=Path(os.environ.get("TOKEN_FILE", "/data/tokens.json")),
            status_file=Path(os.environ.get("STATUS_FILE", "/data/status.json")),
            poll_interval=int(os.environ.get("POLL_INTERVAL", "300")),
            public_url=os.environ.get("PUBLIC_URL", ""),
        )


@dataclass
class AppState:
    """Shared between the poll thread and the HTTP handler.

    ``lock`` guards every mutation of the status dict and of the token file, so
    a re-auth landing mid-cycle cannot interleave with a token refresh.
    """

    status_file: Path
    lock: threading.Lock = field(default_factory=threading.Lock)
    status: dict = field(default_factory=dict)

    def load(self) -> None:
        if self.status_file.exists():
            try:
                self.status = json.loads(self.status_file.read_text())
            except (OSError, ValueError):
                self.status = {}
        # Drop the log throttle marks on startup. They are meant to stop a
        # steady state repeating every cycle, not to stop a fresh process
        # stating the condition it woke up in -- which is the first thing
        # anyone reads after a restart.
        self.status.pop("log_marks", None)

    def _persist(self) -> None:
        write_json_atomic(self.status_file, self.status)

    def update(self, **fields) -> None:
        """Merge fields into the status and persist. Caller must hold the lock."""
        self.status.update(fields)
        try:
            self._persist()
        except OSError as e:
            print(f"Could not persist status: {e}", file=sys.stderr)

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.status)


def log_throttled(state: AppState, key: str, message: str) -> None:
    """Print at most once per LOG_THROTTLE_INTERVAL per key.

    Steady-state conditions (paused, repeatedly failing refresh) need to be
    visible in the log, but printing them every cycle would bury everything
    else. Caller must hold ``state.lock``.
    """
    now = time.time()
    marks = state.status.setdefault("log_marks", {})
    if now - (marks.get(key) or 0) < LOG_THROTTLE_INTERVAL:
        return
    marks[key] = now
    state.update(log_marks=marks)
    print(message)


def _basic_auth() -> str:
    return base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()


def refresh_token(refresh_tok: str) -> dict:
    r = httpx.post(
        f"{AUTH_BASE}/connect/token",
        headers={"Authorization": f"Basic {_basic_auth()}"},
        data={"refresh_token": refresh_tok, "grant_type": "refresh_token"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def exchange_code(code: str, code_verifier: str | None = None) -> dict:
    """Trade an authorization code for a token pair.

    Sending PKCE is harmless if the server ignores it and correct if it does
    not, so the verifier is always included when we have one.
    """
    data = {
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    r = httpx.post(
        f"{AUTH_BASE}/connect/token",
        headers={"Authorization": f"Basic {_basic_auth()}"},
        data=data,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def user_id_from_jwt(access_token: str) -> str:
    payload = access_token.split(".")[1]
    payload += "==" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["sub"]


def load_tokens(token_file: Path) -> dict:
    """Read the live token pair.

    The file wins over the environment: the env values are only a cold-start
    seed and go stale the moment the first refresh is persisted.
    """
    if token_file.exists():
        return json.loads(token_file.read_text())
    return {
        "access_token": os.environ.get("VIGILO_ACCESS_TOKEN", ""),
        "refresh_token": os.environ.get("VIGILO_REFRESH_TOKEN", ""),
    }


def write_json_atomic(path: Path, payload) -> None:
    """Write via temp file + rename.

    A partial write of tokens.json would lock us out entirely, and a partial
    seen.json would re-send every message thread.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload))
    tmp.replace(path)


def save_tokens(token_file: Path, tokens: dict) -> None:
    write_json_atomic(token_file, tokens)


def load_seen(state_file: Path) -> set:
    if state_file.exists():
        return set(json.loads(state_file.read_text()))
    return set()


def save_seen(state_file: Path, seen: set) -> None:
    write_json_atomic(state_file, list(seen))


def download_attachment(url: str) -> bytes:
    r = httpx.get(url, timeout=60, follow_redirects=True)
    r.raise_for_status()
    return r.content


def send_email(
    smtp_host: str,
    smtp_port: int,
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    attachments: list,
) -> None:
    if attachments:
        msg = MIMEMultipart()
        msg.attach(MIMEText(body, "plain", "utf-8"))
        for name, mime_type, data in attachments:
            main_type, sub_type = mime_type.split("/", 1)
            part = MIMEBase(main_type, sub_type)
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=name)
            msg.attach(part)
    else:
        msg = MIMEText(body, "plain", "utf-8")

    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
        s.sendmail(from_addr, [to_addr], msg.as_string())


class VigiloClient:
    def __init__(self, access_token: str, user_id: str) -> None:
        self._http = httpx.Client(
            base_url=API_BASE,
            headers={
                "Authorization": f"Bearer {access_token}",
                "appVersion": APP_VERSION,
            },
            timeout=30,
        )
        self._user_id = user_id

    def get_children(self) -> list:
        r = self._http.get("/api/children", params={"userId": self._user_id})
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            return data
        return data.get("items", [])

    def get_message_threads(self, child_id: str, page_size: int = 50) -> list:
        params = {
            "userId": self._user_id,
            "childIds": child_id,
            "pageSize": page_size,
            "unreadMessageThreadsCountOnly": "false",
            "includeAfterSchoolMessages": "false",
        }
        r = self._http.get("/api/message-threads", params=params)
        r.raise_for_status()
        return r.json().get("messageThreads", [])

    def get_thread(self, thread_uid: str) -> dict:
        r = self._http.get(
            f"/api/messages/threads/{thread_uid}",
            params={"userId": self._user_id, "pageSize": 50},
        )
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        self._http.close()


def format_email_body(thread: dict, messages: list) -> str:
    lines = []
    org = thread.get("organizationalUnit", {})
    org_name = org.get("name", "") if isinstance(org, dict) else str(org)

    if org_name:
        lines.append(f"School: {org_name}")
    lines.append("")

    for msg in messages:
        body = msg.get("body", "")
        created = msg.get("timeCreated", "")
        msg_sender = msg.get("sender", {})
        msg_sender_name = (
            f"{msg_sender.get('firstName', '')} {msg_sender.get('lastName', '')}".strip()
            if isinstance(msg_sender, dict)
            else ""
        )
        lines.append(f"--- {msg_sender_name} ({created}) ---")
        lines.append(body)
        att_list = msg.get("attachments", [])
        if att_list:
            lines.append(f"Attachments: {', '.join(a['name'] for a in att_list)}")
        lines.append("")

    return "\n".join(lines)


def notify_reauth_needed(cfg: Config, state: AppState) -> None:
    """Mail the human that the browser login must be redone, at most daily.

    Takes the lock itself, and must be called WITHOUT it held: sending mail is
    a network round trip and the lock is also what the web UI needs to render.
    """
    with state.lock:
        now = time.time()
        last = state.status.get("reauth_notified_at") or 0
        if now - last < REAUTH_EMAIL_INTERVAL:
            # Suppressing the mail must not also suppress the fact that we are
            # broken -- otherwise the second failure onwards is entirely silent.
            log_throttled(
                state,
                "reauth-suppressed",
                "Re-authentication still required; alert email suppressed "
                f"(last sent {int((now - last) / 60)} min ago).",
            )
            return
        # Claim the slot before sending, so two callers cannot both decide to
        # send. Rolled back below if the send fails, so a transient SMTP
        # outage does not swallow the alert for a whole day.
        state.update(reauth_notified_at=now)

    where = cfg.public_url or "the vigilo-notify re-authentication page"
    subject = "[Vigilo] Re-authentication required"
    body = (
        "The Vigilo refresh token has expired, so no messages are being "
        "forwarded.\n\n"
        f"Open {where} and use the 'Re-authenticate' flow to sign in again.\n"
        "Polling resumes automatically once new tokens are saved."
    )
    try:
        send_email(
            cfg.smtp_host, cfg.smtp_port, cfg.smtp_from, cfg.smtp_to, subject, body, []
        )
        print("Refresh token expired - alert email sent.")
    except Exception as mail_err:
        with state.lock:
            state.update(reauth_notified_at=last)
        print(
            f"Refresh token expired and could not send alert: {mail_err}",
            file=sys.stderr,
        )


def poll_once(cfg: Config, state: AppState) -> None:
    """Run a single poll cycle. Never raises; records outcome in the status."""
    # Nothing below holds the lock across a network call: the lock is also what
    # the web UI takes to render, and a 30s token refresh or a 10s SMTP send
    # would hang the status page exactly when someone is checking on it.
    with state.lock:
        if state.status.get("needs_reauth"):
            # The UI clears this once new tokens are saved; until then there is
            # nothing useful to do and every call would 401. Say so out loud --
            # a paused poller that logs nothing is indistinguishable from a
            # healthy idle one, which makes this state invisible in operation.
            log_throttled(
                state,
                "paused",
                "Paused: re-authentication required. Open the web UI to sign in again.",
            )
            return
        state.update(last_poll_attempt=time.time())

        # Re-read every cycle rather than caching, so tokens written by the
        # re-auth UI while we were sleeping are picked up immediately.
        try:
            tokens = load_tokens(cfg.token_file)
        except (OSError, ValueError) as e:
            state.update(last_error=f"Could not read token file: {e}")
            print(f"Could not read token file: {e}", file=sys.stderr)
            return
        old_refresh = tokens.get("refresh_token")
        if not old_refresh:
            state.update(needs_reauth=True, last_error="No refresh token available")
            missing = True
        else:
            missing = False

    if missing:
        notify_reauth_needed(cfg, state)
        return

    try:
        new_tokens = refresh_token(old_refresh)
    except httpx.HTTPStatusError as e:
        if e.response.status_code in (400, 401):
            with state.lock:
                state.update(needs_reauth=True, last_error="Refresh token expired")
            notify_reauth_needed(cfg, state)
            return
        with state.lock:
            state.update(last_error=f"Token refresh failed: {e}")
        print(f"Token refresh failed: {e}", file=sys.stderr)
        return
    except Exception as e:
        with state.lock:
            state.update(last_error=f"Token refresh failed: {e}")
        print(f"Token refresh failed: {e}", file=sys.stderr)
        return

    with state.lock:
        # A re-auth may have landed while we were on the network. Its tokens are
        # strictly newer than the pair we just derived from the old refresh
        # token, so don't clobber them.
        try:
            current = load_tokens(cfg.token_file)
        except (OSError, ValueError):
            current = {}
        if current.get("refresh_token") not in (None, "", old_refresh):
            print("Re-auth landed mid-cycle; keeping the newer tokens.")
            return
        tokens.update(new_tokens)
        try:
            save_tokens(cfg.token_file, tokens)
        except OSError as e:
            state.update(last_error=f"Could not persist tokens: {e}")
            print(f"Could not persist tokens: {e}", file=sys.stderr)
            return
        access_token = tokens["access_token"]

    emails_sent = 0
    try:
        user_id = user_id_from_jwt(access_token)
        client = VigiloClient(access_token, user_id)
        seen = load_seen(cfg.state_file)
        new_seen = set(seen)

        try:
            children = client.get_children()
            child_ids = [str(c["childId"]) for c in children if c.get("childId")]

            threads = []
            for child_id in child_ids:
                threads.extend(client.get_message_threads(child_id))

            for thread in threads:
                thread_uid = thread.get("threadUid", "")
                if not thread_uid or thread_uid in seen:
                    continue

                try:
                    detail = client.get_thread(thread_uid)
                except Exception as e:
                    print(f"Failed to fetch thread {thread_uid}: {e}", file=sys.stderr)
                    continue

                messages = detail.get("messages", [])
                title = thread.get("title", "(no title)")
                subject = f"[Vigilo] {title}"
                body = format_email_body(thread, messages)

                attachments = []
                for msg in messages:
                    for att in msg.get("attachments", []):
                        try:
                            data = download_attachment(att["url"])
                            attachments.append((att["name"], att["mimeType"], data))
                        except Exception as e:
                            print(
                                f"Failed to download attachment {att['name']}: {e}",
                                file=sys.stderr,
                            )

                try:
                    send_email(
                        cfg.smtp_host,
                        cfg.smtp_port,
                        cfg.smtp_from,
                        cfg.smtp_to,
                        subject,
                        body,
                        attachments,
                    )
                    new_seen.add(thread_uid)
                    emails_sent += 1
                    print(f"Emailed thread: {title}")
                except Exception as e:
                    print(
                        f"Failed to send email for thread {thread_uid}: {e}",
                        file=sys.stderr,
                    )
        finally:
            client.close()

        save_seen(cfg.state_file, new_seen)
    except Exception as e:
        with state.lock:
            state.update(last_error=f"Poll failed: {e}")
        print(f"Poll failed: {e}", file=sys.stderr)
        return

    with state.lock:
        state.update(
            last_successful_poll=time.time(),
            last_error=None,
            emails_sent_total=state.status.get("emails_sent_total", 0) + emails_sent,
        )
    print(f"Done. {emails_sent} new message(s) forwarded.")


def run_loop(cfg: Config, state: AppState, stop: threading.Event) -> None:
    """Poll forever until ``stop`` is set.

    Nothing is allowed to escape this loop: an uncaught exception would kill
    the thread and leave the process up but silently doing nothing.
    """
    while not stop.is_set():
        try:
            poll_once(cfg, state)
        except Exception as e:  # noqa: BLE001 - deliberate catch-all
            print(f"Unexpected error in poll cycle: {e}", file=sys.stderr)
        # Event.wait rather than sleep so SIGTERM is honoured within ~1s
        # instead of leaving the pod to be SIGKILLed after the grace period.
        stop.wait(cfg.poll_interval)


def probe_redirect_uri(candidate: str) -> None:
    """Log whether the auth server would accept ``candidate`` as a redirect_uri.

    Registered redirect URIs are an exact-match allowlist the provider
    controls, and they are validated at the authorize endpoint *before* any
    authentication -- so this is answerable with one unauthenticated request
    and no login. It matters because an accepted https redirect replaces the
    whole copy-paste flow with an ordinary callback, and the paste flow is
    where every failure so far has happened.

    Runs once at startup. Never raises: this is diagnostics, not a dependency.
    """
    try:
        r = httpx.get(
            f"{AUTH_BASE}/connect/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": candidate,
                "response_type": "code",
                "scope": SCOPE,
            },
            follow_redirects=False,
            timeout=15,
        )
    except Exception as e:
        print(f"redirect_uri probe for {candidate} could not run: {e}")
        return

    location = r.headers.get("location", "")
    body = (r.text or "")[:200]
    # An unregistered URI is refused outright rather than redirected to, since
    # redirecting to an unvetted URI is the thing the allowlist exists to stop.
    rejected = r.status_code >= 400 or "invalid_request" in (location + body)
    verdict = "REJECTED" if rejected else "ACCEPTED"
    print(
        f"redirect_uri probe: {candidate} -> {verdict} "
        f"(HTTP {r.status_code}{', location=' + location[:120] if location else ''})"
    )
    if not rejected:
        print(
            "  This redirect is usable. Set VIGILO_REDIRECT_URI to it to replace "
            "the copy-paste flow with an automatic callback."
        )


def validate(cfg: Config) -> None:
    if not cfg.smtp_to:
        print("ERROR: SMTP_TO not set", file=sys.stderr)
        sys.exit(1)
    if not cfg.smtp_from:
        print("ERROR: SMTP_FROM not set", file=sys.stderr)
        sys.exit(1)
    if not CLIENT_ID or not CLIENT_SECRET:
        print(
            "ERROR: VIGILO_CLIENT_ID and VIGILO_CLIENT_SECRET must be set",
            file=sys.stderr,
        )
        sys.exit(1)
