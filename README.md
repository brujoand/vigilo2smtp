# vigilo2smtp

Polls the Vigilo school-messaging API for new message threads and forwards them
as email, attachments included. Runs as a single long-lived process: a poll loop
on a timer plus a small web UI for redoing the OAuth login when the refresh
token expires.

## Re-authenticating

Vigilo refresh tokens expire every 30-90 days. When that happens the poller
emails you, pauses polling, and waits &mdash; it does not crash. Open the UI and
redo the login.

### The problem this flow works around

The OAuth client is Vigilo's Android app, and its registered redirect URI is the
custom scheme `app://ch-parent-android.vigilo.no`. No browser can follow that,
so this cannot be an ordinary callback.

Worse, if Vigilo's own application is installed on the machine you log in from,
**the OS hands it the redirect and it redeems the authorization code**.
Authorization codes are single-use, so by the time you try to use it the code is
already spent and the exchange fails with `invalid_grant` &mdash; no matter how
quickly you work. Codes themselves are not the constraint; one has been redeemed
successfully 168 seconds after the login started.

So the goal is simply to make sure *you* receive the redirect, not that app.

### Recommended: install the redirect handler (Linux/XDG)

```bash
./contrib/install-redirect-handler.sh https://your-ui.example.com
```

This claims `x-scheme-handler/app` for the desktop, so the redirect comes to you
first. Re-authenticating then takes two clicks:

1. Open the UI, click **Log in to Vigilo**, complete the login.
2. The handler opens the UI with the code filled in. Click **Save tokens**.

The handler never submits on your behalf &mdash; it opens `/paste`, which
validates the `state` against a pending login and renders the form for you to
confirm. If `xdg-open` is unavailable it copies the URL to the clipboard, and
failing that writes it to `/tmp/vigilo_code`.

Note this takes the `app://` scheme over from Vigilo's application if it is
installed. To give it back: `xdg-mime default <their>.desktop
x-scheme-handler/app`.

### Manual fallback

On a machine with **no Vigilo application installed**, the redirect simply fails
and the URL stays in the address bar:

1. Open the UI and click **Log in to Vigilo**.
2. Complete the login.
3. The browser fails with *unknown protocol* on an
   `app://ch-parent-android.vigilo.no?code=...` address. **That failure is the
   success case.**
4. Copy the whole failed URL from the address bar and paste it into the form.

Firefox keeps that URL in the address bar; Chrome and Safari frequently clear
it. Where the app *is* installed, or the address bar is lost, open DevTools
&rarr; Network and tick **Preserve log** *before* step 1 &mdash; the failed
`app://` request stays in the log with its full query string, and is visible
even though the OS handed it off. The form also accepts a bare `code` value.

Codes are single-use. If one fails, start a completely fresh login rather than
retrying the same URL.

### If Vigilo ever registers an https redirect

Set `VIGILO_REDIRECT_URI` to it. `GET /oauth/callback` already implements the
automatic flow and the copy-paste step disappears. No code change needed.

## Endpoints

| Path | Purpose |
|---|---|
| `GET /` | Status page, login link, paste form |
| `GET /paste` | Form pre-filled from a captured redirect; validates `state`, never submits |
| `POST /reauth` | Exchange a pasted code or redirect URL |
| `GET /oauth/callback` | Automatic callback (https redirect only) |
| `GET /healthz` | Liveness &mdash; 200 whenever the server is serving |
| `GET /status` | JSON status; booleans and timestamps only, never tokens |

`/healthz` deliberately ignores token validity. A probe that failed on an
expired token would kill the pod exactly when the re-auth UI is needed.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `VIGILO_CLIENT_ID` | *required* | From the Android APK |
| `VIGILO_CLIENT_SECRET` | *required* | From the Android APK |
| `VIGILO_ACCESS_TOKEN` | | Cold-start seed only |
| `VIGILO_REFRESH_TOKEN` | | Cold-start seed only |
| `VIGILO_REDIRECT_URI` | `app://ch-parent-android.vigilo.no` | |
| `SMTP_HOST` | `localhost` | |
| `SMTP_PORT` | `25` | |
| `SMTP_FROM` | *required* | Sender address |
| `SMTP_TO` | *required* | Recipient address |
| `STATE_FILE` | `/data/seen.json` | Forwarded thread UIDs |
| `TOKEN_FILE` | `/data/tokens.json` | Live rotating tokens |
| `STATUS_FILE` | `/data/status.json` | Poll status |
| `POLL_INTERVAL` | `300` | Seconds between cycles |
| `HTTP_PORT` | `8080` | |
| `PUBLIC_URL` | | External URL, used in the alert email |

**`/data/tokens.json` is the source of truth.** `VIGILO_ACCESS_TOKEN` and
`VIGILO_REFRESH_TOKEN` are read only when that file does not exist, so they go
stale the moment the first refresh is persisted. That is by design; the file is
covered by the volume's nightly backup.

## Local development

```bash
pip install httpx
mkdir -p tmp-data
STATE_FILE=tmp-data/seen.json TOKEN_FILE=tmp-data/tokens.json \
  STATUS_FILE=tmp-data/status.json \
  SMTP_FROM=vigilo@example.com SMTP_TO=you@example.com \
  VIGILO_CLIENT_ID=... VIGILO_CLIENT_SECRET=... \
  python main.py
```

Or via the image:

```bash
docker build -t vigilo2smtp .
docker run --rm -p 8080:8080 -v "$PWD/tmp-data:/data" --env-file .env vigilo2smtp
```

## Releasing

Bump `VERSION`; pushing to `main` builds and pushes
`ghcr.io/brujoand/vigilo2smtp:<VERSION>` and `:latest`.
