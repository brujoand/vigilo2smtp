#!/usr/bin/env python3
"""
vigilo2smtp entrypoint.

Runs the poll loop in a background thread and the re-authentication web UI on
the main thread. Both live in one process so they can share the single data
volume holding the rotating tokens.
"""

import signal
import sys
import threading

import poller
import web


def main() -> None:
    cfg = poller.Config.from_env()
    poller.validate(cfg)

    state = poller.AppState(status_file=cfg.status_file)
    state.load()

    stop = threading.Event()
    httpd = web.serve(cfg, state)

    def shutdown(signum, _frame):
        print(f"Received signal {signum}, shutting down.")
        stop.set()
        # shutdown() blocks until serve_forever returns, so it cannot be called
        # from the thread running serve_forever.
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    poll_thread = threading.Thread(
        target=poller.run_loop, args=(cfg, state, stop), name="poller", daemon=True
    )
    poll_thread.start()

    print(f"Serving re-auth UI on port {httpd.server_address[1]}")
    try:
        httpd.serve_forever()
    finally:
        stop.set()
        httpd.server_close()
        poll_thread.join(timeout=5)
    print("Stopped.")
    sys.exit(0)


if __name__ == "__main__":
    main()
