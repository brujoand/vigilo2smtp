FROM python:3.12-slim

# Without this, a long-running process buffers stdout in 8KB blocks and its
# logs never appear -- the short-lived predecessor got away with it because it
# flushed on exit.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir httpx

COPY poller.py web.py main.py ./

# Runs unprivileged by default. Override the uid at deploy time if the data
# volume is owned by something else; /data is the only path written to.
RUN useradd --uid 568 --user-group --no-create-home --shell /usr/sbin/nologin app
USER 568:568

EXPOSE 8080

CMD ["python", "main.py"]
