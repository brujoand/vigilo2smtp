FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir httpx

COPY poller.py .

CMD ["python", "poller.py"]
