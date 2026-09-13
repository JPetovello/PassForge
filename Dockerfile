FROM python:3.13-alpine@sha256:7415fbc3c9e4979cc717d92377ab2bc7b2b4a2af1ac03cc52b5f3f88efedaf3a

WORKDIR /app

COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
    -r requirements.lock

COPY . .

# Ensure data directory exists and assign permissions to nobody:users (99:100)
RUN mkdir -p /app/data && \
    (getent group 100 || addgroup -g 100 users) && \
    (adduser -D -u 99 -G users nobody 2>/dev/null || true) && \
    chown -R 99:100 /app

ENV HOME=/tmp

# Native Docker Healthcheck using Python built-in urllib
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/healthz')" || exit 1

USER 99:100

ENV PORT=5000 \
    PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
