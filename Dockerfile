FROM python:3.13-alpine@sha256:7415fbc3c9e4979cc717d92377ab2bc7b2b4a2af1ac03cc52b5f3f88efedaf3a

# Security-fix libuuid without mutable Alpine repository resolution.
# The exact package bytes are checksum-pinned and installed offline.
ADD --checksum=sha256:8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2 \
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libuuid-2.42.3-r1.apk \
    /tmp/libuuid.apk

RUN apk add --no-cache --no-network /tmp/libuuid.apk && \
    rm -f /tmp/libuuid.apk

WORKDIR /app

COPY --chown=0:0 requirements.lock .
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
    -r requirements.lock

COPY --chown=0:0 . .

# Keep application code and assets root-owned and non-writable by the runtime user.
RUN (getent group 100 || addgroup -g 100 users) && \
    (adduser -D -u 99 -G users nobody 2>/dev/null || true) && \
    chmod -R go-w /app

ENV HOME=/tmp \
    TMPDIR=/tmp \
    PYTHONDONTWRITEBYTECODE=1

# Native Docker Healthcheck using Python built-in urllib
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/healthz')" || exit 1

USER 99:100

ENV PORT=5000 \
    PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
