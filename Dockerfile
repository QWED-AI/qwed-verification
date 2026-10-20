# QWED Docker images (#467). One Dockerfile, two targets:
#
#   server  The API server (uvicorn on port 8000). Published to Docker Hub as
#           qwedai/qwed-verification:
#             docker build --target server -t qwedai/qwed-verification .
#   action  The GitHub Action (action_entrypoint.py). action.yml builds this
#           file without a target, so the Action stage must stay last.
#
# Base: python:3.14-slim-bookworm, pinned by digest.
FROM python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56 AS base

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Vulnerability Fix: Upgrade pip and wheel to patch base image CVEs
# CVE-2026-24049 (Critical): wheel<=0.46.1 -> 0.46.2
# CVE-2025-8869 (Medium):   pip==24.0 -> latest
RUN pip install --no-cache-dir --upgrade "pip>=25.0" "wheel>=0.46.2"


# ============== API SERVER ==============
FROM base AS server

# Every dependency of the server, hash-pinned for Linux and Python 3.14
# (generated from pyproject.toml with the [server] extra; see the file header).
COPY requirements-server.txt /app/requirements-server.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements-server.txt \
    && useradd --create-home --uid 1000 qwed \
    && mkdir -p /var/lib/qwed \
    && chown qwed:qwed /var/lib/qwed

# Code is owned by root and read-only to the server user.
COPY src/qwed_new /app/qwed_new/
COPY qwed_sdk /app/qwed_sdk/

# The default SQLite database (sqlite:///./qwed.db) lives in the working
# directory, the only place the server user can write. Set DATABASE_URL to
# use Postgres instead.
WORKDIR /var/lib/qwed
USER qwed

# uvicorn reads its host and port from these. Change the port with
# -e UVICORN_PORT=...; the health check follows it (a --port argument would
# not).
ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os, sys, urllib.request; port = os.environ.get('UVICORN_PORT', '8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=4).status == 200 else 1)"]

# The server refuses to start without QWED_CORS_ORIGINS, QWED_JWT_SECRET_KEY
# or QWED_API_KEY_LOOKUP_SECRET. It also needs API_KEY_SECRET, and
# QWED_AUDIT_SECRET_KEY to sign the audit chain.
ENTRYPOINT ["python", "-m", "uvicorn", "qwed_new.api.main:app"]


# ============== GITHUB ACTION (default target, keep last) ==============
FROM base AS action

# System Setup & User Creation (single layer)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && apt-get clean \
    && useradd -m -u 1000 appuser \
    && mkdir -p /github/workspace \
    && chown -R appuser:appuser /github

# Dependency Management
# Copy requirements first to leverage Docker's layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt

# Source Code Transfer
# Files live in /app (separate from /github/workspace mount point)
COPY --chown=appuser:appuser qwed_sdk /app/qwed_sdk/
COPY --chown=appuser:appuser src/qwed_new /app/qwed_new/
COPY --chown=appuser:appuser action_entrypoint.py /action_entrypoint.py

# Entrypoint Script (printf avoids CRLF issues without dos2unix)
RUN printf '#!/bin/bash\n\
set -e\n\
# Only re-chown if mount is not already owned by appuser (UID 1000)\n\
if [ -d "/github/workspace" ] && [ "$(stat -c %%u /github/workspace 2>/dev/null)" != "1000" ]; then\n\
    chown -R appuser:appuser /github/workspace\n\
fi\n\
[ -d "/github/file_commands" ] && chmod -R 777 /github/file_commands\n\
exec runuser -u appuser -- python /action_entrypoint.py "$@"' > /entrypoint.sh \
    && chmod +x /entrypoint.sh /action_entrypoint.py

WORKDIR /github/workspace

# NOTE: We start as root to fix permissions on mounted volumes,
# then drop privileges to appuser using runuser in entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
