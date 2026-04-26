# QWED Action v3.1 Docker Image
# Includes all verification engines and security scanners
# Security: python:3.13-slim-bookworm for minimal CVE exposure
# Upgraded from 3.12 (Feb 2024) → 3.13 (April 2026 stable)
# python:3.13-slim-bookworm @ 2026-04-22
FROM python:3.13-slim-bookworm@sha256:bb73517d48bd32016e15eade0c009b2724ec3a025a9975b5cd9b251d0dcadb33

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

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

# Vulnerability Fix: Upgrade pip and wheel to patch base image CVEs
# CVE-2026-24049 (Critical): wheel<=0.46.1 -> 0.46.2
# CVE-2025-8869 (Medium):   pip==24.0 -> latest
RUN pip install --no-cache-dir --upgrade "pip>=25.0" "wheel>=0.46.2" \
    && pip install --no-cache-dir --require-hashes -r /app/requirements.txt

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

# API Server default command
CMD ["python3", "-m", "uvicorn", "qwed_new.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
