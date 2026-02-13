# QWED Action v3.0 Docker Image
# Includes all verification engines and security scanners
# Vulnerability Fix: Upgrade to bookworm and pin digest for immutability
# python:3.12-slim-bookworm @ 2024-02-11
FROM python:3.12-slim-bookworm@sha256:4a8e0824201e50fc44ee8d208a2b3e44f33e00448907e524066fca5a96eb5567

# Prevent python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m -u 1000 appuser

# Fix permissions for GitHub Actions workspace
RUN mkdir -p /github/workspace && chown -R appuser:appuser /github

# Install dos2unix for entrypoint management (runuser is native in base image)
RUN apt-get update && apt-get install -y --no-install-recommends dos2unix && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to leverage cache
COPY requirements.txt /app/requirements.txt

# Vulnerability Fix: Upgrade pip and wheel to patch base image CVEs
# CVE-2026-24049 (Critical): wheel<=0.46.1 -> 0.46.2
# CVE-2025-8869 (Medium):   pip==24.0 -> latest
RUN pip install --no-cache-dir --force-reinstall "pip>=25.0" "wheel>=0.46.2"

# Install dependencies with hash verification
# Vulnerability Fix: Pin versions with hashes to prevent supply chain attacks
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt

# Copy the entire QWED SDK (local version with guards)
COPY --chown=appuser:appuser qwed_sdk /app/qwed_sdk/

# Copy the entrypoint script
COPY --chown=appuser:appuser action_entrypoint.py /action_entrypoint.py
RUN chmod +x /action_entrypoint.py

# Create entrypoint.sh directly to avoid Windows line ending issues (CRLF)
RUN printf '#!/bin/bash\n\
set -e\n\
\n\
# Fix permissions for workspace\n\
if [ -d "/github/workspace" ]; then\n\
    chown -R appuser:appuser /github/workspace\n\
fi\n\
\n\
# Fix permissions for file commands\n\
if [ -d "/github/file_commands" ]; then\n\
    chmod -R 777 /github/file_commands\n\
fi\n\
\n\
# Switch to appuser and run the main entrypoint\n\
exec runuser -u appuser -- python /action_entrypoint.py "$@"\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

# Set Python path to use local SDK
ENV PYTHONPATH=/app

WORKDIR /github/workspace

# NOTE: We do NOT switch USER here. We start as root to fix permissions on mounted volumes
# in entrypoint.sh, then drop privileges to appuser using runuser.
ENTRYPOINT ["/entrypoint.sh"]
