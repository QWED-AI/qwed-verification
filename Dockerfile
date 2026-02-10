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
# CodeRabbit Suggested Fix: Ensure appuser can write to workspace
RUN mkdir -p /github/workspace && chown -R appuser:appuser /github

# Install dependencies with hash verification
# Vulnerability Fix: Pin versions with hashes to prevent supply chain attacks
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt

# Copy the entire QWED SDK (local version with guards)
COPY --chown=appuser:appuser qwed_sdk /app/qwed_sdk/

# Copy the entrypoint script
COPY --chown=appuser:appuser action_entrypoint.py /action_entrypoint.py
RUN chmod +x /action_entrypoint.py

# Set Python path to use local SDK
ENV PYTHONPATH=/app

WORKDIR /github/workspace

# Switch to non-root user
USER appuser

ENTRYPOINT ["python", "/action_entrypoint.py"]
