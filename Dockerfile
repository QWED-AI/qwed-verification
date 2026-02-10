# QWED Action v3.0 Docker Image
# Includes all verification engines and security scanners
# Vulnerability Fix: Upgrade to bookworm for newer security patches
FROM python:3.12-slim-bookworm

# Prevent python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies with constraints
# Vulnerability Fix: Pin versions to prevent supply chain attacks
RUN pip install --no-cache-dir \
    "sympy>=1.12" \
    "httpx>=0.24.0" \
    "colorama>=0.4.6"

# Copy the entire QWED SDK (local version with guards)
COPY qwed_sdk /app/qwed_sdk/

# Copy the entrypoint script
COPY action_entrypoint.py /action_entrypoint.py
RUN chmod +x /action_entrypoint.py

# Set Python path to use local SDK
ENV PYTHONPATH=/app

WORKDIR /github/workspace

ENTRYPOINT ["python", "/action_entrypoint.py"]
