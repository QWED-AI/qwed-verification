# QWED Action v3.0 Docker Image
# Includes all verification engines and security scanners
FROM python:3.11-slim

# Prevent python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies (including httpx needed by qwed_sdk import chain)
# Note: z3-solver NOT included - not needed for secret/code scanning actions
# and requires C++ compiler to build from source
RUN pip install --no-cache-dir sympy colorama httpx

# Copy the entire QWED SDK (local version with guards)
COPY qwed_sdk /app/qwed_sdk/

# Copy the entrypoint script
COPY action_entrypoint.py /action_entrypoint.py
RUN chmod +x /action_entrypoint.py

# Set Python path to use local SDK
ENV PYTHONPATH=/app

WORKDIR /github/workspace

ENTRYPOINT ["python", "/action_entrypoint.py"]
