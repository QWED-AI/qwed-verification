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

# Install dependencies (but NOT qwed - we'll use local copy)
RUN pip install --no-cache-dir sympy z3-solver colorama

# Copy the entire QWED SDK (local version with guards)
COPY qwed_sdk /app/qwed_sdk/

# Copy the entrypoint script
COPY action_entrypoint.py /action_entrypoint.py
RUN chmod +x /action_entrypoint.py

# Set Python path to use local SDK
ENV PYTHONPATH=/app

WORKDIR /github/workspace

ENTRYPOINT ["python", "/action_entrypoint.py"]
