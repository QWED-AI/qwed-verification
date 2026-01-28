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

# Install QWED SDK with all features
# Note: Using editable install for guards access (will be replaced with pip install qwed[full] after release)
RUN pip install --no-cache-dir qwed sympy z3-solver

# Copy the SDK guards (needed for scan-secrets, verify-shell)
COPY qwed_sdk/guards /app/qwed_sdk/guards/
COPY qwed_sdk/__init__.py /app/qwed_sdk/

# Copy the entrypoint script
COPY action_entrypoint.py /action_entrypoint.py
RUN chmod +x /action_entrypoint.py

# Set Python path
ENV PYTHONPATH=/app

WORKDIR /github/workspace

ENTRYPOINT ["python", "/action_entrypoint.py"]
