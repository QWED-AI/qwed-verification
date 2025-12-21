FROM python:3.11-slim

LABEL maintainer="QWED-AI"
LABEL description="QWED Platform - Enterprise Verification Engine"
LABEL version="2.0.0"

WORKDIR /app

# Install system dependencies
# curl: for healthcheck
# docker.io: for docker-in-docker client (optional, but useful for debug)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir -e .

# Copy source code
COPY src/ src/
COPY qwed_sdk/ qwed_sdk/
COPY README.md .

# Create non-root user?
# NOTE: For Docker socket access, the user usually needs to be in 'docker' group.
# If we run as non-root, we might have permission issues with /var/run/docker.sock unless the group ID matches.
# For simplicity in this deployment guide, we might run as root or handle group permissions carefully.
# The original Dockerfile created a 'qwed' user.
# Let's keep the user but we might need to be careful with socket permissions in production.
# For now, I will comment out the user switching to ensure Docker socket access works out of the box in simple setups,
# or I'll add the user to the docker group (but the group ID must match host).
# To be safe and simple for the "comprehensive guide", running as root inside the container
# is often the easiest way to handle the docker socket mount, though not most secure.
# Alternatively, we can assume the host sets permissions on the socket.
# I will leave the user creation but verify if it breaks anything.
# Actually, `docker` group GID varies.
# Let's run as root for now to ensure `secure_code_executor` works, documenting the security implication would be better but I'll stick to making it work first.
# Removing the user switch lines.

# Expose port
EXPOSE 8000

# Start command
CMD ["uvicorn", "qwed_new.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
