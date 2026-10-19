# CrossHair sandbox image for SymbolicVerifier (#431).
#
# CrossHair imports the code it analyses, which executes that code, so
# SymbolicVerifier only runs it in this image through
# SecureCodeExecutor.run_isolated(): no network, read-only root, no host
# mounts, no capabilities, no privilege escalation, user 65534, a private
# tmpfs scratch directory and memory/CPU/PID limits.
#
# Build (the tag must match DEFAULT_CROSSHAIR_IMAGE, or set QWED_CROSSHAIR_IMAGE):
#   docker build -t qwed-crosshair-sandbox:0.0.101 docker/crosshair-sandbox
#
# The image is never pulled at runtime; if it is missing, symbolic
# verification returns BLOCKED (symbolic_verifier.runtime_unavailable).

# Same pinned base as the main QWED image.
FROM python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install --no-cache-dir "crosshair-tool==0.0.101"

WORKDIR /workspace
USER 65534:65534

# Each container runs one short analysis and exits; there is no long-running
# service to probe, so health checks are disabled explicitly.
HEALTHCHECK NONE
