# Source: Standardizing environment for Z3/SymPy engines
FROM python:3.11-slim

# Prevent python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install QWED SDK from PyPI to ensure stable release version
RUN pip install --no-cache-dir qwed

# Copy the entrypoint script
COPY action_entrypoint.py /action_entrypoint.py
RUN chmod +x /action_entrypoint.py

ENTRYPOINT ["python", "/action_entrypoint.py"]
