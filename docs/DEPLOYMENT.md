# QWED Deployment Guide

This guide provides instructions for deploying QWED in various environments.

## Table of Contents
1. [Docker Deployment](#docker-deployment)
2. [Kubernetes Deployment](#kubernetes-deployment)
3. [Manual / Bare Metal Deployment](#manual--bare-metal-deployment)
4. [Environment Variables Reference](#environment-variables-reference)
5. [Production Checklist](#production-checklist)
6. [Troubleshooting](#troubleshooting)
7. [Operations & Monitoring](#operations--monitoring)

---

## Docker Deployment

The easiest way to run QWED locally or on a single server is using Docker Compose.

### Dockerfile

A `Dockerfile` is provided in the root directory. It builds the QWED core service based on `python:3.11-slim`.

```bash
# Build the image manually
docker build -t qwed-core:2.0.0 .
```

### Docker Compose

We provide a `docker-compose.yml` that orchestrates:
- **qwed-core**: The main API server.
- **postgres**: Primary database.
- **redis**: Cache and rate limiting.
- **jaeger**: Distributed tracing.
- **prometheus**: Metrics collection.
- **grafana**: Observability dashboards.

To start the stack:

```bash
docker-compose up -d
```

Access the services:
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Grafana**: http://localhost:3000 (admin/qwed_admin)
- **Jaeger**: http://localhost:16686

> 🏢 **Enterprise Support Coming Soon:** Managed hosting, dedicated support, and SLA guarantees. Contact rahul@qwedai.com

### Notes on Stats Verification
The Stats Verification engine (Engine 3) executes code securely inside Docker containers. For this to work in a Docker Compose environment, the `qwed-core` container mounts the host's Docker socket (`/var/run/docker.sock`). Ensure the user running Docker Compose has appropriate permissions.

---

## Kubernetes Deployment

For production environments, we provide Kubernetes manifests in `deploy/kubernetes/`.

### Prerequisites
- A running Kubernetes cluster (v1.24+ recommended).
- `kubectl` configured.
- A PostgreSQL database and Redis instance (managed services recommended for production).

### Deployment Steps

1. **Create Namespace**
   ```bash
   kubectl create namespace qwed
   ```

2. **Configure Secrets & ConfigMaps**
   Edit `deploy/kubernetes/secret.yaml` with your real API keys and database credentials.
   ```bash
   kubectl apply -f deploy/kubernetes/configmap.yaml
   kubectl apply -f deploy/kubernetes/secret.yaml
   ```

3. **Deploy Application**
   ```bash
   kubectl apply -f deploy/kubernetes/deployment.yaml
   kubectl apply -f deploy/kubernetes/service.yaml
   ```

4. **Verify Deployment**
   ```bash
   kubectl get pods -n qwed
   ```

### Horizontal Pod Autoscaling (HPA)

For high-traffic environments, we recommend enabling HPA (requires Metrics Server):

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: qwed-core-hpa
  namespace: qwed
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: qwed-core
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

---

## Manual / Bare Metal Deployment

If you prefer to run the application directly on a host or VM:

### 1. Prerequisites

**Docker Installation (Required for Secure Code Execution)**
QWED uses Docker for secure code execution in the Stats Verification engine.

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

### 2. Python Dependencies
```bash
# Install dependencies
pip install -e .
```

### 3. Database Setup
Ensure PostgreSQL and Redis are running. Set the `DATABASE_URL` and `REDIS_URL` environment variables.

Initialize the database:
```bash
python -c "from qwed_new.core.database import create_db_and_tables; create_db_and_tables()"
```

### 4. Running the API

```bash
# Production Mode with Gunicorn (Linux/macOS)
gunicorn qwed_new.api.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

---

## Environment Variables Reference

### Infrastructure
| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | Postgres connection string | `sqlite:///./qwed.db` | Yes (Prod) |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` | Yes (Prod) |
| `API_KEY_SECRET` | Secret key for signing JWTs | `change-me...` | **YES** |

### Security Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_INPUT_LENGTH` | Max query length (chars) | 2000 |
| `SIMILARITY_THRESHOLD` | Prompt injection detection threshold | 0.6 |
| `DOCKER_TIMEOUT` | Code execution timeout (seconds) | 10 |
| `DOCKER_MEMORY_LIMIT` | Container memory limit | 512m |

### AI Providers
| Variable | Description | Default |
|----------|-------------|---------|
| `ACTIVE_PROVIDER` | Selected LLM provider | `azure_openai` |
| `AZURE_OPENAI_API_KEY` | API Key for Azure OpenAI | - |
| `AZURE_OPENAI_ENDPOINT` | Endpoint URL | - |
| `ANTHROPIC_API_KEY` | API Key for Anthropic | - |

### Observability
| Variable | Description | Default |
|----------|-------------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Jaeger/OTLP Endpoint | `http://localhost:4317` |

---

## Production Checklist

Before going to production, ensure the following:

### 1. Database Setup
- [ ] Use a managed PostgreSQL instance (e.g., AWS RDS, Azure Database for PostgreSQL).
- [ ] Enable automated backups.
- [ ] Run database migrations.

### 2. Redis Configuration
- [ ] Use a managed Redis instance (e.g., AWS ElastiCache).
- [ ] Configure eviction policy (LRU).
- [ ] Enable persistence (RDB/AOF).

### 3. Security
- [ ] **Rotate Keys**: Change all default passwords and secrets.
- [ ] **SSL/TLS**: Ensure the API is behind a Load Balancer with a valid SSL certificate.
- [ ] **Network Policies**: Restrict access to database/Redis.
- [ ] **Docker Security**: Ensure the Docker socket is protected or use a secure container runtime (gVisor) for the Stats Verification engine if possible.

### 4. Observability
- [ ] Configure alert rules in Prometheus/Grafana.
- [ ] Ensure logs are shipped to a centralized logging system.

---

## Troubleshooting

### 1. Docker Permission Denied
**Error:** `docker: Got permission denied while trying to connect to the Docker daemon socket`
**Solution:** Ensure the user running the app is in the `docker` group, or (for Docker Compose) ensure the socket is mounted correctly and the container user has permissions.

### 2. Stats Verification Failing
**Error:** `SecureCodeExecutor initialization failed`
**Solution:**
1. Check Docker is running: `docker ps`
2. Check `python:3.10-slim` image exists: `docker pull python:3.10-slim` (The executor uses this image).

---

## Operations & Monitoring

### View Recent Security Events

```bash
# Python script
python -c "
from qwed_new.core.database import get_session
from qwed_new.core.models import SecurityEvent
from sqlmodel import select

with get_session() as session:
    events = session.exec(
        select(SecurityEvent)
        .where(SecurityEvent.event_type == 'BLOCKED')
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
    ).all()
    for e in events:
        print(f'{e.timestamp}: {e.reason}')
"
```

### Security Metrics Dashboard

```bash
# Block rate by hour
sqlite3 qwed_v2.db "
SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, COUNT(*) as blocks
FROM security_event
WHERE event_type = 'BLOCKED'
GROUP BY hour
ORDER BY hour DESC
LIMIT 24;
"
```

For detailed architecture documentation, see:
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
