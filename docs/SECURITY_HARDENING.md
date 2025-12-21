# QWED Security Hardening Guide

This guide provides instructions for hardening your QWED deployment for production environments. It covers secret management, network security, authentication, and compliance with OWASP LLM Top 10.

## 1. Secret Management

QWED relies on environment variables for sensitive configuration. **Never commit `.env` files to version control.**

### Environment Variable Injection

For production deployments, we recommend injecting environment variables using your infrastructure's secret management solution.

#### Docker / Kubernetes
Use Kubernetes Secrets or HashiCorp Vault to inject secrets as environment variables into the container.

```yaml
# Example Kubernetes Pod Spec
env:
  - name: OPENAI_API_KEY
    valueFrom:
      secretKeyRef:
        name: qwed-secrets
        key: openai-api-key
  - name: JWT_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: qwed-secrets
        key: jwt-secret
```

#### HashiCorp Vault Integration
If you use Vault, you can use `envconsul` or the Vault Agent Injector to populate environment variables before the application starts.

```bash
# Example with envconsul
envconsul -prefix qwed/prod/ qwed-api
```

### Critical Secrets
Ensure these secrets are rotated regularly:
- `OPENAI_API_KEY` (and other provider keys)
- `JWT_SECRET_KEY` (used for signing session tokens)
- `DATABASE_URL` (if using an external database)

---

## 2. Network Security

### Firewall Rules
Restrict network access to the QWED API server:

- **Public Access**: Allow ports `80` / `443` only via a Load Balancer / WAF.
- **Internal Access**: The QWED application port (default `8000`) should **not** be directly exposed to the internet.
- **Database**: Block all public access to the database port (e.g., `5432`). Only allow connections from the QWED application subnet.

### Rate Limiting (Production)
QWED includes a default in-memory rate limiter. For production, you should tune these limits and consider a distributed solution.

#### Configuration
You can adjust the rate limits using environment variables:

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `100` | Max requests per minute **per API key**. |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Time window in seconds. |

**Example:**
```bash
export RATE_LIMIT_REQUESTS_PER_MINUTE=50
export RATE_LIMIT_WINDOW_SECONDS=60
```

#### Redis Backing (Recommended)
The default in-memory limiter does not scale across multiple worker processes or replicas. For high-availability deployments, we recommend replacing the in-memory `RateLimiter` class with a Redis-backed implementation to ensure consistent enforcement across your cluster.

### CORS Configuration
By default, QWED is configured for development (`*`). You **must** restrict this in production to prevent unauthorized cross-origin requests.

Set the `CORS_ALLOWED_ORIGINS` environment variable to a comma-separated list of trusted domains.

```bash
export CORS_ALLOWED_ORIGINS="https://app.yourcompany.com,https://admin.yourcompany.com"
```

---

## 3. Authentication Hardening

### API Key Rotation
Regularly rotate API keys to minimize the impact of a potential leak.
QWED provides a built-in rotation mechanism:
- Use the `rotate_key` function in `src/qwed_new/core/key_rotation.py` or the administrative API endpoint to issue new keys.
- Old keys should be revoked immediately after the rotation window.

### Password Policies
If you integrate QWED with a custom user database:
- Enforce a minimum length of 12 characters.
- Require a mix of uppercase, lowercase, numbers, and special characters.
- Use the built-in `bcrypt` hashing (already implemented in `src/qwed_new/auth/security.py`).

### Session Management
Control the lifetime of access tokens to reduce the window of opportunity for session hijacking.

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Minutes until the access token expires. |

**Recommendation:** Set this to a lower value (e.g., `15` or `30` minutes) and implement refresh tokens if needed.

```bash
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
```

---

## 4. OWASP LLM Top 10 Compliance

QWED implements technical defenses for the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/). However, security is a shared responsibility.

### Your Responsibilities (User/Deployment)

While QWED handles internal verification, you must implement the following "Human in the Loop" and deployment safeguards:

#### LLM01: Prompt Injection & LLM02: Insecure Output Handling
- **Human in the Loop**: For critical actions (e.g., financial transactions, code deployment), do not rely solely on QWED's verification. Implement a manual approval step.
- **Output Monitoring**: Log and randomly audit verified outputs to ensure the verification engine itself hasn't been bypassed.

#### LLM05: Supply Chain Vulnerabilities
- **Network Isolation**: Run the QWED backend in a VPC without direct outbound internet access, except to specific LLM provider APIs (allowlist).
- **Dependency Scanning**: Regularly scan your deployment container for vulnerabilities in system packages.

#### LLM06: Sensitive Information Disclosure
- **Data Minimization**: Do not send PII (Personally Identifiable Information) to QWED unless absolutely necessary. Mask or redact sensitive data *before* it reaches the API.

For a full list of QWED's internal defenses, see [docs/security.md](security.md).
