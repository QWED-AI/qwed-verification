# QWED Security Audit Checklist (OWASP LLM Top 10 2025)

## Automated Tests

### LLM01: Prompt Injection
- [ ] Basic injection patterns blocked
- [ ] Base64 encoded attacks blocked
- [ ] Unicode/emoji evasion blocked
- [ ] Long input (>2000 chars) blocked
- [ ] System prompt mimicry blocked
- [ ] Multi-language script mixing blocked
- [ ] Zero-width character injection blocked

**Test command:**
```bash
pytest tests/test_security_gateway.py -v
```

### LLM02: Insecure Output Handling
- [ ] XSS vectors sanitized (<script> tags removed)
- [ ] HTML encoding applied
- [ ] JavaScript URLs blocked
- [ ] iframe tags removed
- [ ] Math expressions whitelisted only

**Test command:**
```bash
pytest tests/test_output_sanitizer.py -v
```

### LLM06: Excessive Agency (Code Execution)
- [ ] Docker isolation working
- [ ] Resource limits enforced (CPU, memory, time)
- [ ] Network isolation active
- [ ] Dangerous imports blocked (os, subprocess, eval)
- [ ] File system access restricted

**Test command:**
```bash
pytest tests/test_secure_executor.py -v
```

---

## Manual Penetration Tests

### Test 1: SQL Injection via Query Parameter
**Objective:** Attempt SQL injection through API inputs

```bash
curl -X POST http://13.71.22.94:8000/verify/natural_language \
  -H 'x-api-key: qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI' \
  -H 'Content-Type: application/json' \
  -d '{"query": "1'; DROP TABLE users; --"}'
```

**Expected:** Request blocked or sanitized, no database impact

---

### Test 2: Rate Limit Bypass
**Objective:** Exceed 100 req/min limit

```bash
# Run this script
for i in {1..150}; do
  curl -X POST http://13.71.22.94:8000/verify/natural_language \
    -H 'x-api-key: qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI' \
    -H 'Content-Type: application/json' \
    -d '{"query": "What is 2+2?"}' &
done
wait
```

**Expected:** Requests 101-150 return HTTP 429

---

### Test 3: API Key Brute Force
**Objective:** Attempt to guess valid API keys

```bash
# Try invalid keys rapidly
for i in {1..1000}; do
  curl -X POST http://13.71.22.94:8000/verify/natural_language \
    -H 'x-api-key: qwed_live_invalid_$i' \
    -H 'Content-Type: application/json' \
    -d '{"query": "test"}' 2>&1 | grep -c "401"
done
```

**Expected:** All return 401, IP potentially blacklisted after threshold

---

### Test 4: Docker Escape Attempt
**Objective:** Try to break out of sandbox

```python
# Upload this as CSV data for stats verification
import os
os.system('cat /etc/passwd')  # Try to read host files
```

**Expected:** Code execution blocked before Docker, or fails silently in container

---

### Test 5: JWT Token Tampering
**Objective:** Modify JWT token to escalate privileges

```bash
# Get a valid JWT token from /auth/signin
# Decode it, change "role": "viewer" to "role": "admin"
# Re-encode and try to access admin endpoints

curl -X GET http://13.71.22.94:8000/admin/compliance/export/csv \
  -H 'Authorization: Bearer TAMPERED_TOKEN'
```

**Expected:** Token rejected, signature validation fails

---

### Test 6: Audit Log Tampering
**Objective:** Modify database logs directly

```bash
# SSH to server, modify qwed_v2.db directly
sqlite3 qwed_v2.db "UPDATE verificationlog SET result='HACKED' WHERE id=1;"

# Then verify via API
curl http://13.71.22.94:8000/admin/compliance/verify/1 \
  -H 'x-api-key: ADMIN_KEY'
```

**Expected:** Hash chain broken, verification fails

---

### Test 7: CORS Bypass
**Objective:** Make cross-origin requests from malicious site

```html
<!-- Host this HTML file on different domain -->
<script>
fetch('http://13.71.22.94:8000/verify/natural_language', {
  method: 'POST',
  headers: {
    'x-api-key': 'STOLEN_KEY',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({query: "What is 2+2?"})
}).then(r => r.json()).then(console.log);
</script>
```

**Expected:** CORS policy allows (since you set allow_origins=["*"]), but API key required

---

### Test 8: Memory Exhaustion
**Objective:** Crash server with resource-intensive query

```bash
curl -X POST http://13.71.22.94:8000/verify/natural_language \
  -H 'x-api-key: qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI' \
  -H 'Content-Type: application/json' \
  -d '{"query": "Calculate factorial of 100000"}'
```

**Expected:** Timeout after 10 seconds, or error returned

---

## Compliance Verification

### GDPR Right to Access
```bash
# Request all data for organization
curl http://13.71.22.94:8000/admin/compliance/export/gdpr/1 \
  -H 'x-api-key: qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI' > gdpr_export.json

# Verify contains:
# - All verification logs
# - API keys (hashed)
# - User data
# - Timestamps
```

### SOC 2 Audit Trail
```bash
# Generate SOC 2 report
curl http://13.71.22.94:8000/admin/compliance/report/soc2/1 \
  -H 'x-api-key: qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI' > soc2_report.json

# Verify includes:
# - Security controls documentation
# - Incident log (should be empty)
# - Uptime metrics
# - Access control logs
```

---

## Results Template

| Test ID | Test Name | Status | Notes |
|---------|-----------|--------|-------|
| LLM01-1 | Basic injection blocked | ⏳ PENDING | |
| LLM01-2 | Base64 evasion blocked | ⏳ PENDING | |
| LLM02-1 | XSS sanitized | ⏳ PENDING | |
| PEN-1 | SQL injection blocked | ⏳ PENDING | |
| PEN-2 | Rate limit enforced | ⏳ PENDING | |
| PEN-3 | API key brute force | ⏳ PENDING | |
| PEN-4 | Docker escape prevented | ⏳ PENDING | |
| PEN-5 | JWT tampering blocked | ⏳ PENDING | |
| PEN-6 | Audit integrity maintained | ⏳ PENDING | |
| PEN-7 | CORS configured | ⏳ PENDING | |
| PEN-8 | Memory exhaustion prevented | ⏳ PENDING | |
| COMP-1 | GDPR export working | ⏳ PENDING | |
| COMP-2 | SOC 2 report generated | ⏳ PENDING | |

**Overall Security Score:** __/100

**Critical Issues:** 0  
**High Issues:** 0  
**Medium Issues:** 0  
**Low Issues:** 0

**Certification Readiness:** ⏳ TESTING IN PROGRESS
