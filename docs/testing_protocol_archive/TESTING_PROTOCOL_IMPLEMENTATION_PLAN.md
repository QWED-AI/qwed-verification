# QWED Complete Testing Protocol - Implementation Plan

## Overview

**Timeline:** 15-20 days systematic implementation  
**Scope:** All 7 QWED engines (Code, Math, Logic, Stats, SQL, Fact, Image)  
**Deliverables:** 200-350 automated tests, reporting infrastructure, comprehensive audit

---

## Phase 1: Core Test Infrastructure (Days 1-3)

### Day 1: Test Runner Framework

**Goal:** Build the backbone for all future tests

**Components:**
```
tests/advanced_audit/
├── run_complete_audit.py          # Main orchestrator
├── base_test.py                   # Base test class
├── api_client.py                  # QWED API wrapper with retry
└── config.yaml                    # Centralized configuration
```

**Key Features:**
- Priority-based execution (CRITICAL → HIGH → MEDIUM)
- Result aggregation across all engines
- Timeout handling (30 seconds per test)
- Concurrent test support
- Detailed logging

**Example Implementation:**
```python
class QWEDTestRunner:
    def __init__(self, config_path: str):
        self.config = yaml.load(open(config_path))
        self.client = QWEDAPIClient(
            url=self.config['api']['url'],
            api_key=self.config['api']['key']
        )
        
    def run_tests(self, priority: str = "ALL"):
        """Run tests filtered by priority"""
        if priority == "CRITICAL":
            tests = self.critical_tests
        elif priority == "ALL":
            tests = self.all_tests
        
        for test in tests:
            result = test.execute(self.client)
            self.results.append(result)
```

---

### Day 2: Report Generation

**Goal:** Convert test results into actionable insights

**Components:**
```
tests/advanced_audit/reporters/
├── json_reporter.py               # Machine-readable output
├── markdown_reporter.py           # Human-readable summary
├── html_reporter.py               # Interactive dashboard
└── ci_reporter.py                 # CI/CD integration format
```

**Report Formats:**

**JSON Report:**
```json
{
  "timestamp": "2025-12-01T04:30:00",
  "summary": {
    "total_tests": 287,
    "passed": 246,
    "failed": 41,
    "pass_rate": 85.7
  },
  "by_engine": {
    "code": {"passed": 45, "failed": 2, "pass_rate": 95.7},
    "math": {"passed": 38, "failed": 7, "pass_rate": 84.4}
  }
}
```

**Markdown Report:**
```markdown
# QWED Test Audit - 2025-12-01

## Summary
- **Total Tests:** 287
- **Pass Rate:** 85.7%
- **Critical Failures:** 2

## Per-Engine Results
| Engine | Tests | Passed | Failed | Pass Rate |
|--------|-------|--------|--------|-----------|
| Code   | 47    | 45     | 2      | 95.7%     |
| Math   | 45    | 38     | 7      | 84.4%     |
```

---

### Day 3: Config & Fixtures

**Goal:** Centralized configuration and test utilities

**config.yaml:**
```yaml
api:
  url: "http://13.71.22.94:8000"
  key: "qwed_live_..."
  timeout: 30

test_priorities:
  critical:
    - context_aware_detection
    - sql_injection
    - rce_detection
  high:
    - crypto_misuse
    - hallucination_detection
  medium:
    - ambiguity_detection
    - performance_tests

performance:
  max_concurrent: 100
  max_file_size_lines: 10000
  timeout_threshold: 30

reporting:
  output_dir: "./test_results"
  formats: ["json", "markdown", "html"]
```

**conftest.py (pytest fixtures):**
```python
import pytest
from api_client import QWEDAPIClient

@pytest.fixture
def qwed_client():
    """Provide configured QWED API client"""
    return QWEDAPIClient(
        url="http://13.71.22.94:8000",
        api_key="qwed_live_..."
    )

@pytest.fixture
def test_data_dir(tmp_path):
    """Provide temporary directory for test data"""
    return tmp_path / "test_data"
```

---

## Phase 2: Test Validated Engines (Days 4-6)

### Day 4: Code Engine Test Suite

**Goal:** Validate the engine you've already tested publicly

**Priority Tests:**
```python
# 1. Context-Aware Detection (CRITICAL)
def test_user_input_flow_through_functions():
    code = '''
def get_input():
    return input("Path: ")

def process(path):
    subprocess.run(["ls", path])

path = get_input()
process(path)
'''
    result = verify_code(code)
    assert result["severity_summary"]["critical"] > 0

# 2. Variable Aliasing (CRITICAL)
def test_variable_aliasing():
    code = '''
user_data = input()
safe_var = user_data
another = safe_var
subprocess.run(["sh", "-c", another])
'''
    result = verify_code(code)
    assert not result["is_safe"]

# 3. Reflection Code Execution (CRITICAL)
def test_getattr_abuse():
    code = '''
method_name = input("Method: ")
getattr(api, method_name)()
'''
    result = verify_code(code)
    assert "reflection" in str(result["issues"]).lower()
```

**Expected:** 90%+ pass rate (you've tested this)

---

### Day 5: Math Engine Test Suite

**Key Tests:**
```python
# 1. Order of Operations Ambiguity (HIGH)
def test_ambiguous_expression():
    expr = "8/2(2+2)"
    result = verify_math(expr)
    assert result["requires_manual_review"] == True
    assert "ambiguous" in str(result["issues"]).lower()

# 2. Implicit Multiplication (HIGH)
def test_implicit_multiplication():
    expr1 = "2x + 3"
    expr2 = "2*x + 3"
    # Should be treated identically
    result1 = verify_math(expr1)
    result2 = verify_math(expr2)
    # Check consistency

# 3. Domain Restrictions (CRITICAL)
def test_sqrt_domain():
    claim = "√x is real for all x"
    result = verify_math(claim)
    assert not result["is_safe"]
    assert "domain" in str(result["issues"]).lower()
```

**Expected:** Find gaps, document them

---

### Day 6: Logic Engine Test Suite

**Key Tests:**
```python
# 1. Type Mismatch Handling (CRITICAL)
def test_type_mismatch():
    constraints = {
        "constraints": [
            {"type": "integer", "variable": "x", "value": "not_a_number"}
        ]
    }
    result = verify_logic(constraints)
    assert "type" in str(result["error"]).lower()

# 2. UNSAT Detection (CRITICAL)
def test_contradiction():
    constraints = "x > 10 AND x < 5"
    result = verify_logic(constraints)
    assert result["status"] == "UNSAT"

# 3. Quantifiers (HIGH)
def test_universal_quantifier():
    claim = "forall x: (x > 0) → (x² > 0)"
    result = verify_logic(claim)
    assert result["status"] == "VALID"
```

**Expected:** Fix schema bugs you mentioned

---

## Phase 3: Test New Engines (Days 7-11)

### Day 7: Stats Engine Test Suite

**Critical Tests:**
```python
# 1. DataFrame.eval Injection (CRITICAL)
def test_dataframe_eval_injection():
    code = '''
import pandas as pd
user_formula = input("Formula: ")
df = pd.DataFrame({"x": [1,2,3]})
result = df.eval(user_formula)  # RCE!
'''
    result = verify_stats(code, context={})
    assert not result["is_safe"]
    assert "eval" in str(result["issues"]).lower()

# 2. Exec in Stats Code (CRITICAL)
def test_exec_in_stats():
    code = '''
analysis_code = input("Analysis: ")
exec(analysis_code)
'''
    result = verify_stats(code, context={})
    assert result["severity_summary"]["critical"] > 0

# 3. Large Dataset Handling (HIGH)
def test_large_dataset_performance():
    code = '''
import pandas as pd
import numpy as np
df = pd.DataFrame(np.random.rand(1000000, 100))
mean = df.mean()
'''
    start = time.time()
    result = verify_stats(code, context={})
    elapsed = time.time() - start
    assert elapsed < 30  # Must complete in 30 seconds
```

---

### Day 8: SQL Engine Test Suite

**Critical Tests:**
```python
# 1. Classic SQL Injection (CRITICAL)
def test_union_injection():
    username = "admin' UNION SELECT * FROM passwords--"
    query = f"SELECT * FROM users WHERE name='{username}'"
    result = verify_sql(query, schema)
    assert not result["is_safe"]

# 2. Blind SQL Injection (CRITICAL)
def test_blind_injection():
    username = "admin' AND SLEEP(5)--"
    query = f"SELECT * FROM users WHERE user='{username}'"
    result = verify_sql(query, schema)
    assert "injection" in str(result["issues"]).lower()

# 3. NoSQL Injection (HIGH)
def test_nosql_injection():
    query = {"username": {"$gt": ""}}
    result = verify_sql(query, schema)
    assert not result["is_safe"]
```

---

### Day 9: Fact Engine Test Suite

**Critical Tests:**
```python
# 1. Knowledge Cutoff (CRITICAL)
def test_post_cutoff_claim():
    claim = "In 2024, company X was acquired by Y"
    result = verify_fact(claim, context={})
    assert result["verdict"] == "NOT_ENOUGH_INFO"
    assert "cutoff" in str(result["reasoning"]).lower()

# 2. Contradictory Claims (CRITICAL)
def test_contradictions():
    claims = [
        "Paris is the capital of France",
        "Berlin is the capital of France"
    ]
    # Should detect contradiction
    
# 3. Future Predictions (HIGH)
def test_future_claim():
    claim = "Tomorrow will be sunny in Mumbai"
    result = verify_fact(claim, context={})
    assert result["verdict"] == "NOT_ENOUGH_INFO"
```

---

### Days 10-11: Image Engine Test Suite

**Tests:**
```python
# 1. OCR on Rotated Text (HIGH)
def test_ocr_rotated():
    image = generate_rotated_text_image("Hello World", angle=45)
    result = verify_image(image, claim="Image contains 'Hello World'")
    assert result["verdict"] in ["SUPPORTED", "REFUTED"]

# 2. Claim-Image Mismatch (CRITICAL)
def test_claim_mismatch():
    image = load_image("cat.jpg")
    claim = "This image shows a dog"
    result = verify_image(image, claim)
    assert result["verdict"] == "REFUTED"
```

---

## Phase 4: Integration & Stress (Days 12-14)

### Day 12: Cross-Engine Tests

```python
# Code + Math Hybrid
def test_derivative_implementation():
    code = '''
def derivative(expr):
    """Claims: d/dx(x²) = 2x"""
    if expr == "x**2":
        return "2*x"
'''
    # Code engine checks implementation
    code_result = verify_code(code)
    # Math engine verifies claim
    math_result = verify_math("d/dx(x²) = 2x")
    
    assert code_result["is_safe"]
    assert math_result["is_verified"]
```

### Day 13: Stress Tests

```python
# Large File Handling
def test_large_file():
    code = generate_10000_line_file()
    start = time.time()
    result = verify_code(code)
    elapsed = time.time() - start
    assert elapsed < 30

# Concurrent Requests
def test_concurrent_requests():
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(verify_code, test_code) 
                   for _ in range(100)]
        results = [f.result() for f in futures]
    assert all(r["is_safe"] is not None for r in results)
```

---

## Success Metrics (By Day 20)

### Per-Engine Targets:
- **Code Engine:** 95%+ (already validated)
- **Math Engine:** 85%+
- **Logic Engine:** 85%+
- **Stats Engine:** 80%+
- **SQL Engine:** 90%+
- **Fact Engine:** 75%+
- **Image Engine:** 70%+

### Overall System:
- 100% CRITICAL tests passing
- 90%+ HIGH priority tests passing
- No crashes on malformed input
- <30 second timeout for all operations
- Handles 100 concurrent requests
- Consistent error schema across all engines

---

## Daily Reporting Template

```markdown
# Day X Report: [Engine Name]

## Tests Run
- Total: 47
- Passed: 38 (81%)
- Failed: 9 (19%)

## Critical Failures
1. [Test Name] - [Reason]
2. [Test Name] - [Reason]

## Action Items
- [ ] Fix: [Issue description]
- [ ] Document: [Gap found]
- [ ] Investigate: [Unexpected behavior]

## Next Steps
[What to focus on tomorrow]
```
