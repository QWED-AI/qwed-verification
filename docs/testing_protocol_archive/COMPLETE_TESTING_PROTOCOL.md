# QWED Complete Testing Protocol
## Production-Ready Testing Across All 7 Engines

**Version:** 1.0  
**Last Updated:** 2025-12-01  
**Estimated Timeline:** 15-20 days systematic implementation

---

## Table of Contents
1. [Code Engine Tests](#part-1-code-engine-deep-dive)
2. [Math Engine Tests](#part-2-math-engine-deep-dive)
3. [Logic Engine Tests](#part-3-logic-engine-deep-dive)
4. [Stats Engine Tests](#part-4-stats-engine-deep-dive) ⭐ **NEW**
5. [SQL Engine Tests](#part-5-sql-engine-deep-dive) ⭐ **NEW**
6. [Fact Engine Tests](#part-6-fact-engine-deep-dive) ⭐ **NEW**
7. [Image Engine Tests](#part-7-image-engine-deep-dive) ⭐ **NEW**
8. [Cross-Engine Integration](#part-8-cross-engine-integration)
9. [Stress & Performance](#part-9-stress-and-performance-tests)
10. [Implementation Guide](#part-10-implementation-guide)

---

## PART 1: CODE ENGINE DEEP DIVE

### 1.1 Context-Aware Detection (CRITICAL)

#### Test 1A: User Input Flow Through Function Boundaries
**What you're testing:** Does QWED track tainted data across multiple function calls?

**Test Code:**
```python
def get_user_input():
    return input("Enter path: ")

def sanitize(data):
    # Pretends to sanitize but doesn't
    return data

def process_file(path):
    subprocess.run(["ls", path])

# The flow
user_path = get_user_input()
clean_path = sanitize(user_path)
process_file(clean_path)
```

**Expected Result:** CRITICAL - Command injection via tainted user input

**Pass Criteria:**
- ✅ Detects vulnerability
- ✅ Traces taint through all 3 functions
- ✅ Reports correct line numbers

---

#### Test 1B: Variable Aliasing Detection
**Test Code:**
```python
user_data = input("Enter command: ")
safe_looking_var = user_data
another_name = safe_looking_var
totally_safe = another_name
subprocess.run(["sh", "-c", totally_safe])
```

**Expected Result:** CRITICAL - Detected despite 4 levels of aliasing

**Pass Criteria:**
- ✅ Still detects taint after 4 aliases
- ✅ Reports original source (input())
- ✅ Identifies sink (subprocess.run)

---

### 1.2 AST Edge Cases (CRITICAL)

#### Test 2A: Dynamic Import Detection
```python
module_name = input("Module: ")
imported = __import__(module_name)  # RCE
```

**Expected:** CRITICAL for all dynamic import patterns

---

#### Test 2B: Reflection-Based Code Execution
```python
method_name = input("Method: ")
api = MyAPI()
getattr(api, method_name)()  # Arbitrary method execution
```

**Expected:** CRITICAL - Reflection with user input

---

### 1.3 Cryptography Misuse (HIGH)

#### Test 3A: Weak Hash for Passwords
```python
# Case 1: MD5 for password (BAD)
password = input("Password: ")
hashed = hashlib.md5(password.encode()).hexdigest()

# Case 2: MD5 for checksum (OK)
file_data = open("data.txt", "rb").read()
checksum = hashlib.md5(file_data).hexdigest()
```

**Expected:**
- Case 1: CRITICAL
- Case 2: SAFE or INFO

---

## PART 2: MATH ENGINE DEEP DIVE

### 2.1 Expression Ambiguity Detection (HIGH)

#### Test 4A: Order of Operations Ambiguity
```python
# The famous case
expr = "8/2(2+2)"
# Could be: (8/2)*(2+2) = 16
# Or: 8/(2*(2+2)) = 1
```

**Expected:** WARNING - Ambiguous expression with both interpretations explained

---

#### Test 4B: Implicit Multiplication Handling
```python
expr1 = "2x + 3"
expr2 = "2*x + 3"
# Should be equivalent
```

**Pass Criteria:**
- ✅ Treats 2x and 2*x identically
- ✅ Documents parsing rules

---

### 2.2 Symbolic Simplification (CRITICAL)

#### Test 5A: Algebraic Identity Verification
```python
# Test 1: TRUE
claim1 = "(x² - y²) = (x-y)(x+y)"

# Test 2: FALSE
claim2 = "(x+y)² = x² + y²"  # Missing 2xy

# Test 3: FALSE
claim3 = "√(x²) = x"  # Should be |x|
```

**Expected:** Catch all false identities with explanations

---

## PART 3: LOGIC ENGINE DEEP DIVE

### 3.1 Schema Validation (CRITICAL)

#### Test 6A: Type Mismatch Handling
```json
{
  "constraints": [
    {
      "type": "integer",
      "variable": "x",
      "value": "not_a_number"
    }
  ]
}
```

**Expected:** Schema validation error BEFORE calling Z3

---

### 3.2 Z3 Solver Edge Cases (CRITICAL)

#### Test 7A: Contradiction Detection (UNSAT)
```python
# Test 1: Simple contradiction
x > 10 AND x < 5

# Test 2: Circular
x = y + 1 AN D y = x + 1
```

**Expected:** UNSAT with conflicting constraint pairs identified

---

#### Test 7B: Solver Timeout Handling
```python
# 1000 variables with circular dependencies
# Should timeout after 30 seconds with graceful error
```

---

## PART 4: STATS ENGINE DEEP DIVE ⭐

### 4.1 Docker Isolation Validation (CRITICAL)

#### Test 8A: DataFrame.eval Injection
```python
import pandas as pd
user_formula = input("Formula: ")
df = pd.DataFrame({"x": [1,2,3]})
result = df.eval(user_formula)  # Can execute arbitrary code!
```

**Expected:** CRITICAL - Arbitrary code execution via eval

**Why This Matters:** `DataFrame.eval()` uses Python's `eval()` internally. If user controls the formula, they can inject:
```python
user_formula = "__import__('os').system('rm -rf /')"
```

**Pass Criteria:**
- ✅ Detects eval in pandas context
- ✅ Flags user input to eval as CRITICAL
- ✅ Suggests safe alternatives (e.g., predefined formulas)

---

#### Test 8B: Exec in Analysis Code
```python
analysis_code = input("Enter analysis: ")
exec(analysis_code)  # Direct RCE
```

**Expected:** CRITICAL - exec with user input

---

### 4.2 Statistical Correctness (HIGH)

#### Test 9A: T-Test Implementation Verification
```python
# LLM claims this computes a t-test correctly
def t_test(data1, data2):
    mean_diff = np.mean(data1) - np.mean(data2)
    # Missing: pooled variance, degrees of freedom
    return mean_diff  # WRONG!
```

**Expected:** WARNING - Incorrect statistical implementation

**How to verify:**
- Compare with `scipy.stats.ttest_ind()`
- Check if degrees of freedom are calculated
- Verify pooled variance computation

---

#### Test 9B: Correlation Coefficient Bounds
```python
# LLM claims r=1.5 is a valid correlation
def my_correlation(x, y):
    return 1.5  # IMPOSSIBLE! Must be [-1,1]
```

**Expected:** CRITICAL - Statistical impossibility

---

### 4.3 Large Dataset Handling (HIGH)

#### Test 10A: Performance on 1M+ Rows
```python
code = '''
import pandas as pd
import numpy as np
df = pd.DataFrame(np.random.rand(1000000, 100))
mean = df.mean()
std = df.std()
'''
```

**Expected:**
- Completes in <30 seconds
- No memory leaks
- Returns valid result

---

#### Test 10B: Memory Leak Detection
```python
# Run same analysis code 100 times
# Memory should not grow unbounded
for i in range(100):
    result = verify_stats(analysis_code)
```

**Pass Criteria:**
- ✅ Memory usage stabilizes
- ✅ Docker containers are properly cleaned up

---

## PART 5: SQL ENGINE DEEP DIVE ⭐

### 5.1 SQL Injection Detection (CRITICAL)

#### Test 11A: Classic UNION Injection
```python
username = "admin' UNION SELECT * FROM passwords--"
query = f"SELECT * FROM users WHERE name='{username}'"
```

**Expected:** CRITICAL - SQL injection detected

**Pass Criteria:**
- ✅ Detects UNION attack
- ✅ Identifies SQL comment (--) usage
- ✅ Suggests parameterized queries

---

#### Test 11B: Blind SQL Injection (Time-Based)
```python
username = "admin' AND SLEEP(5)--"
query = f"SELECT * FROM users WHERE user='{username}'"
```

**Expected:** CRITICAL - Time-based blind injection

**Why This Matters:** Attacker doesn't see data directly, but can infer information based on query execution time.

---

#### Test 11C: NoSQL Injection
```python
# MongoDB example
query = {"username": {"$gt": ""}}  # Returns all users!
```

**Expected:** CRITICAL - NoSQL operator injection

---

### 5.2 Schema Validation (HIGH)

#### Test 12A: Table/Column Existence Check
```python
# LLM claims this is safe
query = "SELECT * FROM nonexistent_table WHERE secret_column = 'value'"
schema = {"tables": ["users", "posts"]}
```

**Expected:** WARNING - Table doesn't exist in schema

**Pass Criteria:**
- ✅ Validates table names against provided schema
- ✅ Validates column names
- ✅ Suggests correct table/column names

---

### 5.3 Query Complexity Limits (MEDIUM)

#### Test 13A: Nested SELECT Bomb
```python
query = """
SELECT * FROM (
  SELECT * FROM (
    SELECT * FROM (
      -- 50 levels deep
    )
  )
)
"""
```

**Expected:** WARNING - Excessive nesting may cause DoS

**Pass Criteria:**
- ✅ Limits nesting depth to reasonable threshold (e.g., 10 levels)
- ✅ Warns about performance implications

---

## PART 6: FACT ENGINE DEEP DIVE ⭐

### 6.1 Knowledge Cutoff Detection (CRITICAL)

#### Test 14A: Post-2023 Event Claims
```python
claim = "In 2024, OpenAI released GPT-5"
result = verify_fact(claim, context={})
```

**Expected:** `NOT_ENOUGH_INFO` - Post-cutoff date

**Pass Criteria:**
- ✅ Detects that 2024 is after cutoff
- ✅ Returns NOT_ENOUGH_INFO (not REFUTED)
- ✅ Explains cutoff limitation

---

#### Test 14B: Future Predictions
```python
claim = "Tomorrow will be sunny in Mumbai"
```

**Expected:** `NOT_ENOUGH_INFO` - Future prediction, not verifiable fact

---

### 6.2 Hallucination vs Uncertainty (CRITICAL)

#### Test 15A: Clearly False Claim
```python
claim = "The Eiffel Tower is located in London"
```

**Expected:** `REFUTED` (high confidence)

---

#### Test 15B: Uncertain Claim
```python
claim = "The population of city X is exactly 1,234,567"
```

**Expected:** `NOT_ENOUGH_INFO` - Too specific, hard to verify

**Pass Criteria:**
- ✅ Distinguishes between "definitely false" and "unverifiable"
- ✅ Provides confidence scores

---

### 6.3 Contradictory Claims Detection (HIGH)

#### Test 16A: Direct Contradiction
```python
claims = [
    "Paris is the capital of France",
    "Berlin is the capital of France"
]
```

**Expected:** Detects contradiction between claims

---

### 6.4 Source Citation Validation (MEDIUM)

#### Test 17A: Cited Source Exists
```python
claim = "According to study X published in journal Y..."
```

**Expected:** Verify source can be checked (if possible)

---

## PART 7: IMAGE ENGINE DEEP DIVE ⭐

### 7.1 OCR Accuracy (HIGH)

#### Test 18A: Rotated Text
```python
image = generate_rotated_text_image("Hello World", angle=45)
claim = "Image contains 'Hello World'"
```

**Expected:** Correctly identifies text despite rotation

---

#### Test 18B: Adversarial Font
```python
image = generate_image_with_font("Hello", font="zalgo_text.ttf")
```

**Expected:** Either correctly identifies or returns low confidence

---

### 7.2 Multimodal Claim-Image Alignment (CRITICAL)

#### Test 19A: Claim Mismatch
```python
image = load_image("cat.jpg")
claim = "This image shows a dog"
```

**Expected:** `REFUTED` - Image doesn't match claim

---

#### Test 19B: Partial Match
```python
image = load_image("cat_and_dog.jpg")
claim = "This image contains a cat"
```

**Expected:** `SUPPORTED` - Claim is partially true

---

### 7.3 Image Manipulation Detection (HIGH)

#### Test 20A: Photoshopped Image
```python
image = load_photoshopped_image("fake_moon_landing.jpg")
claim = "This is an unedited photo"
```

**Expected:** WARNING - Shows signs of manipulation (if detectable)

---

## PART 8: CROSS-ENGINE INTEGRATION

### 8.1 Code + Math Hybrid (MEDIUM)

#### Test 21A: Mathematical Implementation
```python
def derivative(expr):
    """Claims: Computes d/dx(x²) = 2x"""
    if expr == "x**2":
        return "2*x"
    return "unknown"
```

**Expected:**
- Code Engine: SAFE (no security issues)
- Math Engine: VERIFIED (derivative is correct)

---

### 8.2 Logic + Code Hybrid (MEDIUM)

#### Test 22A: Algorithmic Correctness
```python
def is_sorted(arr):
    """Claims: Verifies ∀i: arr[i] ≤ arr[i+1]"""
    for i in range(len(arr)-1):
        if arr[i] > arr[i+1]:
            return False
    return True
```

**Expected:**
- Logic Engine: Constraint is valid
- Code Engine: Implementation matches claim

---

## PART 9: STRESS AND PERFORMANCE TESTS

### 9.1 Scale Tests (HIGH)

#### Test 23A: Large File Handling
```python
# Generate 10,000 line file with 50 vulnerabilities
huge_code = generate_huge_file(lines=10000, vulns=50)
```

**Expected:**
- Completes in <30 seconds
- Finds all 50 vulnerabilities

---

#### Test 23B: Concurrent Requests
```python
# Send 100 simultaneous requests
with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(verify_code, code) for _ in range(100)]
```

**Expected:**
- All requests complete successfully
- Average latency <5 seconds

---

### 9.2 Malformed Input (CRITICAL)

#### Test 24A: Edge Cases
```python
# Test empty string
verify_code("")

# Test binary data
verify_code(b"\x89\x50\x4e\x47")

# Test null bytes
verify_code("x = 1\x00\ny = 2")

# Test Unicode nightmares
verify_code("def 函数(): pass")
```

**Expected:** Graceful errors (not crashes) for all

---

## PART 10: IMPLEMENTATION GUIDE

### How to Run This Audit

#### Step 1: Set Up
```bash
cd qwed_new/tests/advanced_audit
pip install -r requirements.txt
```

#### Step 2: Configure
Edit `config.yaml`:
```yaml
api:
  url: "http://13.71.22.94:8000"
  key: "qwed_live_..."
```

#### Step 3: Run Tests
```bash
# Run all tests
python run_complete_audit.py --all

# Run by priority
python run_complete_audit.py --priority CRITICAL

# Run specific engine
python run_complete_audit.py --engine stats

# Generate report
python run_complete_audit.py --report html
```

---

## Success Metrics (By Day 20)

### Must Have:
- [ ] 100% of CRITICAL tests pass
- [ ] 90%+ of HIGH tests pass
- [ ] 80%+ of MEDIUM tests pass
- [ ] No crashes on malformed input
- [ ] Handle 100 concurrent requests
- [ ] Process 10,000 line files in <30s
- [ ] Consistent schema across all engines

### Per-Engine Targets:
- [ ] Code Engine: 95%+
- [ ] Math Engine: 85%+
- [ ] Logic Engine: 85%+
- [ ] Stats Engine: 80%+
- [ ] SQL Engine: 90%+
- [ ] Fact Engine: 75%+
- [ ] Image Engine: 70%+

---

**This is how protocols are hardened. Systematically. Relentlessly. No shortcuts.**
