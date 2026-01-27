# Good First Issue Templates

Use these templates to create issues with the `good first issue` label on GitHub.

---

## Issue 1: Add Edge Case Tests for Statistics Engine

**Title:** `[Testing] Add edge case tests for Statistics Engine`

**Labels:** `good first issue`, `testing`, `help wanted`

**Body:**
```
## 📋 Description

The Statistics Engine needs additional test coverage for edge cases.

## 🎯 What needs to be done

Add test cases for:
- [ ] Empty data arrays
- [ ] Single element arrays
- [ ] Very large numbers (overflow scenarios)
- [ ] Negative numbers in variance calculations

## 📁 Files to modify

- `tests/test_stats_verifier.py`

## 🏃 How to run tests

```bash
pytest tests/test_stats_verifier.py -v
```

## ⏱️ Estimated time

~1-2 hours

## 📚 Resources

- [Statistics Verifier source](./src/qwed_new/core/stats_verifier.py)
- [Existing tests](./tests/test_stats_verifier.py)
```

---

## Issue 2: Improve Type Hints

**Title:** `[Docs] Add comprehensive type hints to core modules`

**Labels:** `good first issue`, `documentation`, `help wanted`

**Body:**
```
## 📋 Description

Several core modules lack comprehensive type hints, making it harder for IDEs to provide autocomplete.

## 🎯 What needs to be done

Add type hints to these files:
- [ ] `src/qwed_new/core/math_verifier.py`
- [ ] `src/qwed_new/core/logic_verifier.py`

## 📁 Example

Before:
```python
def verify(self, expression, claimed_result):
```

After:
```python
def verify(self, expression: str, claimed_result: str) -> VerificationResult:
```

## ⏱️ Estimated time

~30 minutes per file
```

---

## Issue 3: Add Spanish Documentation

**Title:** `[i18n] Translate Quick Start guide to Spanish`

**Labels:** `good first issue`, `documentation`, `translation`

**Body:**
```
## 📋 Description

Help make QWED accessible to Spanish-speaking developers!

## 🎯 What needs to be done

Translate the Quick Start section of README.md to Spanish and create:
- `docs/es/QUICK_START.md`

## ⏱️ Estimated time

~1 hour
```

---

## Issue 4: Rust SDK README Examples

**Title:** `[SDK] Add more examples to Rust SDK README`

**Labels:** `good first issue`, `rust`, `documentation`

**Body:**
```
## 📋 Description

The Rust SDK README needs more practical examples.

## 🎯 What needs to be done

Add examples for:
- [ ] verify_math with calculus
- [ ] verify_logic with business rules
- [ ] Error handling patterns

## 📁 Files to modify

- `sdk-rust/README.md`

## ⏱️ Estimated time

~1 hour
```

---

## How to Create Issues

1. Go to https://github.com/QWED-AI/qwed-verification/issues/new
2. Copy the **Title** 
3. Add the **Labels** (create them first if they don't exist)
4. Paste the **Body** content
5. Submit!

