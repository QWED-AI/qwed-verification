# QWED Advanced Testing Framework

## Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure API credentials:**
Edit `config.yaml` and set your QWED API URL and key.

## Running Tests

### Run all tests:
```bash
python run_complete_audit.py --all
```

### Run by priority:
```bash
python run_complete_audit.py --priority CRITICAL
```

### Run specific engine:
```bash
python run_complete_audit.py --engine code
```

### Generate multiple report formats:
```bash
python run_complete_audit.py --all --report json markdown html
```

### Using pytest directly:
```bash
# Run all tests
pytest test_suites/

# Run specific engine tests
pytest test_suites/code_engine_*.py

# Run only CRITICAL tests
pytest -m critical

# Run with verbose output
pytest test_suites/ -v

# Run in parallel
pytest test_suites/ -n auto
```

## Project Structure

```
advanced_audit/
├── run_complete_audit.py    # Main test runner
├── config.yaml               # Configuration
├── conftest.py              # Pytest fixtures
├── api_client.py            # QWED API client
├── base_test.py             # Base test class
├── test_utils.py            # Utilities
├── test_suites/             # Test implementations
│   ├── code_engine_basic.py
│   └── ... (more to be added)
├── reporters/               # Report generators
│   ├── json_reporter.py
│   ├── markdown_reporter.py
│   └── html_reporter.py
└── test_results/            # Generated reports
```

## Writing New Tests

### Example test file:

```python
# test_suites/my_new_test.py
from base_test import BaseTest, TestResult

class MyTest(BaseTest):
    def __init__(self):
        super().__init__(
            test_id="CODE_003",
            test_name="My test description",
            engine="code",
            priority="CRITICAL"
        )
    
    def execute(self, api_client) -> TestResult:
        code = "# Your test code here"
        response = api_client.verify_code(code)
        
        passed = self._check_result("CRITICAL", response.data)
        
        return TestResult(
            test_id=self.test_id,
            test_name=self.test_name,
            engine=self.engine,
            priority=self.priority,
            passed=passed,
            expected_result="CRITICAL",
            actual_result=response.data,
            latency_ms=response.latency_ms
        )

# Export tests
AVAILABLE_TESTS = [MyTest()]
```

## Cleanup

Remove old test reports:
```python
from test_utils import TestDataManager

manager = TestDataManager()
manager.cleanup_old_reports(days_old=7)  # Remove reports older than 7 days
```

## Next Steps (Days 4-20)

- **Days 4-6:** Test validated engines (Code, Math, Logic)
- **Days 7-11:** Test new engines (Stats, SQL, Fact, Image)
- **Days 12-14:** Integration and stress tests
- **Days 15-20:** Fix issues and harden
