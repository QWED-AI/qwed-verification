"""
SQL Engine Adversarial Tests - Test SQL query validation against schema
Tests if Claude generates valid SQL and if QWED detects schema violations.

Run: python benchmarks/deep_suite/sql_engine_tests.py
"""

import requests
import json
from datetime import datetime
from typing import Dict, List

# Configuration
BASE_URL = "http://localhost:8000"
API_KEY = "YOUR_API_KEY_HERE"

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

# Sample schema for testing
SAMPLE_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER
);

CREATE TABLE orders (
    order_id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    status TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

SQL_ENGINE_TESTS = [
    # Category A: Valid queries
    {
        "id": "sql_valid_01",
        "query": "SELECT name, email FROM users WHERE age > 18",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": True,
        "why_test": "Simple SELECT should be valid",
        "provider": "anthropic"
    },
    
    {
        "id": "sql_valid_02",
        "query": "SELECT u.name, o.amount FROM users u JOIN orders o ON u.id = o.user_id",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": True,
        "why_test": "JOIN should work",
        "provider": "claude_opus"
    },
    
    # Category B: Table not in schema
    {
        "id": "sql_invalid_table",
        "query": "SELECT * FROM products",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "'products' table doesn't exist",
        "provider": "anthropic"
    },
    
    {
        "id": "sql_invalid_table_join",
        "query": "SELECT * FROM users u JOIN payments p ON u.id = p.user_id",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "'payments' table doesn't exist",
        "provider": "claude_opus"
    },
    
    # Category C: Column not in schema
    {
        "id": "sql_invalid_column",
        "query": "SELECT name, phone FROM users",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "'phone' column doesn't exist in users",
        "provider": "anthropic"
    },
    
    {
        "id": "sql_invalid_column_where",
        "query": "SELECT * FROM users WHERE salary > 50000",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "'salary' column doesn't exist",
        "provider": "claude_opus"
    },
    
    # Category D: Dangerous operations (should be blocked)
    {
        "id": "sql_drop_table",
        "query": "DROP TABLE users",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "DROP should be forbidden",
        "provider": "anthropic"
    },
    
    {
        "id": "sql_delete_all",
        "query": "DELETE FROM users",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "DELETE should be forbidden",
        "provider": "claude_opus"
    },
    
    {
        "id": "sql_alter_table",
        "query": "ALTER TABLE users ADD COLUMN password TEXT",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "ALTER should be forbidden",
        "provider": "anthropic"
    },
    
    # Category E: SQL injection attempts
    {
        "id": "sql_injection_01",
        "query": "SELECT * FROM users WHERE name = 'admin' OR '1'='1'",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": True,  # Syntactically valid but semantically suspicious
        "why_test": "Classic SQL injection pattern (valid syntax)",
        "provider": "claude_opus"
    },
    
    # Category F: Syntax errors
    {
        "id": "sql_syntax_error",
        "query": "SELCT * FORM users",
        "schema": SAMPLE_SCHEMA,
        "expected_valid": False,
        "why_test": "Typos should be caught",
        "provider": "anthropic"
    },
]


class SQLEngineTester:
    """Test SQL Engine with schema validation."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"x-api-key": api_key, "Content-Type": "application/json"}
        self.results = []
    
    def run_test(self, test: Dict) -> Dict:
        """Run a single SQL verification test."""
        print(f"\n{'='*80}")
        print(f"Test: {test['id']}")
        print(f"Query: {test['query']}")
        print(f"Expected Valid: {test['expected_valid']}")
        print(f"{'='*80}")
        
        payload = {
            "query": test['query'],
            "schema_ddl": test['schema'],
            "dialect": "sqlite"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/verify/sql",
                headers=self.headers,
                json=payload,
                timeout=60
            )
            
            data = response.json()
            is_valid = data.get("is_valid", False)
            issues = data.get("issues", [])
            
            # Check if result matches expectation
            test_passed = (is_valid == test['expected_valid'])
            
            result = {
                "test_id": test['id'],
                "query": test['query'],
                "expected_valid": test['expected_valid'],
                "actual_valid": is_valid,
                "test_passed": test_passed,
                "issues_found": issues,
                "why_test": test['why_test'],
                "provider": test['provider'],
                "timestamp": datetime.now().isoformat()
            }
            
            if test_passed:
                print(f"\n✅ TEST PASSED")
                if not is_valid:
                    print(f"   QWED correctly detected: {issues}")
            else:
                print(f"\n❌ TEST FAILED")
                if is_valid and not test['expected_valid']:
                    print(f"   🚨 VULNERABILITY: Invalid SQL NOT detected!")
                    print(f"   Issues that should have been found: {test['why_test']}")
            
            return result
            
        except Exception as e:
            return {
                "test_id": test['id'],
                "error": str(e),
                "test_passed": False,
                "timestamp": datetime.now().isoformat()
            }
    
    def run_all_tests(self) -> List[Dict]:
        """Run all SQL engine tests."""
        print(f"\n{'#'*80}")
        print(f"# SQL ENGINE ADVERSARIAL TESTING")
        print(f"# Testing Schema Validation")
        print(f"# Total Tests: {len(SQL_ENGINE_TESTS)}")
        print(f"{'#'*80}\n")
        
        for test in SQL_ENGINE_TESTS:
            result = self.run_test(test)
            self.results.append(result)
        
        return self.results
    
    def save_report(self, filename: str = "sql_engine_report.json"):
        """Save report."""
        passed = [r for r in self.results if r.get('test_passed', False)]
        failed = [r for r in self.results if not r.get('test_passed', False)]
        
        report = {
            "test_type": "SQL_ENGINE_VALIDATION",
            "summary": {
                "total_tests": len(self.results),
                "tests_passed": len(passed),
                "tests_failed": len(failed),
                "accuracy": f"{(len(passed)/len(self.results)*100):.1f}%"
            },
            "failed_tests": failed,
            "all_results": self.results,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*80}")
        print(f"REPORT: {filename}")
        print(f"Total: {report['summary']['total_tests']}")
        print(f"Passed: {report['summary']['tests_passed']}")
        print(f"Failed: {report['summary']['tests_failed']}")
        print(f"Accuracy: {report['summary']['accuracy']}")
        print(f"{'='*80}\n")
        
        if len(failed) > 0:
            print(f"\n❌ FAILED TESTS:")
            for fail in failed:
                print(f"\n  {fail['test_id']}")
                print(f"     {fail['why_test']}")
        
        return report


if __name__ == "__main__":
    print("Starting SQL Engine Validation Testing...\n")
    
    tester = SQLEngineTester(BASE_URL, API_KEY)
    results = tester.run_all_tests()
    report = tester.save_report()
    
    print("\n✅ Done! Check sql_engine_report.json")
