"""
Pytest Configuration and Fixtures for QWED Testing
Provides common fixtures for all test suites
"""

import pytest
import yaml
from pathlib import Path
from typing import Dict, Any
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from api_client import QWEDAPIClient


@pytest.fixture(scope="session")
def config() -> Dict[str, Any]:
    """Load test configuration (session-scoped)"""
    config_file = Path(__file__).parent / "config.yaml"
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def qwed_client(config) -> QWEDAPIClient:
    """
    Provide configured QWED API client (session-scoped)
    Reused across all tests for efficiency
    """
    api_config = config['api']
    return QWEDAPIClient(
        base_url=api_config['url'],
        api_key=api_config['key'],
        timeout=api_config.get('timeout', 30),
        max_retries=api_config.get('max_retries', 3)
    )


@pytest.fixture(scope="function")
def test_output_dir(tmp_path) -> Path:
    """
    Provide temporary directory for test outputs (function-scoped)
    Automatically cleaned up after each test
    """
    return tmp_path / "test_output"


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment(config):
    """
    Setup test environment before any tests run
    Runs once per session automatically
    """
    # Create output directories
    output_dir = Path(config['reporting']['output_dir'])
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n🔧 Test environment setup complete")
    print(f"   Output dir: {output_dir}")
    
    yield
    
    # Cleanup after all tests (if needed)
    print(f"\n🧹 Test environment cleanup complete")


@pytest.fixture
def sample_vulnerable_code() -> Dict[str, str]:
    """
    Provide sample vulnerable code snippets for testing
    """
    return {
        "eval_rce": '''
user_input = input("Code: ")
eval(user_input)  # RCE
''',
        "pickle_rce": '''
import pickle
data = input("Data: ")
obj = pickle.loads(data)  # Deserialization RCE
''',
        "sql_injection": '''
username = input("User: ")
query = f"SELECT * FROM users WHERE name='{username}'"  # SQL injection
''',
        "command_injection": '''
import subprocess
filename = input("File: ")
subprocess.run(["ls", filename])  # Command injection if user controls filename
''',
        "hardcoded_secret": '''
api_key = "sk-1234567890abcdef"  # Hardcoded secret
''',
        "insecure_ssl": '''
import requests
requests.get("https://api.example.com", verify=False)  # Insecure SSL
'''
    }


@pytest.fixture
def sample_safe_code() -> Dict[str, str]:
    """
    Provide sample safe code snippets for testing
    """
    return {
        "safe_function": '''
def add(a: int, b: int) -> int:
    return a + b
''',
        "safe_import": '''
import json
data = json.loads('{"key": "value"}')
''',
        "safe_file_read": '''
with open("config.json", "r") as f:  # Hardcoded path is safe
    config = json.load(f)
'''
    }


@pytest.fixture
def performance_threshold(config) -> Dict[str, float]:
    """
    Provide performance thresholds for timing assertions
    """
    return {
        "max_latency_ms": config['performance']['timeout_threshold_seconds'] * 1000,
        "avg_latency_ms": 5000,  # 5 seconds average
        "max_concurrent": config['performance']['max_concurrent_requests']
    }


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "critical: mark test as critical priority"
    )
    config.addinivalue_line(
        "markers", "high: mark test as high priority"
    )
    config.addinivalue_line(
        "markers", "medium: mark test as medium priority"
    )
    config.addinivalue_line(
        "markers", "code_engine: mark test for code verification engine"
    )
    config.addinivalue_line(
        "markers", "math_engine: mark test for math verification engine"
    )
    config.addinivalue_line(
        "markers", "logic_engine: mark test for logic verification engine"
    )
    config.addinivalue_line(
        "markers", "stats_engine: mark test for stats verification engine"
    )
    config.addinivalue_line(
        "markers", "sql_engine: mark test for SQL verification engine"
    )
    config.addinivalue_line(
        "markers", "fact_engine: mark test for fact verification engine"
    )
    config.addinivalue_line(
        "markers", "image_engine: mark test for image verification engine"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "stress: mark test as stress/performance test"
    )


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to apply markers automatically
    based on test module/class names
    """
    for item in items:
        # Auto-apply engine markers based on test file name
        if "code_engine" in str(item.fspath):
            item.add_marker(pytest.mark.code_engine)
        elif "math_engine" in str(item.fspath):
            item.add_marker(pytest.mark.math_engine)
        elif "logic_engine" in str(item.fspath):
            item.add_marker(pytest.mark.logic_engine)
        elif "stats_engine" in str(item.fspath):
            item.add_marker(pytest.mark.stats_engine)
        elif "sql_engine" in str(item.fspath):
            item.add_marker(pytest.mark.sql_engine)
        elif "fact_engine" in str(item.fspath):
            item.add_marker(pytest.mark.fact_engine)
        elif "image_engine" in str(item.fspath):
            item.add_marker(pytest.mark.image_engine)
        
        # Auto-apply priority markers based on test class/function name
        if "critical" in item.nodeid.lower():
            item.add_marker(pytest.mark.critical)
        elif "high" in item.nodeid.lower():
            item.add_marker(pytest.mark.high)
