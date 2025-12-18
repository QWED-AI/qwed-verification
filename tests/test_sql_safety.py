import pytest
import sys
import os

# Ensure src is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from qwed_new.core.sql_verifier import SQLVerifier

def test_sql_verifier_destructive_commands():
    verifier = SQLVerifier()
    
    # DROP should be blocked
    result = verifier.verify_sql("DROP TABLE users")
    assert result["is_safe"] is False
    assert "Destructive command detected" in result["issues"][0]
    
    # TRUNCATE should be blocked
    result = verifier.verify_sql("TRUNCATE TABLE logs")
    assert result["is_safe"] is False
    assert "Destructive command detected" in result["issues"][0]

def test_sql_verifier_sensitive_columns():
    verifier = SQLVerifier()
    
    # Accessing password_hash should be blocked
    result = verifier.verify_sql("SELECT email, password_hash FROM users")
    assert result["is_safe"] is False
    assert "sensitive column 'password_hash'" in result["issues"][0]
    
    # Accessing salary should be blocked
    result = verifier.verify_sql("SELECT name FROM employees WHERE salary > 1000")
    assert result["is_safe"] is False
    assert "sensitive column 'salary'" in result["issues"][0]

def test_sql_verifier_injection_patterns():
    verifier = SQLVerifier()
    
    # Tautology injection (OR 1=1)
    result = verifier.verify_sql("SELECT * FROM users WHERE id = 1 OR 1=1")
    assert result["is_safe"] is False
    assert "Tautology detected" in result["issues"][0]
    
    # Another tautology (a=a)
    result = verifier.verify_sql("SELECT * FROM users WHERE 'a' = 'a'")
    assert result["is_safe"] is False
    assert "Tautology detected" in result["issues"][0]

def test_sql_verifier_safe_query():
    verifier = SQLVerifier()
    
    # Normal SELECT should pass
    result = verifier.verify_sql("SELECT id, name, email FROM users WHERE id = 123")
    assert result["is_safe"] is True
    assert result["status"] == "SAFE"

def test_sql_verifier_schema_validation():
    verifier = SQLVerifier()
    schema = "CREATE TABLE users (id INT, name TEXT, email TEXT);"
    
    # Table exists in schema
    result = verifier.verify_sql("SELECT name FROM users", schema_ddl=schema)
    assert result["is_safe"] is True
    
    # Table does NOT exist in schema
    result = verifier.verify_sql("SELECT name FROM passwords", schema_ddl=schema)
    assert result["is_safe"] is False
    assert "Table 'passwords' does not exist" in result["issues"][0]
