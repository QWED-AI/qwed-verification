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
    assert result["status"] == "BLOCKED"
    # Check that there's an issue about destructive command
    assert any("Destructive" in str(issue.get("description", issue)) or 
               "destructive" in str(issue.get("type", issue))
               for issue in result["issues"])
    
    # TRUNCATE should be blocked
    result = verifier.verify_sql("TRUNCATE TABLE logs")
    assert result["is_safe"] is False
    assert any("Destructive" in str(issue.get("description", issue)) or 
               "destructive" in str(issue.get("type", issue))
               for issue in result["issues"])

def test_sql_verifier_sensitive_columns():
    verifier = SQLVerifier()
    
    # Accessing password_hash should be blocked
    result = verifier.verify_sql("SELECT email, password_hash FROM users")
    assert result["is_safe"] is False
    # Check for sensitive column issue
    assert any("password_hash" in str(issue.get("description", issue)) or
               "sensitive" in str(issue.get("type", issue)).lower()
               for issue in result["issues"])
    
    # Accessing salary should be blocked
    result = verifier.verify_sql("SELECT name FROM employees WHERE salary > 1000")
    assert result["is_safe"] is False
    assert any("salary" in str(issue.get("description", issue)) or
               "sensitive" in str(issue.get("type", issue)).lower()
               for issue in result["issues"])

def test_sql_verifier_injection_patterns():
    verifier = SQLVerifier()
    
    # Tautology injection (OR 1=1)
    result = verifier.verify_sql("SELECT * FROM users WHERE id = 1 OR 1=1")
    assert result["is_safe"] is False
    # Check for tautology or injection issue
    assert any("tautology" in str(issue.get("description", issue)).lower() or
               "tautology" in str(issue.get("type", issue)).lower() or
               "injection" in str(issue.get("type", issue)).lower()
               for issue in result["issues"])
    
    # Another tautology (a=a)
    result = verifier.verify_sql("SELECT * FROM users WHERE 'a' = 'a'")
    assert result["is_safe"] is False
    assert any("tautology" in str(issue.get("description", issue)).lower() or
               "tautology" in str(issue.get("type", issue)).lower()
               for issue in result["issues"])

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
    
    # Table does NOT exist in schema - this generates WARNING not CRITICAL
    result = verifier.verify_sql("SELECT name FROM passwords", schema_ddl=schema)
    # Schema validation issues are warnings, not critical
    assert result["warning_count"] > 0 or result["is_safe"] is False
