import sys
import os

# Ensure src is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from qwed_new.core.sql_verifier import SQLVerifier
from qwed_new.core.diagnostics import DiagnosticStatus


def _issues(result):
    return result.developer_fields.get("issues", [])


def test_sql_verifier_destructive_commands():
    verifier = SQLVerifier()

    # DROP is proven malicious -> VERIFIED-as-malicious (not BLOCKED), is_valid False
    result = verifier.verify_sql("DROP TABLE users")
    assert result.status is DiagnosticStatus.VERIFIED
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("malicious_classification") is True
    assert result.proof_ref is not None
    assert any("Destructive" in str(issue.get("description", issue)) or
               "destructive" in str(issue.get("type", issue))
               for issue in _issues(result))

    # TRUNCATE should be blocked
    result = verifier.verify_sql("TRUNCATE TABLE logs")
    assert result.developer_fields.get("is_valid") is False
    assert any("Destructive" in str(issue.get("description", issue)) or
               "destructive" in str(issue.get("type", issue)) or
               "admin" in str(issue.get("type", issue))
               for issue in _issues(result))

    # SET ROLE should remain identified as an administrative command
    result = verifier.verify_sql("SET ROLE app_reader")
    assert result.developer_fields.get("is_valid") is False
    assert any(
        "Administrative" in str(issue.get("description", issue))
        or "admin" in str(issue.get("type", issue)).lower()
        for issue in _issues(result)
    )


def test_sql_verifier_sensitive_columns():
    verifier = SQLVerifier()

    # Accessing password_hash should be flagged
    result = verifier.verify_sql("SELECT email, password_hash FROM users")
    assert result.developer_fields.get("is_valid") is False
    # Check for sensitive column issue
    assert any("password_hash" in str(issue.get("description", issue)) or
               "sensitive" in str(issue.get("type", issue)).lower()
               for issue in _issues(result))

    # Accessing salary should be flagged
    result = verifier.verify_sql("SELECT name FROM employees WHERE salary > 1000")
    assert result.developer_fields.get("is_valid") is False
    assert any("salary" in str(issue.get("description", issue)) or
               "sensitive" in str(issue.get("type", issue)).lower()
               for issue in _issues(result))


def test_sql_verifier_injection_patterns():
    verifier = SQLVerifier()

    # Tautology injection (OR 1=1)
    result = verifier.verify_sql("SELECT * FROM users WHERE id = 1 OR 1=1")
    assert result.developer_fields.get("is_valid") is False
    # Check for tautology or injection issue
    assert any("tautology" in str(issue.get("description", issue)).lower() or
               "tautology" in str(issue.get("type", issue)).lower() or
               "injection" in str(issue.get("type", issue)).lower()
               for issue in _issues(result))

    # Another tautology (a=a)
    result = verifier.verify_sql("SELECT * FROM users WHERE 'a' = 'a'")
    assert result.developer_fields.get("is_valid") is False
    assert any("tautology" in str(issue.get("description", issue)).lower() or
               "tautology" in str(issue.get("type", issue)).lower()
               for issue in _issues(result))


def test_sql_verifier_safe_query():
    verifier = SQLVerifier()

    # Normal SELECT should pass
    result = verifier.verify_sql("SELECT id, name, email FROM users WHERE id = 123")
    assert result.status is DiagnosticStatus.VERIFIED
    assert result.developer_fields.get("is_valid") is True
    assert result.proof_ref is not None


def test_sql_verifier_schema_validation():
    verifier = SQLVerifier()
    schema = "CREATE TABLE users (id INT, name TEXT, email TEXT);"

    # Table exists in schema
    result = verifier.verify_sql("SELECT name FROM users", schema_ddl=schema)
    assert result.developer_fields.get("is_valid") is True

    # Table does NOT exist in schema - this generates WARNING not CRITICAL
    result = verifier.verify_sql("SELECT name FROM passwords", schema_ddl=schema)
    assert result.developer_fields.get("warning_count", 0) > 0 or result.developer_fields.get("is_valid") is False


def test_sql_verifier_parse_error_is_blocked():
    verifier = SQLVerifier()

    result = verifier.verify_sql("SELEC FROM users WHERE")  # unparseable
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.constraint_id == "sql_verifier.parse_error"
    assert result.developer_fields.get("is_valid") is False
    # agent_message must be sanitized (no raw SQLGlot output leaked)
    assert "sql" in result.agent_message.lower()


def test_sql_verifier_agent_message_is_sanitized():
    """agent_message must never leak detection rules, rule IDs, or the raw query."""
    verifier = SQLVerifier()

    result = verifier.verify_sql("SELECT password_hash FROM users; DROP TABLE users;")
    # Rule-level detail lives in developer_fields, not agent_message.
    for secret in ("password_hash", "destructive_command", "injection", "DROP"):
        assert secret.lower() not in result.agent_message.lower()
    assert "verify" in result.agent_message.lower() or "safe" in result.agent_message.lower()


def test_sql_verifier_malicious_proof_is_deterministic():
    """Same malicious input yields the same proof_ref (verdict is bound to the AST)."""
    verifier = SQLVerifier()
    a = verifier.verify_sql("SELECT * FROM users; DROP TABLE users;")
    b = verifier.verify_sql("SELECT * FROM users; DROP TABLE users;")
    assert a.status is DiagnosticStatus.VERIFIED
    assert a.developer_fields.get("is_valid") is False
    assert a.proof_ref == b.proof_ref
    assert a.proof_ref.startswith("sha256:")


def test_sql_verifier_batch_returns_diagnostic_result():
    verifier = SQLVerifier()

    result = verifier.verify_batch(
        ["SELECT id FROM users WHERE id = 1", "DROP TABLE users; DROP TABLE orders;"]
    )
    assert result.status is DiagnosticStatus.VERIFIED
    assert result.proof_ref is not None
    assert result.developer_fields.get("is_valid") is False
    summary = result.developer_fields["summary"]
    assert summary["total"] == 2
    assert summary["safe"] == 1
    assert summary["unsafe"] == 1
    assert len(result.developer_fields["results"]) == 2