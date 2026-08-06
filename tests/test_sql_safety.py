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
    assert result.developer_fields.get("warning_count", 0) > 0
    assert result.developer_fields.get("is_valid") is True


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


def test_sql_verifier_proof_is_bound_to_the_verdict():
    """Opposite verdicts on one AST must not share a proof_ref."""
    strict = SQLVerifier(allow_destructive=False)
    permissive = SQLVerifier(allow_destructive=True)

    blocked_verdict = strict.verify_sql("DROP TABLE users")
    allowed_verdict = permissive.verify_sql("DROP TABLE users")

    assert blocked_verdict.developer_fields.get("is_valid") is False
    assert allowed_verdict.developer_fields.get("is_valid") is True
    assert blocked_verdict.proof_ref != allowed_verdict.proof_ref


def test_sql_verifier_batch_separates_blocked_from_malicious():
    """Batch summary separates parse-blocked items from proven-malicious items."""
    verifier = SQLVerifier()

    result = verifier.verify_batch(
        [
            "SELECT id FROM users WHERE id = 1",
            "DROP TABLE users; DROP TABLE orders;",
            "SELEC FROM users WHERE",  # unparseable -> BLOCKED
        ]
    )
    assert result.status is DiagnosticStatus.BLOCKED
    summary = result.developer_fields["summary"]
    assert summary["total"] == 3
    assert summary["safe"] == 1
    assert summary["malicious"] == 1
    assert summary["unsafe"] == 1
    assert summary["blocked"] == 1


def test_sql_verifier_batch_all_safe_is_verified():
    verifier = SQLVerifier()

    result = verifier.verify_batch(
        ["SELECT id FROM users WHERE id = 1", "SELECT name FROM users WHERE id = 2"]
    )
    assert result.status is DiagnosticStatus.VERIFIED
    assert result.proof_ref is not None
    assert result.developer_fields.get("is_valid") is True
    summary = result.developer_fields["summary"]
    assert summary["total"] == 2
    assert summary["safe"] == 2
    assert summary["unsafe"] == 0
    assert summary["malicious"] == 0
    assert summary["blocked"] == 0
    assert "blocked" in summary  # documented summary field is present


def test_sql_verifier_batch_with_malicious_is_blocked():
    """A batch containing a malicious query is non-authoritative (BLOCKED)."""
    verifier = SQLVerifier()

    result = verifier.verify_batch(
        ["SELECT id FROM users WHERE id = 1", "DROP TABLE users; DROP TABLE orders;"]
    )
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("malicious_classification") is True
    assert result.developer_fields.get("constraint_id") == "sql_verifier.malicious"
    summary = result.developer_fields["summary"]
    assert summary["total"] == 2
    assert summary["safe"] == 1
    assert summary["unsafe"] == 1
    assert summary["malicious"] == 1
    assert summary["blocked"] == 0
    assert len(result.developer_fields["results"]) == 2


def test_sql_verifier_batch_with_parse_error_is_not_malicious():
    """A parse-error batch must never be classified as malicious (Greptile P1)."""
    verifier = SQLVerifier()

    result = verifier.verify_batch(["SELECT id FROM users WHERE id = 1", "SELEC FROM users WHERE"])
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.developer_fields.get("malicious_classification") is False
    assert result.developer_fields.get("constraint_id") == "sql_verifier.batch_blocked"
    summary = result.developer_fields["summary"]
    assert summary["total"] == 2
    assert summary["safe"] == 1
    assert summary["unsafe"] == 0
    assert summary["malicious"] == 0
    assert summary["blocked"] == 1


def test_sql_verifier_batch_with_execution_error_is_not_malicious(monkeypatch):
    """A batch with an internal analysis failure is blocked, not malicious (Greptile P1)."""
    verifier = SQLVerifier()

    def _boom(self, parsed_query):
        raise RuntimeError("internal analysis failure")

    monkeypatch.setattr(SQLVerifier, "_check_column_access", _boom)
    result = verifier.verify_batch(["SELECT id FROM users WHERE id = 1", "SELECT name FROM users"])
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields.get("malicious_classification") is False
    summary = result.developer_fields["summary"]
    assert summary["safe"] == 0
    assert summary["malicious"] == 0
    assert summary["blocked"] == 2


def test_sql_verifier_execution_error_is_blocked(monkeypatch):
    verifier = SQLVerifier()

    def _boom(self, parsed_query):
        raise RuntimeError("internal analysis failure")

    monkeypatch.setattr(SQLVerifier, "_check_column_access", _boom)
    result = verifier.verify_sql("SELECT id FROM users WHERE id = 1")
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.constraint_id == "sql_verifier.execution_error"
    assert "internal" in result.agent_message.lower()


def test_sql_verifier_complexity_violation_is_not_malicious():
    """A resource-limit (complexity) violation is CRITICAL but NOT malicious (CodeRabbit)."""
    verifier = SQLVerifier(complexity_limits={"max_tables": 1})

    result = verifier.verify_sql(
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.uid JOIN items i ON i.id = o.item_id"
    )
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("critical_count") == 1
    assert result.developer_fields.get("malicious_classification") is False
    assert result.developer_fields.get("constraint_id") == "sql_verifier.complexity_limit_exceeded"


def test_sql_verifier_schema_parse_failure_is_blocked():
    """Unparseable DDL blocks with a dedicated constraint, never a VERIFIED result."""
    verifier = SQLVerifier()

    result = verifier.verify_sql(
        "SELECT name FROM users", schema_ddl="CREATE TABLE users (id INT, name TEXT"
    )
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("constraint_id") == "sql_verifier.schema_parse_error"
    assert result.developer_fields.get("malicious_classification") is False


def test_sql_verifier_malicious_with_schema_parse_failure_is_blocked():
    """Malice does not override an incomplete analysis: malicious + schema parse
    failure is BLOCKED (schema_parse_error), never VERIFIED (Sentry HIGH)."""
    verifier = SQLVerifier()

    result = verifier.verify_sql(
        "SELECT * FROM users; DROP TABLE users;",
        schema_ddl="CREATE TABLE users (id INT, name TEXT",
    )
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("constraint_id") == "sql_verifier.schema_parse_error"
    # The malicious finding is preserved as truth even though admission is blocked.
    assert result.developer_fields.get("malicious_classification") is True


def test_sql_verifier_empty_batch_is_not_authoritative():
    """An empty batch must never produce an authoritative VERIFIED result."""
    verifier = SQLVerifier()

    result = verifier.verify_batch([])
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("malicious_classification") is False
    assert result.developer_fields.get("constraint_id") == "sql_verifier.empty_batch"
    assert result.developer_fields["results"] == []
    summary = result.developer_fields["summary"]
    assert summary["total"] == 0
    assert summary["safe"] == 0
    assert summary["unsafe"] == 0
    assert summary["malicious"] == 0
    assert summary["blocked"] == 0
    assert summary["total_critical"] == 0
    assert summary["total_warnings"] == 0


def test_sql_verifier_malicious_classification_requires_malice_proof():
    """Injection/stacking prove malice; complexity alone never does."""
    verifier = SQLVerifier(complexity_limits={"max_tables": 1})

    injection = verifier.verify_sql("SELECT * FROM users WHERE id = 1 OR 1=1")
    assert injection.developer_fields.get("malicious_classification") is True
    assert injection.developer_fields.get("constraint_id") == "sql_verifier.malicious"

    stacked = verifier.verify_sql("SELECT * FROM users; DROP TABLE users;")
    assert stacked.developer_fields.get("malicious_classification") is True
    assert stacked.developer_fields.get("constraint_id") == "sql_verifier.malicious"


def test_sql_verifier_batch_counts_complexity_as_blocked_not_malicious():
    """Batch summary: complexity-only items land in 'blocked', not 'malicious'."""
    verifier = SQLVerifier(complexity_limits={"max_tables": 1})

    result = verifier.verify_batch(
        [
            "SELECT id FROM users WHERE id = 1",
            "SELECT u.id FROM users u JOIN orders o ON u.id = o.uid JOIN items i ON i.id = o.item_id",
        ]
    )
    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields.get("malicious_classification") is False
    assert result.developer_fields.get("constraint_id") == "sql_verifier.batch_blocked"
    summary = result.developer_fields["summary"]
    assert summary["total"] == 2
    assert summary["safe"] == 1
    assert summary["malicious"] == 0
    assert summary["blocked"] == 1


def test_sql_verifier_batch_evidence_binds_policy_and_schema():
    """Batch proof_ref changes when limits, blocked columns, or schema change."""
    queries = ["SELECT id FROM users WHERE id = 1"]

    base = SQLVerifier().verify_batch(queries)
    relimited = SQLVerifier(complexity_limits={"max_tables": 5}).verify_batch(queries)
    reblocked = SQLVerifier(blocked_columns={"custom_secret_col"}).verify_batch(queries)
    with_schema = SQLVerifier().verify_batch(
        queries, schema_ddl="CREATE TABLE users (id INT, name TEXT);"
    )

    assert base.proof_ref is not None
    assert base.proof_ref == SQLVerifier().verify_batch(queries).proof_ref
    assert base.proof_ref != relimited.proof_ref
    assert base.proof_ref != reblocked.proof_ref
    assert base.proof_ref != with_schema.proof_ref
