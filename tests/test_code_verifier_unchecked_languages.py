"""Code CodeVerifier cannot show safe is not admitted (GHSA-7xrf).

- JavaScript, TypeScript, Java and Go were judged by listed substrings, and
  code with none of them was VERIFIED · ADMIT: `const {exec} =
  require('child_process'); exec('id');` and `Runtime.getRuntime().exec(...)`
  among it. Finding a listed substring still shows the code unsafe; finding
  none now gives UNVERIFIABLE.
- SQL sent to /verify/code had its own checks and admitted `DROP TABLE users`.
  It is now also decided by SQLVerifier, as /verify/sql decides it.

Nothing is executed.
"""

import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.sql_verifier import SQLVerifier
from tests.test_issue_307_admission_rows import client  # noqa: F401  (client is a fixture)


def _verdict(code, language):
    result = CodeVerifier().verify_code(code, language=language)
    return (
        result.status.value,
        result.developer_fields.get("is_valid"),
        admission_decision(result).value,
        result.developer_fields.get("constraint_id"),
    )


UNCHECKED = [
    ("javascript", "const {exec} = require('child_process'); exec('id');"),
    ("javascript", "const run = require('child_' + 'process').execSync; run('id');"),
    ("typescript", "import * as cp from 'child_process'; cp.spawnSync('id');"),
    ("ts", "let total: number = 1 + 2;"),
    ("js", "const total = 1 + 2;"),
    ("java", 'Runtime r = Runtime.getRuntime(); r.exec("id");'),
    ("java", "int total = 1 + 2;"),
    ("go", 'cmd := exec.Cmd{Path: "/bin/id"}; cmd.Run()'),
    ("go", "total := 1 + 2"),
    ("JavaScript", "const total = 1;"),
]


@pytest.mark.parametrize("language, code", UNCHECKED)
def test_code_in_a_language_without_a_sound_checker_is_unverifiable(language, code):
    assert _verdict(code, language) == (
        "UNVERIFIABLE", False, "BLOCKED", "code_verifier.language_unverifiable"
    )


@pytest.mark.parametrize("language, code", [
    ("javascript", "eval(userInput);"),
    ("java", 'Runtime.getRuntime().exec(cmd);'),
    ("go", 'exec.Command("sh", "-c", cmd)'),
])
def test_a_listed_pattern_still_shows_the_code_unsafe(language, code):
    assert _verdict(code, language) == ("VERIFIED", False, "BLOCKED", "code_verifier.code_unsafe")


def test_an_unsupported_language_is_still_blocked():
    assert _verdict("fn main() {}", "rust")[3] == "code_verifier.unsupported_language"


SQL_REFUSED = [
    "DROP TABLE users",
    "SELECT 1; DROP TABLE users",
    "DELETE FROM users",
    "UPDATE users SET name = 'a' WHERE id = 1",
    "TRUNCATE users",
    "GRANT ALL ON users TO bob",
    "COPY users TO '/tmp/x'",
    "SELECT pg_read_file('/etc/passwd')",
]


@pytest.mark.parametrize("query", SQL_REFUSED)
def test_sql_that_sql_verifier_refuses_is_not_admitted(query):
    assert admission_decision(SQLVerifier().verify_sql(query)).value == "BLOCKED"
    status, is_valid, admission, constraint = _verdict(query, "sql")
    assert (status, is_valid, admission, constraint) == ("VERIFIED", False, "BLOCKED", "code_verifier.code_unsafe")
    issues = CodeVerifier().verify_code(query, language="sql").developer_fields["issues"]
    assert any(issue["type"] == "sql_not_admitted" for issue in issues)


@pytest.mark.parametrize("query", ["SELEC broken", ""])
def test_sql_that_sql_verifier_cannot_verify_is_blocked(query):
    assert _verdict(query, "sql") == ("BLOCKED", False, "BLOCKED", "code_verifier.sql_unverified")
    fields = CodeVerifier().verify_code(query, language="sql").developer_fields
    assert fields["sql_constraint_id"] == SQLVerifier().verify_sql(query).developer_fields["constraint_id"]


@pytest.mark.parametrize("query", ["SELECT id, name FROM users WHERE id = 5", "SELECT 1"])
def test_sql_that_both_checks_admit_is_admitted(query):
    assert _verdict(query, "sql") == ("VERIFIED", True, "ADMIT", "code_verifier.code_safe")


def test_code_verifiers_own_sql_findings_still_apply():
    # SQLVerifier admits a UNION read; CodeVerifier's own check refuses it.
    assert _verdict("SELECT id FROM a UNION SELECT id FROM b", "sql")[2] == "BLOCKED"


def test_the_route_returns_unverifiable_for_javascript(client):  # noqa: F811
    response = client.post(
        "/verify/code", json={"code": "const {exec} = require('child_process'); exec('id');", "language": "javascript"}
    )
    body = response.json()
    assert body["status"] == "UNVERIFIABLE"
    assert body["admission"] == "BLOCKED"


def test_the_route_blocks_python_that_reads_a_name_it_never_binds(client):  # noqa: F811
    response = client.post(
        "/verify/code", json={"code": "secret = os.environ.get('AWS_SECRET_ACCESS_KEY')", "language": "python"}
    )
    assert response.json()["admission"] == "BLOCKED"
