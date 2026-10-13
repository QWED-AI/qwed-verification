"""Project-scoped OpenAI keys are detected (GHSA-64xf-wffc-63fm).

ConfigGuard and the code verifier matched OpenAI keys with sk-[A-Za-z0-9]...,
which cannot match the "-" in sk-proj-, sk-svcacct- or sk-admin- keys, so
such a key was reported as no secret at all.

Every key here is synthetic and assembled at run time, so no file holds a
string that looks like a real key.
"""

import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision
from qwed_sdk.guards.config_guard import ConfigGuard

BODY = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z" + "_Qa-Zb7Yc"
KEYS = {
    "project": "sk-" + "proj-" + BODY,
    "service account": "sk-" + "svcacct-" + BODY,
    "admin": "sk-" + "admin-" + BODY,
    "legacy": "sk-" + "A1b2C3d4E5f6G7h8I9j0" * 2 + "K1l2M3n4",  # 48 alphanumerics
}


@pytest.mark.parametrize("kind", sorted(KEYS))
def test_config_guard_detects_openai_keys(kind):
    result = ConfigGuard().verify_config_safety({"OPENAI_API_KEY": KEYS[kind]})
    assert result["verified"] is False, result
    assert any(v["type"] == "OPENAI_API_KEY" for v in result["violations"]), result


@pytest.mark.parametrize("kind", sorted(KEYS))
def test_code_verifier_detects_openai_keys(kind):
    result = CodeVerifier().verify_code(f'client = OpenAI(api_key="{KEYS[kind]}")\n')
    fields = result.developer_fields
    assert fields["is_valid"] is False
    assert admission_decision(result).value == "BLOCKED"
    assert any(i["type"] == "hardcoded_secret" and i["description"] == "OpenAI API Key" for i in fields["issues"]), fields["issues"]


def test_anthropic_keys_are_not_reported_as_openai():
    key = "sk-" + "ant-" + "api03-" + BODY
    result = ConfigGuard().verify_config_safety({"ANTHROPIC_API_KEY": key})
    types = {v["type"] for v in result["violations"]}
    assert "ANTHROPIC_API_KEY" in types
    assert "OPENAI_API_KEY" not in types


@pytest.mark.parametrize("value", ["task-1", "sk-short", "sk-proj-tooShort", "risk-assessment-template"])
def test_ordinary_strings_are_not_openai_keys(value):
    result = ConfigGuard().verify_config_safety({"setting": value})
    assert not any(v["type"] == "OPENAI_API_KEY" for v in result.get("violations", [])), result
