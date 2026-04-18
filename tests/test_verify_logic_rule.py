import pytest

from qwed_new.core.verifier import (
    VERIFY_LOGIC_RULE_DEPRECATED_ERROR,
    VerificationEngine,
)


def test_verify_logic_rule_fails_closed_with_explicit_error():
    engine = VerificationEngine()

    with pytest.raises(NotImplementedError, match=VERIFY_LOGIC_RULE_DEPRECATED_ERROR):
        engine.verify_logic_rule(
            rule="if user.is_admin then allow",
            context={"user": {"is_admin": True}},
        )
