import pandas as pd
import pytest

from qwed_new.core.code_executor import (
    LEGACY_CODE_EXECUTOR_DISABLED,
    CodeExecutor,
)


def test_code_executor_is_hard_blocked_for_harmless_code():
    executor = CodeExecutor()

    with pytest.raises(RuntimeError, match="CodeExecutor is disabled"):
        executor.execute("result = 2 + 2")


def test_code_executor_is_hard_blocked_with_dataframe_context():
    executor = CodeExecutor()
    df = pd.DataFrame({"value": [1, 2, 3]})

    with pytest.raises(RuntimeError) as exc_info:
        executor.execute("result = df['value'].sum()", df=df)

    assert str(exc_info.value) == LEGACY_CODE_EXECUTOR_DISABLED


def test_code_executor_error_points_callers_to_secure_boundary():
    executor = CodeExecutor()

    with pytest.raises(RuntimeError) as exc_info:
        executor.execute("__import__('os').system('echo unsafe')")

    assert "SecureCodeExecutor" in str(exc_info.value)
