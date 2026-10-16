"""GHSA-j3x4-v3p2-4mq3: the sandbox static gates all key on identifier syntax and
could be defeated (names assembled from string literals, getattr with string
constants, sys.modules re-acquisition, stored references) to reach process
execution or eval/exec via the interpreter namespace.

The structural fix isolates the execution namespace: the user code is exec'd with
a capability allowlist of builtins and an import guard that permits only safe
modules, so eval/exec/getattr/vars/__import__/sys.modules and os/subprocess/… are
simply absent at runtime. These tests drive the REAL harness (secure_code_executor
._wrap_code) in a subprocess with the /workspace paths redirected to a tmpdir, so
no Docker is needed to exercise the namespace behaviour.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

np = pytest.importorskip("numpy")

from qwed_new.core.secure_code_executor import (
    SecureCodeExecutor,
    _find_dangerous_pattern,
)


def _run_in_harness(user_code: str, context=None):
    """Run user_code through the real harness, returning (returncode, result_dict)."""
    ex = SecureCodeExecutor.__new__(SecureCodeExecutor)
    ex.max_result_bytes = 64000
    with tempfile.TemporaryDirectory() as d:
        harness = ex._wrap_code(user_code).replace("/workspace/", d.replace("\\", "/") + "/")
        with open(os.path.join(d, "script.py"), "w", encoding="utf-8") as f:
            f.write(harness)
        with open(os.path.join(d, "user_code.py"), "w", encoding="utf-8") as f:
            f.write(user_code)
        with open(os.path.join(d, "context.json"), "w", encoding="utf-8") as f:
            json.dump(context or {}, f)
        env = dict(os.environ, PYTHONUTF8="1")
        proc = subprocess.run(
            [sys.executable, os.path.join(d, "script.py")],
            capture_output=True, text=True, env=env, timeout=60,
        )
        result_path = os.path.join(d, "result.json")
        result = {}
        if os.path.exists(result_path):
            with open(result_path, encoding="utf-8") as f:
                result = json.load(f)
        return proc.returncode, result


# --- legitimate computation must still run -------------------------------------

@pytest.mark.parametrize("code,expected", [
    ("result = 1 + 1", 2),
    ("result = sum([1, 2, 3]) + max(4, 5)", 11),
    ("result = int(np.sum([1, 2, 3, 4]))", 10),              # np pre-bound
    ("import numpy as np\nresult = int(np.prod([1, 2, 3]))", 6),  # allowed import
    ("import math\nresult = round(math.sqrt(16))", 4),
    ("result = [x * x for x in range(4)]", [0, 1, 4, 9]),
])
def test_legitimate_code_runs(code, expected):
    rc, result = _run_in_harness(code)
    assert rc == 0, result
    assert result.get("result") == expected


def test_injected_dataframe_is_usable():
    ctx = {"df": {"_type": "dataframe", "data": [{"a": 1}, {"a": 2}, {"a": 3}]}}
    rc, result = _run_in_harness("result = int(df['a'].sum())", ctx)
    assert rc == 0, result
    assert result.get("result") == 6


# --- the bypass family reaches nothing at runtime ------------------------------

BYPASSES = [
    "import os\nresult = os.system('id')",
    "result = __import__('os').system('id')",
    "import importlib\nresult = importlib.import_module('os').system('id')",
    "n = 'o' + 's'\nresult = __import__(n).system('id')",      # assembled name
    "import sys\nresult = sys.modules['os'].system('id')",
    "import ctypes\nresult = ctypes.CDLL('libc.so.6')",
    "result = getattr([], 'append')",                          # reflection builtin
    "result = eval('1 + 1')",
    "exec('x = 1')\nresult = 1",
    "result = open('/etc/passwd')",
    "result = vars()",
]


@pytest.mark.parametrize("code", BYPASSES)
def test_bypass_is_blocked_at_runtime(code):
    rc, result = _run_in_harness(code)
    assert rc != 0
    assert "error" in result          # harness reports an error, no 'result'
    assert "result" not in result


# --- static-gate stopgap (posix_spawn / posix_spawnp / Popen) ------------------

@pytest.mark.parametrize("code", [
    "import os\nos.posix_spawn('/bin/sh', ['sh'], {})",
    "import os\nos.posix_spawnp('sh', ['sh'], {})",
    "import subprocess\nsubprocess.Popen(['ls'])",
])
def test_static_gate_flags_new_os_call_names(code):
    assert _find_dangerous_pattern(code) is not None
