"""QWED probe: TEST_CODE context — same patterns as runtime file.

Expectation: QWED downgrades most to advisory WARNING; Snyk/Sonar may
treat identically to runtime (context blindness comparison).
"""

import os
import subprocess

DEMO_KEY = "QWED_TEST_VALUE_not_a_real_secret"
aws_key = "AKIAIOSFODNN7EXAMPLE"  # real-format AWS example in test context


def test_eval_probe():
    return eval("1 + 1")


def test_shell_probe():
    os.system("echo hi")
    subprocess.call("ls -la", shell=True)
