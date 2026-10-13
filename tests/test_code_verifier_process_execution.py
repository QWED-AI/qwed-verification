"""Shell and process execution is never admitted (GHSA-6rxr-gq43-694g).

verify_code used to report os.system, os.popen and subprocess calls as
WARNING-level, context-dependent findings, so code that runs shell commands
came back VERIFIED with is_valid True and admission ADMIT, whatever the
argument, including caller input such as input().
"""

import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision

PROCESS_CODE = [
    # The advisory's proof of concept.
    'import os\nos.system("rm -rf /tmp/qwed-poc")',
    # Caller input reaching a shell.
    "import os\nos.system(input())\n",
    "import subprocess\nsubprocess.run(input(), shell=True)\n",
    # Every family named in the fix, called directly.
    "import os\nos.popen(cmd).read()\n",
    "import os\nos.execv('/bin/sh', ['sh'])\n",
    "import os\nos.spawnl(os.P_WAIT, '/bin/sh', 'sh')\n",
    "import os\nos.posix_spawn('/bin/sh', ['sh'], {})\n",
    "import subprocess\nsubprocess.Popen(['ls'])\n",
    "import subprocess\nsubprocess.call('ls', shell=True)\n",
    "import subprocess\nsubprocess.check_call(['ls'])\n",
    "import subprocess\nsubprocess.check_output(['ls'])\n",
    "import subprocess\nsubprocess.getoutput('ls')\n",
    "import pty\npty.spawn('/bin/sh')\n",
    "import asyncio\nasyncio.create_subprocess_shell(cmd)\n",
    # Through an alias, which a plain text scan does not see.
    "import subprocess as sp\nsp.run(cmd, shell=True)\n",
    "import os as o\no.popen(cmd)\n",
    "from os import system\nsystem(user_command)\n",
    "from os import system as run_it\nrun_it(user_command)\n",
    "from subprocess import check_output as co\nco(['ls'])\n",
    "from subprocess import *\nrun(cmd, shell=True)\n",
]


@pytest.mark.parametrize("code", PROCESS_CODE)
def test_process_execution_is_never_admitted(code):
    result = CodeVerifier().verify_code(code)
    fields = result.developer_fields
    assert fields["is_valid"] is False, fields
    assert fields["is_safe"] is False
    assert admission_decision(result).value == "BLOCKED"
    assert any(i["type"] == "process_execution" and i["severity"] == "CRITICAL" for i in fields["issues"]), fields["issues"]


@pytest.mark.parametrize("code", [
    'import os\nos.system("rm -rf /tmp/qwed-poc")',
    "import os\nos.system('ls')\n",
    "import subprocess as sp\nsp.run(['ls'])\n",
])
def test_deep_verification_is_never_admitted(code):
    result = CodeVerifier().verify_python_deep(code)
    assert result.developer_fields["is_valid"] is False
    assert admission_decision(result).value == "BLOCKED"


@pytest.mark.parametrize("code", [
    "def add(a, b):\n    return a + b\n",
    "import os\nprint(os.path.join('a', 'b'))\n",
    "import subprocess\n",
    "from os import path\nprint(path.basename('/tmp/x'))\n",
    "import asyncio\nasyncio.run(main())\n",
])
def test_code_without_process_execution_is_unchanged(code):
    result = CodeVerifier().verify_code(code)
    assert result.developer_fields["is_valid"] is True, result.developer_fields["issues"]
    assert admission_decision(result).value == "ADMIT"
