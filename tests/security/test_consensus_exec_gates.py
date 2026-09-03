"""Regression tests for PR-3 (closes #335 + #336): code-execution gate
hardening on the consensus/consensus-adjacent paths.

#335: the consensus translator validated expression CHARACTERS, not SHAPE —
a charset-valid multi-line expression became multi-statement module code at
`result = {expression}` interpolation and reached the sandbox.
#336: the SecureCodeExecutor AST matchers tested only first import segments,
innermost attribute bases and 8 builtin call names, so module-indirection
gadgets (pd.io.common.os / np.lib.npyio.os / posix / importlib) reached the
container; the stats RestrictedExecutor missed Attribute-func calls and deep
chains into sandbox module aliases entirely.
"""

import pytest

from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.translator import SecurityError, TranslationLayer
from qwed_new.core.secure_code_executor import _find_dangerous_pattern
from qwed_new.core.stats_verifier import RestrictedExecutor


def _task(expression: str) -> MathVerificationTask:
    return MathVerificationTask(
        expression=expression, claimed_answer=1, confidence=0.9, reasoning="test"
    )


class TestTranslatorStructuralGate:
    """#335: `_validate_math_output` must accept exactly ONE expression —
    the expression is interpolated verbatim into `result = {expression}`."""

    def test_poc_multistatement_smuggle_rejected(self):
        # The #335 PoC: charset-valid, denylist-clean, executes module code.
        poc = "1\nimport pandas.io.common as pc\npc.os.system(chr(105) + chr(100))"
        validator = TranslationLayer()
        task = _task(poc)
        with pytest.raises(SecurityError):
            validator._validate_math_output(task)

    @pytest.mark.parametrize(
        "expression",
        [
            "1\nimport os",                       # newline smuggling, bare import
            "2 + 2\nimport os",                   # statement after expression
            "import posix\nposix.system('id')",   # statement form
            "1;2",                                # semicolon chain
            "x = 5",                              # assignment (also charset-blocked)
        ],
    )
    def test_statement_forms_rejected(self, expression):
        validator = TranslationLayer()
        task = _task(expression)
        with pytest.raises(SecurityError):
            validator._validate_math_output(task)

    @pytest.mark.parametrize(
        "expression",
        [
            "2 + 2",
            "sqrt(16) + (1 + 2)",
            "1000 * (1 + 0.05)**2",
            "(\n1 +\n2\n)",   # newlines INSIDE one bracketed expression: safe
            "2 + 2\n",        # trailing newline after one expression: safe
        ],
    )
    def test_single_expression_forms_accepted(self, expression):
        TranslationLayer()._validate_math_output(_task(expression))

    def test_oversized_expression_rejected_before_parse(self):
        """CodeRabbit on #346: the length bound fires before the AST gate —
        oversized input is rejected without ever reaching the parser."""
        oversized = "1+" * 260 + "1"  # 521 chars, single expression shape
        assert len(oversized) > 500
        validator = TranslationLayer()
        task = _task(oversized)
        with pytest.raises(SecurityError):
            validator._validate_math_output(task)


class TestExecutorAstGate:
    """#336: module-indirection gadgets must be blocked by the executor's
    own defense-in-depth gate (`_find_dangerous_pattern`)."""

    @pytest.mark.parametrize(
        "code",
        [
            "import posix\nposix.system('id')",
            "import importlib\nimportlib.import_module('os').system('id')",
            "import pandas.io.common as pc\npc.os.system('id')",
            "import numpy.lib.npyio as npy\nnpy.os.getenv('HOME')",
            "from os import system\nsystem('id')",
            "from pandas.io.common import os\nos.system('id')",
            # Aliased-member gadget (#346 review, CodeRabbit): the real OS
            # module bound under an innocuous name via a clean module path.
            "from pandas.io.common import os as safe\nsafe.execl('/bin/id', 'id')",
            "from pandas.io.common import os as safe\nsafe.spawnl('/bin/id', 'id')",
            "import ctypes\nctypes.CDLL('libc.so.6')",
        ],
    )
    def test_gadgets_blocked(self, code):
        assert _find_dangerous_pattern(code) is not None

    @pytest.mark.parametrize(
        "code",
        [
            # The AST-aware guarantee: dangerous text outside executable
            # positions must never flag (docstring/comment/string literal).
            '"""os.system(\'id\') lives in a docstring"""\nresult = 1\n',
            "# os.system('id') is only a comment\nresult = 1\n",
            "note = 'never call os.system'\nresult = 2\n",
            # Legit pandas/numpy verification code.
            "import pandas as pd\ndf = pd.DataFrame({'a': [1, 2]})\nprint(df['a'].mean())\n",
            "import numpy as np\nresult = np.mean([1, 2, 3])\n",
        ],
    )
    def test_legitimate_code_passes(self, code):
        assert _find_dangerous_pattern(code) is None


class TestStatsRestrictedExecutor:
    """#336 stats path: Attribute-func calls and deep chains rooted at
    sandbox module aliases must be rejected; the one-level public surface
    and data-rooted chains stay allowed."""

    def setup_method(self):
        self.executor = RestrictedExecutor()

    def _unsafe(self, code):
        ok, issues = self.executor.is_code_safe(code)
        assert not ok, f"expected rejection: {code!r}"
        return issues

    def _safe(self, code):
        ok, issues = self.executor.is_code_safe(code)
        assert ok, f"expected acceptance, got {issues}: {code!r}"

    def test_deep_chain_pandas_blocked_and_deduped(self):
        issues = self._unsafe("result = pd.io.common.os.system('id')")
        assert len(issues) == len(set(issues))  # no duplicate spam

    def test_deep_chain_numpy_blocked(self):
        self._unsafe("result = np.lib.npyio.os.getenv('HOME')")

    def test_attribute_func_blocked_call(self):
        self._unsafe("result = obj.eval('1+1')")

    def test_bare_blocked_call(self):
        issues = self._unsafe("result = eval('1 + 1')")
        assert any("Blocked function: eval" in i for i in issues)

    def test_public_surface_one_level_allowed(self):
        self._safe("result = pd.read_csv('f.csv')")
        self._safe("result = np.mean([1, 2, 3])")

    def test_legitimate_nested_public_apis_allowed(self):
        """Greptile P1 on #346: the alias-internals check must not reject
        legitimate nested public namespaces — only chains that NAME a
        dangerous module are gadget traversals."""
        self._safe("result = np.linalg.norm([3.0, 4.0])")
        self._safe("np.random.seed(42)\nresult = np.random.normal()")
        self._safe("result = pd.Timestamp.now().isoformat()")

    def test_readonly_sys_metadata_allowed(self):
        """Greptile P1 round 2 + Sentry LOW: plain sys metadata is read-only
        — the alias check flags traversal into dangerous modules, not the
        alias root itself. Pure methods on allowed immutable members
        (str.split on sys.version) are harmless by construction."""
        self._safe("result = sys.maxsize")
        self._safe("result = sys.float_info.dig")
        self._safe("result = sys.byteorder")
        self._safe("result = sys.version.split()[0]")

    def test_reflective_and_controlling_sys_members_blocked(self):
        self._unsafe("result = sys.modules['os'].getcwd()")
        self._unsafe("sys.exit(1)")
        self._unsafe("sys.setrecursionlimit(10)")

    def test_reflective_sys_to_process_primitive_blocked(self):
        # sys.modules is blocked directly AND the OS-primitive call name is
        # blocked even through an unchecked chain root (subscript), so the
        # reflection escape cannot rebind and call around the gate.
        self._unsafe("result = sys.modules['os'].system('id')")

    def test_frame_introspection_blocked(self):
        """Greptile P1 round 3: sys is introspectable end-to-end, so sys
        members outside the named read-only allowlist fail closed —
        _getframe handed out the live globals after the member denylist
        had blocked modules."""
        self._unsafe("result = sys._getframe(0).f_globals")
        self._unsafe("result = sys._current_frames()")
        self._unsafe("result = sys.exc_info()")
        self._unsafe("result = sys.call_tracing")

    def test_sys_allowlisted_metadata_nested_access_allowed(self):
        self._safe("result = sys.implementation.name")
        self._safe("result = sys.version_info[:2]")

    def test_data_rooted_chains_unaffected(self):
        self._safe("result = df.groupby('k')['v'].mean()")
        self._safe("result = df.col.sum()")

    def test_import_statements_rejected(self):
        issues = self._unsafe("import pandas as pd\nresult = pd.read_csv('f.csv')")
        assert any("Import statements not allowed" in i for i in issues)

    def test_unparseable_code_fails_closed(self):
        ok, issues = self.executor.is_code_safe("this is not python (")
        assert not ok
        assert any(i.startswith("Syntax error") for i in issues)
