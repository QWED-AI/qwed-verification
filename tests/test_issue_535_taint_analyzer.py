"""Regression tests for QWED-AI/qwed-verification#535.

TaintAnalyzer reported SAFE for code where user input reaches a shell sink
inside an expression (BinOp, f-string, %-formatting, str.format, join), and
it treated html.escape as a shell sanitiser. Unknown helper calls also
dropped taint (substring sanitiser matching, e.g. "int" in
"print_and_return").
"""
import pytest

from src.qwed_new.core.taint_analyzer import TaintAnalyzer


@pytest.fixture
def analyzer():
    return TaintAnalyzer()


# Each snippet must be VULNERABLE: tainted `x` reaches os.system.
SHELL_EXPRESSION_CASES = {
    "concat": 'import os\nx = input()\nos.system("ls " + x)',
    "f-string": 'import os\nx = input()\nos.system(f"ls {x}")',
    "percent-format": 'import os\nx = input()\nos.system("ls %s" % x)',
    "str-format": 'import os\nx = input()\nos.system("ls {}".format(x))',
    "join": 'import os\nx = input()\nos.system(" ".join(["ls", x]))',
    "html-escape": (
        'import os, html\nx = input()\ny = html.escape(x)\nos.system(y)'
    ),
    "helper": (
        'import os\nx = input()\ny = print_and_return(x)\nos.system(y)'
    ),
    # Controls: these were already caught before the fix.
    "bare-name": 'import os\nx = input()\nos.system(x)',
    "direct": 'import os\nos.system(input())',
}


@pytest.mark.parametrize("name", sorted(SHELL_EXPRESSION_CASES))
def test_tainted_input_reaching_shell_is_vulnerable(analyzer, name):
    result = analyzer.analyze(SHELL_EXPRESSION_CASES[name])
    assert result["status"] == "VULNERABLE", name
    assert len(result["vulnerabilities"]) >= 1, name


def test_shlex_quote_is_safe_for_shell(analyzer):
    code = 'import os, shlex\nx = input()\ny = shlex.quote(x)\nos.system(y)'
    result = analyzer.analyze(code)
    assert result["status"] == "SAFE"
    assert result["vulnerabilities"] == []


def test_shlex_quote_still_tainted_for_sql(analyzer):
    code = 'import shlex\nx = input()\ny = shlex.quote(x)\ncursor.execute(y)'
    result = analyzer.analyze(code)
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) >= 1


def test_shlex_quote_still_tainted_for_html(analyzer):
    code = 'import shlex\nx = input()\ny = shlex.quote(x)\nrender_template_string(y)'
    result = analyzer.analyze(code)
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) >= 1


def test_html_escape_is_safe_for_html(analyzer):
    code = (
        'import html\nx = input()\ny = html.escape(x)\n'
        'mark_safe(y)'
    )
    result = analyzer.analyze(code)
    assert result["status"] == "SAFE"
    assert result["vulnerabilities"] == []


# --- Regression tests for PR #586 review findings ---


def test_aug_assign_keeps_existing_taint(analyzer):
    """`y += "suffix"` must add RHS taint, not drop `y`'s taint."""
    code = 'import os\nx = input()\ny = x\ny += "suffix"\nos.system(y)'
    result = analyzer.analyze(code)
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) >= 1


def test_attribute_subscript_sources_in_expressions(analyzer):
    """Direct env/argv references inside expressions are sources."""
    for code in (
        'import os\ncmd = "echo " + os.environ["CMD"]\nos.system(cmd)',
        'import os, sys\nx = "ls " + sys.argv[1]\nos.system(x)',
        "import os, sys\nos.system('ls ' + sys.argv[1])",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code
        assert len(result["sources_found"]) >= 1 or any(
            v["source"]["variable"].startswith("<direct:")
            for v in result["vulnerabilities"]
        ), code


def test_branch_reassignment_keeps_taint(analyzer):
    """Taint from any branch RHS survives; union, never last-write-wins."""
    for code in (
        "import os\nif c:\n    cmd = input()\nelse:\n    cmd = 'ls'\n"
        "os.system(cmd)\n",
        "import os\nx = input()\ny = x\nif ok:\n    y = 'ls'\n"
        "os.system(y)\n",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code


def test_nested_sanitizer_matches_inline_form(analyzer):
    """`cmd = "ls " + shlex.quote(x)` is SAFE, like the inline form."""
    code = (
        'import os, shlex\nx = input()\n'
        'cmd = "ls " + shlex.quote(x)\nos.system(cmd)'
    )
    result = analyzer.analyze(code)
    assert result["status"] == "SAFE"
    assert result["vulnerabilities"] == []


def test_template_sink_not_cleared_by_html_escape(analyzer):
    """render_template_string is SSTI: html.escape must not clear it."""
    code = (
        'import html\nfrom flask import render_template_string\n'
        'x = input()\nrender_template_string(html.escape(x))'
    )
    result = analyzer.analyze(code)
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) >= 1


def test_source_matching_is_exact_name(analyzer):
    """os.getcwd() and dict.get() are not sources."""
    for code in (
        'import os\nx = os.getcwd()\nos.system(x)',
        'import os\nd = {"k": "ls"}\nx = d.get("k")\nos.system(x)',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "SAFE", code
        assert result["vulnerabilities"] == [], code


def test_sql_parameter_binding_is_safe(analyzer):
    """Taint only in execute() params is safe; taint in query is not."""
    safe = (
        "x = input()\n"
        "cursor.execute('SELECT * FROM u WHERE id = %s', (x,))"
    )
    result = analyzer.analyze(safe)
    assert result["status"] == "SAFE"
    assert result["vulnerabilities"] == []

    vulnerable = "x = input()\nq = 'SELECT ' + x\ncursor.execute(q, (1,))"
    result = analyzer.analyze(vulnerable)
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) >= 1


def test_tuple_unpacking_taints_per_element(analyzer):
    """`safe, bad = "ls", input()`: only `bad` is tainted."""
    safe = 'import os\nsafe, bad = "ls", input()\nos.system(safe)'
    result = analyzer.analyze(safe)
    assert result["status"] == "SAFE"
    assert result["vulnerabilities"] == []

    vulnerable = 'import os\nsafe, bad = "ls", input()\nos.system(bad)'
    result = analyzer.analyze(vulnerable)
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) >= 1
