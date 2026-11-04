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
        'render_template_string(y)'
    )
    result = analyzer.analyze(code)
    assert result["status"] == "SAFE"
    assert result["vulnerabilities"] == []
