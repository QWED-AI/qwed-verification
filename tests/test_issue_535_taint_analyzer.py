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


def test_method_call_sources_are_detected(analyzer):
    """Dotted method calls match sources by last segment (not `get`)."""
    for code in (
        'import os, sys\ncmd = sys.stdin.readline()\nos.system(cmd)',
        'import os, sys\ncmd = sys.stdin.read()\nos.system(cmd)',
        'import os\ndata = conn.recv(1024)\nos.system(data)',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code


def test_request_attribute_get_is_source(analyzer):
    """Any `request.<attr>.get` is a source; plain `dict.get` is not."""
    for attr in ("cookies", "headers", "values", "query_params"):
        code = f"import os\nx = request.{attr}.get('q')\nos.system(x)"
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code

    safe = 'import os\nd = {"q": "ls"}\nx = d.get("q")\nos.system(x)'
    result = analyzer.analyze(safe)
    assert result["status"] == "SAFE", safe
    assert result["vulnerabilities"] == [], safe


def test_request_object_methods_are_sources(analyzer):
    """Request-object `get*` methods are sources; plain `dict.get` is not."""
    for code in (
        "import os\nfrom flask import request\n"
        "cmd = request.get_data()\nos.system(cmd)",
        "import os, flask\n"
        "cmd = flask.request.args.get('q')\nos.system(cmd)",
        "import os\nfrom flask import request\n"
        "cmd = request.get_json()['cmd']\nos.system(cmd)",
        "import os\nfrom flask import request\n"
        "cmd = request.args.getlist('q')[0]\nos.system(cmd)",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code

    safe = "import os\nd = {}\nx = d.get('q')\nos.system(x)"
    result = analyzer.analyze(safe)
    assert result["status"] == "SAFE", safe
    assert result["vulnerabilities"] == [], safe


def test_sanitizer_result_transformed_is_not_clean(analyzer):
    """A sanitizer whose result is then transformed does not clean."""
    for code in (
        "import os, shlex\nx = input()\n"
        "y = shlex.quote(x).strip(\"'\")\nos.system(y)",
        "import os, shlex\nx = input()\n"
        "os.system(shlex.quote(x).strip(\"'\"))",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code

    for code in (
        "import os, shlex\nx = input()\n"
        'cmd = "ls " + shlex.quote(x)\nos.system(cmd)',
        "import os, shlex\nx = input()\n"
        'os.system(f"ls {shlex.quote(x)}")',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "SAFE", code
        assert result["vulnerabilities"] == [], code


def test_sink_keywords_injectable_only(analyzer):
    """Only injectable sink keywords are inspected."""
    for code in (
        "import os, subprocess\n"
        "subprocess.run(['ls'], env=os.environ.copy())",
        "import os, subprocess\n"
        "subprocess.run(['ls'], cwd=os.environ['HOME'])",
        "import subprocess\nd = input()\n"
        "subprocess.run(['cat'], input=d)",
        "import requests\np = input()\n"
        "requests.post('https://x.example', json=p)",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "SAFE", code
        assert result["vulnerabilities"] == [], code

    for code in (
        "import requests\nu = input()\nrequests.get(url=u)",
        "import subprocess\nc = input()\n"
        "subprocess.run(args=c, shell=True)",
        "q = input()\ncursor.execute(args=(), query=q)",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code

    safe = 'q = input()\ncursor.execute("SELECT ?", params=q)'
    result = analyzer.analyze(safe)
    assert result["status"] == "SAFE", safe
    assert result["vulnerabilities"] == [], safe


def test_shell_command_keywords_inspected(analyzer):
    """os.popen(cmd=...) is a shell sink keyword."""
    code = 'import os\nx = input()\nos.popen(cmd=x)'
    result = analyzer.analyze(code)
    assert result["status"] == "VULNERABLE", code
    assert len(result["vulnerabilities"]) >= 1, code


def test_sql_keyword_query_with_expansion(analyzer):
    """`**` expansions are fail-closed for the SQL query argument."""
    vulnerable = "x = input()\ncursor.execute(query=x, **{'args': ()})"
    result = analyzer.analyze(vulnerable)
    assert result["status"] == "VULNERABLE", vulnerable
    assert len(result["vulnerabilities"]) >= 1, vulnerable

    safe = 'x = input()\ncursor.execute("SELECT ?", params=x)'
    result = analyzer.analyze(safe)
    assert result["status"] == "SAFE", safe
    assert result["vulnerabilities"] == [], safe


def test_request_subscript_reads_are_sources(analyzer):
    """request.<attr>['k'] reads are sources; method/plain attrs are not."""
    for code in (
        'import os\nx = request.form["cmd"]\nos.system(x)',
        'import os\nx = request.args["cmd"]\nos.system(x)',
        'import os\nx = request.cookies["c"]\nos.system(x)',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code

    for code in (
        'import os\nx = request.method\nos.system(x)',
        'import os\nx = some_obj.form["x"]\nos.system(x)',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "SAFE", code
        assert result["vulnerabilities"] == [], code


def test_sliced_sanitizer_is_not_clean(analyzer):
    """A sliced sanitizer result does not clean; plain concat is safe."""
    for code in (
        "import os, shlex\nx = input()\n"
        "y = shlex.quote(x)[1:-1]\nos.system(y)",
        "import os, shlex\nx = input()\n"
        "os.system('ls ' + shlex.quote(x)[1:-1])",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code

    safe = (
        "import os, shlex\nx = input()\n"
        'cmd = "ls " + shlex.quote(x)\nos.system(cmd)'
    )
    result = analyzer.analyze(safe)
    assert result["status"] == "SAFE", safe
    assert result["vulnerabilities"] == [], safe


def test_starred_unpacking_target_is_tainted(analyzer):
    """Starred unpacking targets inherit the whole RHS taint."""
    for code in (
        "import os, sys\nprog, *args = sys.argv\nos.system(args[0])",
        "import os\nfirst, *rest = input().split()\n"
        "os.system(rest[0])",
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code
