"""Regression tests for QWED-AI/qwed-verification#535.

TaintAnalyzer reported SAFE for code where user input reaches a shell sink
inside an expression (BinOp, f-string, %-formatting, str.format, join), and
it treated html.escape as a shell sanitiser. Unknown helper calls also
dropped taint (substring sanitiser matching, e.g. "int" in
"print_and_return").
"""
import ast

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


def test_shlex_quote_gives_no_shell_relief(analyzer):
    """shlex.quote protects one word; the command around it decides the rest.

    The quoted word still names the program, runs under ``sh -c``, or is
    read as an option (``--to-command=id`` needs no quoting, so tar runs
    ``id``), so no shell sink is relieved.
    """
    for code in (
        'import os, shlex\nx = input()\ny = shlex.quote(x)\nos.system(y)',
        'import os, shlex\nx = input()\nos.system(shlex.quote(x))',
        'import os, shlex\nx = input()\ny = shlex.quote(x)\n'
        'os.system("ls " + y)',
        'import os, shlex\nx = input()\nos.system("sh -c " + shlex.quote(x))',
        'import os, shlex\nx = input()\n'
        'os.system("tar xf a.tar " + shlex.quote(x))',
        'import os, shlex\nx = input()\n'
        'os.system(\'echo "\' + shlex.quote(x) + \'"\')',
        'import os, shlex\nx = input()\nos.system(f"echo {shlex.quote(x)!r}")',
        'import os, shlex\nx = input()\nos.system("echo %r" % shlex.quote(x))',
        'import os, shlex\nx = input()\n'
        'os.system("echo " + repr(shlex.quote(x)))',
        'from shlex import quote\nimport os\nx = input()\n'
        'os.system("ls " + quote(x))',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "VULNERABLE", code
        assert len(result["vulnerabilities"]) >= 1, code


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
    """`s = "<p>" + html.escape(x)` is SAFE, like the inline form."""
    for code in (
        'import html\nx = input()\n'
        's = "<p>" + html.escape(x)\nmark_safe(s)',
        'import html\nx = input()\nmark_safe("<p>" + html.escape(x))',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "SAFE", code
        assert result["vulnerabilities"] == [], code


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
        "import html\nx = input()\n"
        'cmd = "<p>" + html.escape(x)\nmark_safe(cmd)',
        "import html\nx = input()\n"
        'mark_safe(f"<p>{html.escape(x)}</p>")',
    ):
        result = analyzer.analyze(code)
        assert result["status"] == "SAFE", code
        assert result["vulnerabilities"] == [], code


def test_sink_keywords_injectable_only(analyzer):
    """Every sink keyword is inspected except those that carry no payload."""
    for code in (
        "import os, subprocess\n"
        "subprocess.run(['ls'], env=os.environ.copy())",
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
        # cwd picks which ./tool a relative program path runs.
        "import os, subprocess\n"
        "subprocess.run(['ls'], cwd=os.environ['HOME'])",
        # input= is the script when the program is a shell.
        "import subprocess\nd = input()\n"
        "subprocess.run(['cat'], input=d)",
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

    # The HTTP method grammar allows |, &, $ and backticks.
    code = 'import os\nx = request.method\nos.system(x)'
    result = analyzer.analyze(code)
    assert result["status"] == "VULNERABLE", code

    code = 'import os\nx = some_obj.form["x"]\nos.system(x)'
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
        "import html\nx = input()\n"
        'cmd = "<p>" + html.escape(x)\nmark_safe(cmd)'
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


# --- Maintainer review of PR #586: sanitiser relief must be backed ---


def _assert_vulnerable(analyzer, code):
    result = analyzer.analyze(code)
    assert result["status"] == "VULNERABLE", code
    assert len(result["vulnerabilities"]) >= 1, code


def _assert_safe(analyzer, code):
    result = analyzer.analyze(code)
    assert result["status"] == "SAFE", code
    assert result["vulnerabilities"] == [], code


def test_shlex_split_is_not_a_sanitizer(analyzer):
    """shlex.split only splits words: the caller still picks the program."""
    _assert_vulnerable(
        analyzer,
        "import shlex, subprocess\nsubprocess.run(shlex.split(input()))",
    )


def test_shlex_quote_still_tainted_for_mark_safe(analyzer):
    """shlex.quote does nothing for HTML, so mark_safe stays tainted."""
    _assert_vulnerable(
        analyzer, "import shlex\nx = input()\ny = shlex.quote(x)\nmark_safe(y)"
    )


TRANSFORMED_SANITIZER_CASES = {
    "unquote-inline": (
        'import os, shlex\nx = input()\n'
        'os.system("echo " + unquote(shlex.quote(x)))'
    ),
    "unescape-inline": (
        "import html\nx = input()\nmark_safe(html.unescape(html.escape(x)))"
    ),
    "slice-variable": (
        "import html\nx = input()\ny = html.escape(x)\nmark_safe(y[1:-1])"
    ),
    "strip-variable": (
        "import html\nx = input()\ny = html.escape(x)\n"
        "mark_safe(y.strip(\"'\"))"
    ),
    "call-variable": (
        "import html\nx = input()\ny = html.escape(x)\nmark_safe(unquote(y))"
    ),
    "shell-slice-variable": (
        'import os, shlex\nx = input()\ny = shlex.quote(x)\n'
        'os.system("echo " + y[1:-1])'
    ),
    "repr": "import html\nx = input()\nmark_safe(repr(html.escape(x)))",
    "fstring-conversion": (
        'import html\nx = input()\nmark_safe(f"<p>{html.escape(x)!r}</p>")'
    ),
    "fstring-format-spec": (
        'import html\nx = input()\nmark_safe(f"<p>{html.escape(x):>9}</p>")'
    ),
    "percent-r": (
        'import html\nx = input()\nmark_safe("<p>%r</p>" % html.escape(x))'
    ),
    "percent-width": (
        'import html\nx = input()\nmark_safe("<p>%9s</p>" % html.escape(x))'
    ),
    "percent-mapping": (
        'import html\nx = input()\n'
        'mark_safe("<p>%(v)s</p>" % {"v": html.escape(x)})'
    ),
    "format-conversion": (
        'import html\nx = input()\nmark_safe("<p>{!r}</p>".format(html.escape(x)))'
    ),
    "format-numbered": (
        'import html\nx = input()\nmark_safe("<p>{0}</p>".format(html.escape(x)))'
    ),
    "format-spec": (
        'import html\nx = input()\nmark_safe("<p>{:>9}</p>".format(html.escape(x)))'
    ),
    "join": 'import html\nx = input()\nmark_safe("".join([html.escape(x)]))',
    "number-to-str": 'import os\nx = input()\nos.system("kill " + str(int(x)))',
    "number-to-chr": 'import os\nx = input()\nos.system("echo " + chr(int(x)))',
}


@pytest.mark.parametrize("name", sorted(TRANSFORMED_SANITIZER_CASES))
def test_transformed_sanitized_value_is_tainted(analyzer, name):
    """Relief ends as soon as anything transforms the sanitised value."""
    _assert_vulnerable(analyzer, TRANSFORMED_SANITIZER_CASES[name])


DIRECT_POSITION_SAFE_CASES = {
    "argument": "import html\nx = input()\nmark_safe(html.escape(x))",
    "concat": "import html\nx = input()\nmark_safe('<b>' + html.escape(x) + '</b>')",
    "fstring": "import html\nx = input()\nmark_safe(f'<p>{html.escape(x)}</p>')",
    "percent-s": "import html\nx = input()\nmark_safe('<p>%s %%</p>' % html.escape(x))",
    "percent-tuple": (
        "import html\nx = input()\n"
        "mark_safe('<p>%s</p><p>%s</p>' % (html.escape(x), html.escape(x)))"
    ),
    "format": "import html\nx = input()\nmark_safe('<p>{}</p>'.format(html.escape(x)))",
    "format-escaped-braces": (
        "import html\nx = input()\n"
        "mark_safe('<p>{{}} {}</p>'.format(html.escape(x), 1))"
    ),
    "two-escaped-values": (
        "import html\nx = input()\n"
        "mark_safe(f'<b>{html.escape(x)}</b> said {html.escape(x)}')"
    ),
    "variable": "import html\nx = input()\ny = html.escape(x)\nmark_safe('<b>' + y)",
    "variable-chain": (
        "import html\nx = input()\ny = html.escape(x)\nz = '<p>' + y\n"
        "mark_safe(z + '</p>')"
    ),
    "aug-assign": (
        "import html\nx = input()\ny = html.escape(x)\ny += '</b>'\nmark_safe(y)"
    ),
    "quote-true": "import html\nx = input()\nmark_safe(html.escape(x, True))",
    "keyword-s": "import html\nx = input()\nmark_safe(html.escape(s=x, quote=True))",
    "number-fstring": "import os\nx = input()\nos.system(f'kill {int(x)}')",
    "number-variable": "import os\nx = input()\ny = int(x)\nos.system('kill %s' % y)",
    "number-in-attribute": (
        "import os\nx = input()\nmark_safe('<a href=' + f'{int(x)}' + '>')"
    ),
    "path": (
        "from werkzeug.utils import secure_filename\nx = input()\n"
        "open('/srv/' + secure_filename(x))"
    ),
}


@pytest.mark.parametrize("name", sorted(DIRECT_POSITION_SAFE_CASES))
def test_sanitizer_relieves_only_in_direct_positions(analyzer, name):
    """+, plain f-string fields, %s and plain {} keep the relief."""
    _assert_safe(analyzer, DIRECT_POSITION_SAFE_CASES[name])


HTML_CONTEXT_CASES = {
    "unquoted-attribute": "mark_safe('<a href=' + html.escape(x) + '>')",
    "quoted-attribute": "mark_safe('<a title=\"' + html.escape(x) + '\">')",
    "attribute-gt-in-quotes": (
        "mark_safe('<a title=\"a>b\" onclick=' + html.escape(x) + '>')"
    ),
    "unclosed-quote": "mark_safe('<a title=\"x ' + html.escape(x))",
    "script": "mark_safe('<script>var a = ' + html.escape(x))",
    "style": "mark_safe('<p><style>p { color: ' + html.escape(x))",
    "comment": "mark_safe('<!-- ' + html.escape(x) + ' -->')",
    "trailing-lt": "mark_safe('<p><' + html.escape(x))",
    "trailing-end-tag-open": "mark_safe('<p></' + html.escape(x))",
    "unclosed-end-tag": "mark_safe('<p></a ' + html.escape(x))",
    "unclosed-bogus-comment": "mark_safe('<p><!x ' + html.escape(x))",
    # A quote opens a value only after "=": in a name it is a plain
    # character, so it cannot pair with a later quote.
    "quote-in-attribute-name": (
        "mark_safe(\"<a b'c><img src=x onerror='1>\" + html.escape(x) + \"'>\")"
    ),
    "quote-in-bogus-comment": (
        "mark_safe(\"<?x a='><img src=x onerror='1>\" + html.escape(x) + \"'>\")"
    ),
    "lt-before-space": (
        "mark_safe(\"< a='><img src=x onerror='1>\" + html.escape(x) + \"'>\")"
    ),
    "abrupt-empty-comment": "mark_safe(\"<!--><a href='-->\" + html.escape(x))",
    "bang-comment-end": "mark_safe(\"<!-- --!><a href='-->\" + html.escape(x))",
    # Elements that change how the rest is read: no relief after them.
    "closed-script": "mark_safe('<script>a()</script><p>' + html.escape(x))",
    "closed-style": "mark_safe('<style>p {}</style>' + html.escape(x))",
    "script-escape": "mark_safe('<script><!--<script></script>' + html.escape(x))",
    "textarea": (
        "mark_safe(\"<textarea><a title='</textarea><img src=x onerror='1>\""
        " + html.escape(x))"
    ),
    "svg": "mark_safe(\"<svg><style><a href='</style>\" + html.escape(x))",
    "unclosed-script-close": "mark_safe('<script>a()</script ' + html.escape(x))",
    "after-unknown-value": "mark_safe(prefix + html.escape(x))",
    "after-unescaped-value": "mark_safe(html.escape(x) + '<a href=' + html.escape(x))",
    "quote-false": "mark_safe(html.escape(x, quote=False))",
    "quote-false-positional": "mark_safe(html.escape(x, False))",
    "quote-variable": "mark_safe(html.escape(x, quote=q))",
    "starred": "mark_safe(html.escape(*[x, False]))",
    "unknown-keyword": "mark_safe(html.escape(x, other=True))",
}


@pytest.mark.parametrize("name", sorted(HTML_CONTEXT_CASES))
def test_html_relief_needs_text_content(analyzer, name):
    """HTML escaping relieves only in text content, with quotes escaped."""
    code = "import html\nx = input()\n" + HTML_CONTEXT_CASES[name]
    _assert_vulnerable(analyzer, code)


@pytest.mark.parametrize("prefix", [
    "<p>",
    "<a href=\"/x\">link</a> ",
    "<a title='a>b'>t</a>",
    "<!-- note --><p>",
    "<!----><p>",
    "<!DOCTYPE html><p>",
    "a < b ",
    "<p></>",
    "<p></ x>",
    "<a b'c>t</a>",
    "<input value=a'b>",
    "<a title=\"x'y\">t</a>",
    "<img src=x/>",
    "<br/><p>",
    "<!---><p>",
])
def test_html_relief_after_closed_markup(analyzer, prefix):
    """Constant markup that ends in text content keeps the relief."""
    code = f"import html\nx = input()\nmark_safe({prefix!r} + html.escape(x))"
    _assert_safe(analyzer, code)


SANITIZER_NAME_CASES = {
    "own-def": "def clean(s):\n    return s\nx = input()\nmark_safe(clean(x))",
    "wrong-module": "from re import escape\nx = input()\nmark_safe(escape(x))",
    "not-imported": "x = input()\nmark_safe(escape(x))",
    "unimported-module": "x = input()\nmark_safe(html.escape(x))",
    "lambda": "escape = lambda s: s\nx = input()\nmark_safe(escape(x))",
    "rebound-module": (
        "import html\nhtml = make_html()\nx = input()\nmark_safe(html.escape(x))"
    ),
    "two-imports": (
        "try:\n    from markupsafe import escape\nexcept ImportError:\n"
        "    from html import escape\nx = input()\nmark_safe(escape(x))"
    ),
    "relative-import": "from . import html\nx = input()\nmark_safe(html.escape(x))",
    "parameter": (
        "import html\ndef f(html):\n    return html\nx = input()\n"
        "mark_safe(html.escape(x))"
    ),
    "class": (
        "class html:\n    escape = staticmethod(str)\nx = input()\n"
        "mark_safe(html.escape(x))"
    ),
    "except-as": (
        "import html\ntry:\n    pass\nexcept Exception as html:\n    pass\n"
        "x = input()\nmark_safe(html.escape(x))"
    ),
    "match-capture": (
        "import html\nmatch v:\n    case [*html]:\n        pass\n"
        "x = input()\nmark_safe(html.escape(x))"
    ),
    "match-as": (
        "import html\nmatch v:\n    case html:\n        pass\n"
        "x = input()\nmark_safe(html.escape(x))"
    ),
    "match-rest": (
        "import html\nmatch v:\n    case {**html}:\n        pass\n"
        "x = input()\nmark_safe(html.escape(x))"
    ),
    "async-def": (
        "import html\nasync def html():\n    pass\nx = input()\n"
        "mark_safe(html.escape(x))"
    ),
    "call-root": "import html\nx = input()\nmark_safe(get_html().escape(x))",
    "own-int": "import os\ndef int(s):\n    return s\nx = input()\nos.system(int(x))",
    "int-from-module": (
        "import os\nfrom numpy import int64 as int\nx = input()\nos.system(int(x))"
    ),
    "int-attribute": "import os\nx = input()\nos.system(int.real(x))",
}


@pytest.mark.parametrize("name", sorted(SANITIZER_NAME_CASES))
def test_sanitizer_must_be_imported_from_its_module(analyzer, name):
    """Only a sanitiser the code imports itself, never rebinds, relieves."""
    _assert_vulnerable(analyzer, SANITIZER_NAME_CASES[name])


@pytest.mark.parametrize("code", [
    "from html import escape\nx = input()\nmark_safe(escape(x))",
    "from html import escape as e\nx = input()\nmark_safe(e(x))",
    "import html as h\nx = input()\nmark_safe(h.escape(x))",
    "import html\nimport html\nx = input()\nmark_safe(html.escape(x))",
    "import markupsafe\nx = input()\nmark_safe(markupsafe.escape(x))",
    "from markupsafe import Markup\nx = input()\nmark_safe(Markup.escape(x))",
    "from django.utils.html import escape\nx = input()\nmark_safe(escape(x))",
    "import django.utils.html\nx = input()\nmark_safe(django.utils.html.escape(x))",
    "import html\nclass A:\n    def __init__(self):\n        super().__init__()\n"
    "x = input()\nmark_safe(html.escape(x))",
])
def test_imported_sanitizer_relieves(analyzer, code):
    """The right module's sanitiser, however it is imported, relieves."""
    _assert_safe(analyzer, code)


PATCHED_SANITIZER_CASES = {
    "attribute-store": "import html\nhtml.escape = str",
    "attribute-store-alias": "import html\nm = html\nm.escape = str",
    "store-on-import": "import html\nhtml.helper = 1",
    "code-swap": "import html\nhtml.escape.__code__ = (lambda s: s).__code__",
    "setattr": "import html\nsetattr(html, 'escape', str)",
    "namespace": "import html\nvars(html)['escape'] = str",
    "module-dict": "import html\nhtml.__dict__['escape'] = str",
    "modules": "import html, sys\nsys.modules['html'] = fake",
    "builtins": "import builtins, html\nbuiltins.int = str",
    "builtin-module": "import html\nprint.__self__.int = str",
    "star-import": "from markupsafe import *\nimport html",
    "from-reflective": "from builtins import setattr\nimport html",
    "from-sys-modules": "from sys import modules\nimport html",
    "exec": "import html\nexec('html.escape = str')",
    "getattr": "import html\ngetattr(html, '__dict__')['escape'] = str",
    "attrgetter": (
        "import html, operator\noperator.attrgetter('__dict__')(html)['escape'] = str"
    ),
    "formatter": (
        "import html, string\n"
        "string.Formatter().get_field('0.__dict__', [html], {})[0]['escape'] = str"
    ),
    "inspect": "import html, inspect\nm = inspect.getmodule(html.escape)",
    "mock-patch": "import html\nfrom unittest import mock\nmock.patch('html.escape', str).start()",
    "mock-patch-object": (
        "import html\nfrom unittest import mock\n"
        "mock.patch.object(html, 'escape', str).start()"
    ),
    "unittest-mock": "import html, unittest.mock\nunittest.mock.patch('html.escape', str).start()",
    "pydoc-locate": "import html, pydoc\npydoc.locate('html.__dict__')['escape'] = str",
    "pkgutil-resolve": (
        "import html, pkgutil\npkgutil.resolve_name('html:__dict__')['escape'] = str"
    ),
    "monkeypatch": (
        "import html\ndef test(monkeypatch):\n    monkeypatch.setattr('html.escape', str)"
    ),
    "code-in-string": (
        "import html, timeit\n"
        "timeit.timeit('pass', setup='import html; html.escape = str', number=1)"
    ),
}


@pytest.mark.parametrize("name", sorted(PATCHED_SANITIZER_CASES))
def test_code_that_may_patch_a_sanitizer_gets_no_relief(analyzer, name):
    """Patching, reflection, star imports and object loaders end relief."""
    code = (
        PATCHED_SANITIZER_CASES[name]
        + "\nx = input()\nmark_safe(html.escape(x))"
    )
    _assert_vulnerable(analyzer, code)


def test_builtin_patched_by_string_lookup_gets_no_relief(analyzer):
    """getattr reaches a builtin's module by strings: int() is not trusted."""
    _assert_vulnerable(
        analyzer,
        "import os\ngetattr(getattr(print, '__self__'), '__dict__')['int'] = str\n"
        "x = input()\nos.system(int(x))",
    )


def test_builtin_patched_by_mock_gets_no_relief(analyzer):
    """mock.patch replaces int() by a dotted string: int() is not trusted."""
    _assert_vulnerable(
        analyzer,
        "import os\nfrom unittest import mock\n"
        "mock.patch('builtins.int', str).start()\nx = input()\nos.system(int(x))",
    )


@pytest.mark.parametrize("code", [
    "import os\nfrom os import environ\nos.system(environ.get('X'))",
    "import os\nfrom os import environ\nc = environ.get('X')\nos.system(c)",
    "import os\nfrom os import environ\nos.system(environ['X'])",
    "import os\nfrom os import getenv as env\nos.system(env('X'))",
    "import os\nfrom sys import argv\nos.system(argv[1])",
    "import os as o\no.system(o.environ.get('X'))",
    "import os\nfrom flask import request as req\nos.system(req.args.get('c'))",
    "import os\nfrom flask import request as req\nc = req.path\nos.system(c)",
])
def test_sources_resolve_through_imports(analyzer, code):
    """A source imported under another name is still a source."""
    _assert_vulnerable(analyzer, code)


@pytest.mark.parametrize("code", [
    "from sys import argv\nimport subprocess\nsubprocess.call(argv)",
    "import os\nfrom sys import argv\nos.system(' '.join(argv))",
    "import os\nfrom sys import argv\nc = ' '.join(argv)\nos.system(c)",
    "from os import environ\nx = environ\neval(x['X'])",
    # An import counts even if the name is assigned too (fail closed).
    "import os\nfrom os import environ\nenviron = {}\nos.system(environ['X'])",
])
def test_imported_source_name_read_on_its_own(analyzer, code):
    """A bare name imported from a source module is a source read."""
    _assert_vulnerable(analyzer, code)


@pytest.mark.parametrize("code", [
    "from os import *\neval(environ['X'])",
    "from os import *\neval(environ.get('X'))",
    "from sys import *\neval(argv[1])",
    "from sys import *\nx = argv\neval(x[1])",
])
def test_star_imported_source_names(analyzer, code):
    """A star import may bind a source name."""
    _assert_vulnerable(analyzer, code)


@pytest.mark.parametrize("code, status", [
    ("from sys import argv\nargv += ['x']", "SAFE"),
    ("from sys import *\nargv += ['x']", "SAFE"),
    ("from os import environ\nenviron |= {'A': 'b'}", "SAFE"),
    ("import os\nfrom sys import argv\nargv += ['x']\nos.system(' '.join(argv))",
     "VULNERABLE"),
    ("from os import environ\nenviron |= {'A': 'b'}\neval(environ['A'])",
     "VULNERABLE"),
])
def test_augmented_assignment_to_imported_source(analyzer, code, status):
    """x += ... on an imported source name is analysed, not a crash."""
    result = analyzer.analyze(code)
    assert result["status"] == status, code


def test_relative_star_import_binds_no_source(analyzer):
    """A relative star import names no known module."""
    _assert_safe(analyzer, "from . import *\nx = 'ls'\neval(x)")


def test_imported_source_is_named_by_its_full_name(analyzer):
    """sources_found names an imported source by its module path."""
    result = analyzer.analyze(
        "import os\nfrom os import environ\nc = environ.get('X')\nos.system(c)"
    )
    assert result["sources_found"][0]["name"] == "os.environ.get"
    assert result["sources_found"][0]["variable"] == "c"


def test_get_on_another_module_is_not_a_source(analyzer):
    """environ from some other module is not os.environ."""
    _assert_safe(
        analyzer,
        "import os\nfrom settings import environ\nos.system(environ.get('X'))",
    )


def test_shell_input_and_env_keywords_are_inspected(analyzer):
    """input= feeds a shell script; env= can set LD_PRELOAD."""
    for code in (
        'import subprocess\nx = input()\nsubprocess.run(["bash"], input=x)',
        'import subprocess\nx = input()\n'
        'subprocess.run(["ls"], env={"LD_PRELOAD": x})',
        "import os, subprocess\nx = input()\n"
        "subprocess.run(['ls'], env=dict(os.environ, X=x))",
        # os is not imported here, so os.environ is not known to be it.
        "import subprocess\nsubprocess.run(['ls'], env=os.environ.copy())",
        # Reflection anywhere: no passthrough exemption either.
        "import os, subprocess\nsetattr(os, 'environ', {})\n"
        "subprocess.run(['ls'], env=os.environ)",
    ):
        _assert_vulnerable(analyzer, code)

    for code in (
        "import os, subprocess\nsubprocess.run(['ls'], env=os.environ)",
        "import os, subprocess\nsubprocess.run(['ls'], env=os.environ.copy())",
        "import subprocess\nx = input()\n"
        "subprocess.run(['ls'], check=True, timeout=float(x), text=True)",
    ):
        _assert_safe(analyzer, code)


def test_unlisted_keywords_are_inspected(analyzer):
    """An allowlist of safe keywords: anything else is inspected."""
    for code in (
        "import requests\nu = input()\n"
        "requests.get('https://x.example', proxies={'https': u})",
        "q = input()\ncursor.execute(statement=q)",
        "q = input()\ncursor.execute(**{'query': q})",
    ):
        _assert_vulnerable(analyzer, code)
    _assert_safe(
        analyzer,
        "import requests\nq = input()\n"
        "requests.get('https://x.example', params={'q': q}, timeout=5)",
    )


@pytest.mark.parametrize("read", [
    "request.path",
    "request.full_path",
    "request.url",
    "request.body",
    'request.META["HTTP_X"]',
    "request.query_string",
    "request.method",
    "request.args.to_dict()",
    "self.request.path",
    "flask.request.url",
])
def test_every_request_attribute_read_is_a_source(analyzer, read):
    """Any request.<attr> read is a source, request.method included."""
    _assert_vulnerable(analyzer, f'import os\nos.system("ls " + {read})')
    _assert_vulnerable(analyzer, f"import os\nv = {read}\nos.system(v)")


def test_urllib_request_is_not_a_request_source(analyzer):
    """urllib.request.urlopen is a sink, not a request read."""
    _assert_safe(
        analyzer,
        "import urllib.request\nurllib.request.urlopen('https://x.example')",
    )


@pytest.mark.parametrize("length", [99, 100, 101, 250])
def test_reverse_assignment_chain_reaches_fixed_point(analyzer, length):
    """No pass limit: a long chain written in reverse order inside a loop."""
    lines = ["import os"] + [f"v{i} = ''" for i in range(length, -1, -1)]
    lines.append("while True:")
    lines += [f"    v{i} = v{i - 1}" for i in range(length, 0, -1)]
    lines += ["    v0 = input()", f"    os.system(v{length})"]
    result = analyzer.analyze("\n".join(lines))
    assert result["status"] == "VULNERABLE"
    assert result["vulnerabilities"][0]["source"]["variable"] == "v0"


def test_long_augmented_assignment_chain(analyzer):
    """Many += on one variable keep its taint (and stay linear in size)."""
    lines = ["import os", "y = ''", "y += input()"] + ["y += 'a'"] * 500
    lines.append("os.system(y)")
    result = analyzer.analyze("\n".join(lines))
    assert result["status"] == "VULNERABLE"


def test_inline_source_call_is_reported_once(analyzer):
    """os.system(request.args.get("c")) is one finding, not two."""
    result = analyzer.analyze('import os\nos.system(request.args.get("c"))')
    assert result["status"] == "VULNERABLE"
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["source"]["name"] == "request.args.get"


def test_source_found_through_intermediate_variables(analyzer):
    """A finding names the source behind a chain of assignments."""
    result = analyzer.analyze(
        'import os\ny = "ls " + input()\nz = y\nos.system(z)'
    )
    assert result["status"] == "VULNERABLE"
    source = result["vulnerabilities"][0]["source"]
    assert source["name"] == "input"
    assert source["variable"] == "<direct:input>"


def test_tainted_name_without_source_is_still_reported(analyzer, monkeypatch):
    """Fail closed: no source found for a tainted variable is still a finding."""
    monkeypatch.setattr(analyzer, "_source_for", lambda _var: None)
    result = analyzer.analyze("import os\nx = input()\ny = x\nos.system(y)")
    assert result["status"] == "VULNERABLE"
    source = result["vulnerabilities"][0]["source"]
    assert source["name"] == "<unknown>"
    assert source["variable"] == "y"


@pytest.mark.parametrize("code", [
    'mark_safe("<p>%y</p>" % html.escape(x))',
    'mark_safe("<p>%*s</p>" % (5, html.escape(x)))',
    'mark_safe("<p>{</p>".format(html.escape(x)))',
    'mark_safe("<p>{v}</p>".format(v=html.escape(x)))',
    'mark_safe("<p>{:{}}</p>".format(html.escape(x), 5))',
    'mark_safe("<p>%s %s</p>" % (html.escape(x),))',
    'mark_safe("<p>%s</p>" % (*[html.escape(x)],))',
    'mark_safe("<p>{} {}</p>".format(html.escape(x)))',
    'mark_safe(b"<p>" + html.escape(x))',
])
def test_templates_that_cannot_be_followed_give_no_relief(analyzer, code):
    """A template that is malformed or not plain is not a direct position."""
    _assert_vulnerable(analyzer, "import html\nx = input()\n" + code)


def test_template_starting_with_a_field_keeps_relief(analyzer):
    """A plain field first in the template is still a direct position."""
    _assert_safe(
        analyzer,
        'import html\nx = input()\nmark_safe("{}</p>".format(html.escape(x)))',
    )


def test_assignment_forms_carry_taint(analyzer):
    """Annotated assignment and named expressions carry taint."""
    for code in (
        "import os\nx: str = input()\nos.system(x)",
        "import os\nif (x := input()):\n    os.system(x)",
        "import os\nos.system((y := input()))",
        "import os\nx: str\nx = input()\nos.system(x)",
    ):
        _assert_vulnerable(analyzer, code)


def test_untracked_targets_do_not_break_analysis(analyzer):
    """Attribute and subscript targets are not tracked, but do not fail."""
    result = analyzer.analyze(
        "import os\nd = {}\nself.cmd = input()\nd['k'] += input()\n"
        "n: int = 5\nos.system('ls')"
    )
    assert result["status"] == "SAFE"


def test_reads_with_no_dotted_name(analyzer):
    """A call with no dotted name is neither a source nor a sanitiser."""
    _assert_safe(analyzer, "import os\nos.system((lambda: 'ls')())")
    assert analyzer._check_source_call(ast.Name(id="input", ctx=ast.Load())) is None
    assert analyzer._source_for("never_assigned") is None


def test_case_mapping_without_rest_binds_nothing(analyzer):
    """`case {"k": 1}` binds no name, so html stays the imported module."""
    _assert_safe(
        analyzer,
        "import html\nmatch v:\n    case {'k': 1}:\n        pass\n"
        "x = input()\nmark_safe(html.escape(x))",
    )


def test_store_through_a_call_ends_relief(analyzer):
    """An attribute stored through a call result may patch a sanitiser."""
    _assert_vulnerable(
        analyzer,
        "import html\nget_html().escape = str\nx = input()\n"
        "mark_safe(html.escape(x))",
    )


def test_same_source_twice_in_one_argument_is_one_finding(analyzer):
    """One sink argument reading the same tainted variable twice."""
    result = analyzer.analyze("import os\nx = input()\nos.system(x + x)")
    assert len(result["vulnerabilities"]) == 1
