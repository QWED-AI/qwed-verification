"""#534: CodeVerifier reads the critical builtins as names, not substrings.

The line scan matched ``exec``, ``eval`` and ``compile`` anywhere in a line,
so ``cur.execute(...)``, ``model.evaluate(x)`` and ``re.compile(...)`` were
refused as ``dangerous_function``. The builtins are now matched on the AST:
as names, as attributes (the object may be the builtins module reached
another way) and in strings, with ``re.compile`` on an imported ``re`` the
one attribute admitted.
"""

import pytest

from qwed_new.core.code_verifier import CodeVerifier


def _verify(code):
    fields = CodeVerifier().verify_code(code, "python").developer_fields
    return fields["is_valid"], [(issue["type"], issue["pattern"]) for issue in fields["issues"]]


@pytest.mark.parametrize("code", [
    'cur.execute("SELECT ?", params)',
    'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))',
    'import re\npat = re.compile(r"[0-9]+")',
    "score = model.evaluate(x)",
    "def compile_report():\n    return 1\ncompile_report()",
    'import re as r\np = r.compile("a+")',
    "# we never call eval here\nx = 1",
    "my_getattr_helper = 1",
    "from ast import literal_eval\nvalue = literal_eval(s)",
])
def test_code_that_only_names_a_longer_identifier_is_admitted(code):
    assert _verify(code) == (True, [])


@pytest.mark.parametrize(("code", "pattern"), [
    ("exec(x)", "exec"),
    ("eval(x)", "eval"),
    ('compile(x, "f", "exec")', "compile"),
    ('__import__("json")', "__import__"),
    ("getattr(o, name)", "getattr"),
    ("setattr(o, name, v)", "setattr"),
    # Not called, but bound to another name.
    ("f = eval\nf(x)", "eval"),
    # Through the builtins module, or an import of it.
    ("import builtins\nbuiltins.exec(x)", "builtins"),
    ("import builtins as b\nb.exec(x)", "builtins"),
    ("from builtins import exec as run\nrun(x)", "exec"),
    ("from builtins import *\neval(x)", "eval"),
    # The builtins module reached without importing it.
    ("print.__self__.exec(payload)", "exec"),
    ('vars(print.__self__)["exec"](payload)', "exec"),
    ('print.__self__.compile(payload, "", "exec")', "compile"),
    # re.compile is admitted only on an imported re that is never rebound.
    ('re = print.__self__\nre.compile(payload, "", "exec")', "compile"),
    ('import re\nre = print.__self__\nre.compile(payload, "", "exec")', "compile"),
    ('import re\ndef f(re):\n    return re.compile(p, "", "exec")', "compile"),
    ('import re\nimport builtins as re\nre.compile(p, "", "exec")', "compile"),
    # ... or rebound through a namespace dict, or by setting re.compile.
    ('import re\nglobals()["re"] = m\nre.compile(p, "<s>", "single")', "compile"),
    ('import re\nglobals().update(re=m)\nre.compile(p, "<s>", "single")', "compile"),
    ('import re\nimport sys\nsys._getframe().f_globals["re"] = m\nre.compile(p, "", "single")', "compile"),
    ('import re\nfrom helpers import *\nre.compile(p, "", "single")', "compile"),
    ('import re\nre.compile = f\nre.compile(p, "", "single")', "compile"),
    ('import re, sys\nsys.modules.get(__name__).re = m\nre.compile(p, "", "single")', "compile"),
    ('import re, __main__\n__main__.re = m\nre.compile(p, "", "single")', "compile"),
    # Setting compile on the re module is itself an attribute named compile.
    ('import re, sys\nsys.modules.get("re").compile = f\nre.compile(p, "", "single")', "compile"),
    # The builtin read as an attribute by a match pattern or a from-import.
    ("match m:\n    case object(exec=run):\n        run(payload)", "exec"),
    ("match m:\n    case object(eval=run):\n        run(payload)", "eval"),
    ("match m:\n    case object(compile=run):\n        run(payload)", "compile"),
    ("match m:\n    case object(getattr=run):\n        run(payload)", "getattr"),
    ("from helpers import exec as run\nrun(payload)", "exec"),
    # A bare name is the builtin whatever an import elsewhere binds to it:
    # imports are not scoped or ordered here.
    ('from re import compile\np = compile("a+")', "compile"),
    ("exec(input())\nfrom re import compile as exec", "exec"),
    ("def f():\n    from re import compile as eval\neval(payload)", "eval"),
    ("def f():\n    import math as exec\nexec(payload)", "exec"),
    ("from builtins import exec as run\ndef f():\n    from json import loads as run\nrun(payload)", "exec"),
    # The builtins module reached through a builtin function, with the name split.
    ('vars(print.__self__)["ex" + "ec"](payload)', "__self__"),
    # getattr / setattr / delattr by their dunder names.
    ("m.__getattribute__(n)(payload)", "__getattribute__"),
    ("object.__getattribute__(m, n)(payload)", "__getattribute__"),
    ("m.__getattr__(n)(payload)", "__getattr__"),
    ("m.__setattr__(n, v)", "__setattr__"),
    ("m.__delattr__(n)", "__delattr__"),
    # Longer names that also run or compile code, or look it up by name.
    ("import six\nsix.exec_(src)", "exec_"),
    ("from six import exec_\nexec_(src)", "exec_"),
    ("spec.loader.exec_module(mod)", "exec_module"),
    ("import codeop\nc = codeop.compile_command(src)", "compile_command"),
    ("import inspect\nf = inspect.getattr_static(m, n)", "getattr_static"),
    # Code that does not parse is scanned for whole identifiers.
    ("exec(x", "exec"),
])
def test_the_critical_builtins_are_still_refused(code, pattern):
    is_valid, issues = _verify(code)

    assert is_valid is False
    assert pattern in {issue_pattern for issue_type, issue_pattern in issues
                       if issue_type in {"dangerous_function", "dangerous_attribute"}}


def test_code_that_does_not_parse_is_not_read_by_substring():
    assert ("dangerous_function", "exec") not in _verify("cur.execute(x")[1]
