"""#534: CodeVerifier reads the critical builtins as names, not substrings.

The line scan matched ``exec``, ``eval`` and ``compile`` anywhere in a line,
so ``cur.execute(...)``, ``model.evaluate(x)`` and ``re.compile(...)`` were
refused as ``dangerous_function``. The builtins are now matched on the AST:
as names, as attributes (the object may be the builtins module reached
another way) and in strings, with ``re.compile(pattern, flags)`` on an
imported ``re`` the one attribute admitted. Python that does not parse is
BLOCKED, since the AST checks cannot run on it.
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
    # Defining the dunder accessors is not reading them.
    "class Proxy:\n    def __getattr__(self, name):\n        return 1",
    "def __getattr__(name):\n    return 1",
    "# Proxy overrides __setattr__ here\nx = 1",
    # re.compile with its flags, by position or keyword, beside sys.
    'import re\np = re.compile(r"a+", re.I)',
    'import re\np = re.compile(pattern=r"a+", flags=re.I)',
    'import re, sys\nprint(sys.argv)\np = re.compile(r"a+")',
    # The names inside longer words in strings, docstrings and formatted text.
    'cur.execute("SELECT * FROM evaluations WHERE id = ?", (uid,))',
    'print("executing job")',
    'def score():\n    """Re-evaluates the score."""\n    return 1',
    'status = "recompiled"',
    'print("executing " + job)',
    'print("evaluations: {}".format(n))',
    # ... and reshaped, where the result leaves no name.
    'log.info("executing %s" % job)',
    'msg = "evaluations: %d" % n',
    'parts = "executed,ok".split(",")',
    'cur.execute("SELECT * FROM evaluations WHERE id = %s" % uid)',
    'sql = "SELECT * FROM evaluations WHERE id = %s"\ncur.execute(sql % uid)',
    'log.info("%(job)s: executing" % {"job": name})',
    'title = "Re-evaluated"[:5]',
    # Only % substitutes a conversion; + keeps "%s" as text.
    'label = "%sexec" + suffix',
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
    ('re = print.__self__\nre.compile(payload)', "compile"),
    ('import re\nre = m\nre.compile(p)', "compile"),
    ('import re\ndef f(re):\n    return re.compile(p)', "compile"),
    ('import re\nimport builtins as re\nre.compile(p)', "compile"),
    # ... or rebound through a namespace dict, or by setting re.compile.
    ('import re\nglobals()["re"] = m\nre.compile(p)', "compile"),
    ('import re\nglobals().update(re=m)\nre.compile(p)', "compile"),
    ('import re\nimport sys\nsys._getframe().f_globals["re"] = m\nre.compile(p)', "compile"),
    ('import re\nfrom helpers import *\nre.compile(p)', "compile"),
    ('import re\nre.compile = f\nre.compile(p)', "compile"),
    ('import re, sys\nsys.modules.get(__name__).re = m\nre.compile(p)', "compile"),
    ('import re, __main__\n__main__.re = m\nre.compile(p)', "compile"),
    # ... or supplied by the import system before import re reads it.
    ('import sys\nsys.modules.update({"re": m})\nimport re\nre.compile(p)', "compile"),
    ('from sys import modules as cache\ncache.update(re=m)\nimport re\nre.compile(p)', "compile"),
    ('import sys\nsys.meta_path.insert(0, finder)\nimport re\nre.compile(p)', "compile"),
    ('import sys\nsys.path_hooks.insert(0, hook)\nimport re\nre.compile(p)', "compile"),
    ('import sys\nsys.path_importer_cache.clear()\nimport re\nre.compile(p)', "compile"),
    # Setting compile on the re module is itself an attribute named compile.
    ('import re, sys\nsys.modules.get("re").compile = f\nre.compile(p)', "compile"),
    # ... and only when called as re.compile(pattern, flags): the builtin
    # compile cannot run in that shape, whatever re turns out to be.
    ('import re\nre.compile(p, "<s>", "single")', "compile"),
    ('import re\nre.compile(p, filename="<s>")', "compile"),
    ('import re\nre.compile(*args)', "compile"),
    ('import re\nre.compile(**kwargs)', "compile"),
    ('import re\nc = re.compile\nc(p, "<s>", "single")', "compile"),
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
    # A literal holding the name inside a longer word, sliced, %-formatted
    # or stripped into it at runtime.
    ('vars(m)["xexec"[1:]](payload)', "exec"),
    ('get = vars(object)["x__getattribute__"[1:]]\nget(m, n)', "__getattribute__"),
    ('vars(m)["%sexec" % ""](payload)', "exec"),
    ('vars(m)["%(a)sexec" % d](payload)', "exec"),
    # A conversion may become a separator, not only nothing.
    ('vars(m)["a%sexec" % sep](payload)', "exec"),
    ('vars(m)["xexec".lstrip("x")](payload)', "exec"),
    ('vars(m)["xexec"[-4:]](payload)', "exec"),
    ('vars(m)["qexecq".replace("q", "")](payload)', "exec"),
    ('vars(m)["qexec".split("q")[1]](payload)', "exec"),
    # A %-format mapping key may nest parentheses.
    ('get = vars(object)["%(a(b))s__getattribute__" % keys]', "__getattribute__"),
    # Steps chained, or a method saved and called later.
    ('vars(m)["xexecx"[1:][:-1]](payload)', "exec"),
    ('vars(m)["xexecx".lstrip("x").rstrip("x")](payload)', "exec"),
    ('vars(m)[("x%sexecx" % "")[1:5]](payload)', "exec"),
    ('strip = "x__getattribute__".lstrip\nget = vars(object)[strip("x")]', "__getattribute__"),
    # ... or assigned to a name first, through other names and steps.
    ('name = "xexec"\nvars(m)[name[1:]](payload)', "exec"),
    ('name: str = "xexec"\nvars(m)[name.lstrip("x")](payload)', "exec"),
    ('a = "xexec"\nb = a\nc = b\nvars(m)[c[1:]](payload)', "exec"),
    ('s = "xxexec"\nt = s[1:]\nvars(m)[t[1:]](payload)', "exec"),
    ('s = "x%sexec" % ""\nvars(m)[s[1:]](payload)', "exec"),
    ('fmt = "%sexec"\nvars(m)[fmt % ""](payload)', "exec"),
    ('t = "xexec"[0:]\nvars(m)[t[1:]](payload)', "exec"),
    ('fmt = "%sexecute"[:6]\nvars(m)[fmt % ""](payload)', "exec"),
    # Conversion flags, and a format the reader cannot parse.
    ('vars(m)["%-sexec" % ""](payload)', "exec"),
    ('vars(m)["%(xexec" % d](payload)', "exec"),
    ('fmt = "%(xexec"\nvars(m)[fmt % d](payload)', "exec"),
    # Where the arguments are not literals, the literal is matched anywhere.
    ('vars(m)["xexec".lstrip(c)](payload)', "exec"),
    ('vars(m)["xexec"[i:]](payload)', "exec"),
    ('vars(m)["xexec".translate(table)](payload)', "exec"),
    # The longest name a string holds is the one reported.
    ('vars(m)["exec_module"](spec)', "exec_module"),
    # getattr / setattr / delattr by their dunder names.
    ("m.__getattribute__(n)(payload)", "__getattribute__"),
    ("object.__getattribute__(m, n)(payload)", "__getattribute__"),
    ("m.__getattr__(n)(payload)", "__getattr__"),
    ("m.__setattr__(n, v)", "__setattr__"),
    ("m.__delattr__(n)", "__delattr__"),
    ('vars(object)["__getattribute__"](m, n)', "__getattribute__"),
    ("match m:\n    case object(__getattribute__=get):\n        get(n)", "__getattribute__"),
    # Longer names that also run or compile code, or look it up by name.
    ("import six\nsix.exec_(src)", "exec_"),
    ("from six import exec_\nexec_(src)", "exec_"),
    ("spec.loader.exec_module(mod)", "exec_module"),
    ("import codeop\nc = codeop.compile_command(src)", "compile_command"),
    ("import inspect\nf = inspect.getattr_static(m, n)", "getattr_static"),
    ("loop.subprocess_exec(proto, prog)", "subprocess_exec"),
    ("loop.subprocess_shell(proto, cmd)", "subprocess_shell"),
    ("from asyncio.subprocess import create_subprocess_exec as spawn\nspawn(prog)", "create_subprocess_exec"),
    ("from asyncio.subprocess import create_subprocess_shell as spawn\nspawn(cmd)", "create_subprocess_shell"),
    ("from _posixsubprocess import fork_exec as spawn\nspawn(args)", "fork_exec"),
    ("import os\nos._execvpe(prog, args)", "_execvpe"),
    ("p._execute_child(args)", "_execute_child"),
    ("import multiprocessing\nmultiprocessing.set_executable(prog)", "set_executable"),
    ("import pdb\npdb.runeval(src)", "runeval"),
    ("tcl.evalfile(path)", "evalfile"),
    ("ref._evaluate(g, l)", "_evaluate"),
    ("import typing\ntyping._eval_type(ref, g, l)", "_eval_type"),
    ("from importlib._bootstrap import _exec\n_exec(spec, mod)", "_exec"),
    ("import _imp\n_imp.exec_dynamic(mod)", "exec_dynamic"),
    ("import _imp\n_imp.exec_builtin(mod)", "exec_builtin"),
    ("imp.load_compiled(name, path)", "load_compiled"),
    ("import codeop\ncodeop._compile(src, f, mode)", "_compile"),
    ("import codeop\ncodeop._maybe_compile(c, src, f, mode)", "_maybe_compile"),
    ("import dis\ndis._try_compile(src, name)", "_try_compile"),
    ("import zipimport\nzipimport._compile_source(path, src)", "_compile_source"),
    ("from importlib._bootstrap_external import _compile_bytecode\n_compile_bytecode(data)", "_compile_bytecode"),
    ("import compileall\ncompileall.compile_file(path)", "compile_file"),
    ("import compileall\ncompileall.compile_dir(path)", "compile_dir"),
    ("import compileall\ncompileall.compile_path()", "compile_path"),
    ("import pickle\npickle._getattribute(m, n)", "_getattribute"),
])
def test_the_critical_builtins_are_still_refused(code, pattern):
    is_valid, issues = _verify(code)

    assert is_valid is False
    assert pattern in {issue_pattern for issue_type, issue_pattern in issues
                       if issue_type in {"dangerous_function", "dangerous_attribute"}}


@pytest.mark.parametrize("code", ["exec(x", "cur.execute(x", "x = (", "def f(:\n    pass", "x = 1\x00"])
def test_python_that_does_not_parse_is_blocked(code):
    # The AST checks cannot run on it, so it is not certified either way.
    result = CodeVerifier().verify_code(code, "python")

    assert result.status.value == "BLOCKED"
    assert result.developer_fields["constraint_id"] == "code_verifier.parse_error"
    assert result.developer_fields["is_valid"] is False
