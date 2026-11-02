"""#534: CodeVerifier reads the critical builtins as names, not substrings.

The line scan matched ``exec``, ``eval`` and ``compile`` anywhere in a line,
so ``cur.execute(...)``, ``model.evaluate(x)`` and ``re.compile(...)`` were
refused as ``dangerous_function``. The builtins are now matched on the AST:
as names, as attributes (the object may be the builtins module reached
another way) and in strings, with ``re.compile(pattern, flags)`` on an
imported ``re`` the one attribute admitted. ``evaluate`` is read the same
way for Python 3.14's ``ForwardRef.evaluate()``, which runs its string, so
``model.evaluate(x)`` with one argument is refused and ``model.evaluate(x, y)``
admitted. Python that does not parse is BLOCKED, since the AST checks cannot
run on it.
"""

import sys

import pytest

from qwed_new.core import string_steps
from qwed_new.core.code_verifier import CodeVerifier


def _verify(code):
    fields = CodeVerifier().verify_code(code, "python").developer_fields
    return fields["is_valid"], [(issue["type"], issue["pattern"]) for issue in fields["issues"]]


@pytest.mark.parametrize("code", [
    'cur.execute("SELECT ?", params)',
    'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))',
    'import re\npat = re.compile(r"[0-9]+")',
    "score = model.evaluate(x, y)",
    "score = model.evaluate(x=X, y=Y)",
    "score = model.evaluate(ds, verbose=0)",
    # sys.modules is a dict, not callable: model.modules() is not it, nor is
    # a name of that name, which only an attribute read, a class pattern or
    # an import binds.
    'import re\nfor layer in model.modules():\n    pass\np = re.compile(r"[0-9]+")',
    'import re\nmodules = ["a", "b"]\np = re.compile(r"[0-9]+")',
    "def compile_report():\n    return 1\ncompile_report()",
    # The module's opening run of imports binds the modules installed.
    'import pandas as pd\nq = "SELECT * FROM evaluations"\ncur.execute(q)\nrows = pd.read_csv(path)\nprint(rows[1:])',
    'try:\n    import orjson as json\nexcept ImportError:\n    import json\nlabel = "evaluation"\nprint(json.loads(s)[1:])',
    'from os.path import *\nlabel = "evaluation"\nprint(name[1:])',
    "run(execute=True)",
    "def build(compiled=True):\n    return compiled",
    'import re as r\np = r.compile("a+")',
    "# we never call eval here\nx = 1",
    "my_getattr_helper = 1",
    "from ast import literal_eval\nvalue = literal_eval(s)",
    # def __getattr__ answers attribute reads (PEP 562 for a module), and
    # object has none: it is admitted wherever it is defined.
    "class Proxy:\n    def __getattr__(self, name):\n        return 1",
    "def __getattr__(name):\n    return 1",
    "def __dir__():\n    return []\ndef __getattr__(name):\n    return 1",
    "def make():\n    class Proxy:\n        def __getattr__(self, name):\n            return 1\n    return Proxy",
    "class C:\n    @cache\n    def __getattr__(self, name):\n        return 1",
    "class C:\n    try:\n        def __getattr__(self, name):\n            return 1\n    except Exception:\n        pass",
    "class C:\n    try:\n        from fast import Base\n    except ImportError:\n        def __getattr__(self, name):\n            return 1",
    "import sys\nif sys.version_info >= (3, 7):\n    def __getattr__(name):\n        return 1",
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
    'line = "executed,ok"\nparts = line.split(",")',
    'print(("executing " + job).upper())',
    'title = "Re-evaluated"[:5]',
    'print("%-10s|" % "executing")',
    # Only % substitutes a conversion; + keeps "%s" as text.
    'label = "%sexec" + suffix',
    # Prose that reaches an index, or a cut between words, leaves no name.
    'rows = cur.execute("SELECT name FROM evaluations").fetchall()\nfor r in rows:\n    print(r[0])',
    'row = cur.execute("SELECT name FROM evaluations").fetchone()\nprint(row[0].strip())',
    'log.info("executing", line.split(",")[0].strip())',
    "names = sorted(xs, key=str.lower)",
    # ... and prose that cannot reach a cut is not matched.
    'import sys\nlog.info("executing %s", job)\nfor a in sys.argv[1:]:\n    print(a)',
    'def score(x):\n    """Re-evaluates the score."""\n    return x[1:]',
    'import sys\nclass Job:\n    def __repr__(self):\n        return "executing job"\nprint(sys.argv[1:])',
    'class Runner:\n    def __init__(self, path):\n        """Set up the evaluator."""\n        self.path = path\nprint(Runner("a").path[1:])',
    # Names in identifiers, where nothing reads them back as strings.
    'def run():\n    cur.execute("SELECT 1")\nif __name__ == "__main__":\n    run()\nprint(sys.argv[1:])',
    "import logging\nlog = logging.getLogger(__name__)\ncur.execute(q)\nprint(args.path[1:])",
    "class Runner:\n    def execute(self):\n        return 1\nprint(Runner().items[1:])",
    # Common words are introspection only when an introspection module
    # gives them.
    'cur.execute("SELECT a, b FROM t")\nfields = [d[0] for d in cur.description]\nprint(fields[1:])',
    'cur.execute("x")\nexception = get()\nprint(exception[1:])',
    'cur.execute("x")\nsignature = get()\nprint(signature[1:])',
    'cur.execute("x")\nprint(form.fields[1:])',
    'from sys import argv\ncur.execute("x")\nprint(argv[1:])',
    # A precision cuts what a format inserts, not the format's own text.
    'print(f"evaluated {score:.2f}")',
    'print("evaluated %.2f" % score)',
    'print("evaluated {:.2f}".format(score))',
    'print(f"executing {job}")',
    # A number on the left of % is arithmetic; a regex or a search API on
    # text that holds no name is not a match, nor is a regex helper that
    # removes nothing.
    'n = len("executing")\nprint(100 % n)',
    'from sys import exit\nexit("execution failed")',
    'import re\nprint(re.sub(r"\\s+", " ", text))\nprint("executing")',
    'res = es.search(index="evaluations")',
    'from re import escape as quote\nprint(quote("executing"))',
    # A star import of an introspection module seeds its introspection
    # names only, and only where they are read as names.
    "from dataclasses import *\ndef compile_report():\n    return 1\nprint(value[1:])",
    "from dataclasses import *\ncur.execute(q)\nprint(form.fields[1:])",
    "from dataclasses import fields\nprint(fields(C))\ncur.execute(q)\nprint(form.fields[1:])",
    # A call through a table reaches functions read as values, not every one.
    'handlers = {"a": print}\nhandlers["a"]("executing")\ndef parse(line):\n    return line[1:]\nparse(x)',
    # A replace that grows the text a little is worked out.
    'msg = "executing job"\nprint(msg.replace("job", "task"))',
    # A step that overflows is not worked out, and does not fail the check.
    'parts = "a,b".split(",", 100000000000000000000000000000)',
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
    ('import re\nns.vars()["re"] = m\nre.compile(p)', "compile"),
    # A class pattern reads an attribute too, without an Attribute node.
    ('import sys\nmatch sys:\n    case object(modules=cache):\n        cache.update(re=m)\nimport re\nre.compile(p)', "compile"),
    ('import re\nmatch ns:\n    case object(vars=v):\n        v()["re"] = m\nre.compile(p)', "compile"),
    ('import sys\ns = "abc"\nmatch sys._getframe():\n    case object(f_globals=g):\n        g["s"] = "xexec"\nvars(m)[s[1:]](payload)', "exec"),
    ('s = "abc"\nmatch ns:\n    case object(vars=v):\n        v()["s"] = "xexec"\nvars(m)[s[1:]](payload)', "exec"),
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
    # Case changes, str() and + carry the value to the next step.
    ('vars(m)["xexec".upper().lower()[1:]](payload)', "exec"),
    ('vars(m)[str("xexec")[1:]](payload)', "exec"),
    ('vars(m)[("xexe" + "c")[1:]](payload)', "exec"),
    ('vars(m)["EXEC".lower()](payload)', "exec"),
    ('vars(m)["ex" + "ec"](payload)', "exec"),
    ('vars(m)[("xexec" + suffix)[1:5]](payload)', "exec"),
    # ... or assigned to a name first, through other names and steps.
    ('name = "xexec"\nvars(m)[name[1:]](payload)', "exec"),
    ('name: str = "xexec"\nvars(m)[name.lstrip("x")](payload)', "exec"),
    ('a = "xexec"\nb = a\nc = b\nvars(m)[c[1:]](payload)', "exec"),
    ('s = "xxexec"\nt = s[1:]\nvars(m)[t[1:]](payload)', "exec"),
    ('s = "x%sexec" % ""\nvars(m)[s[1:]](payload)', "exec"),
    ('fmt = "%sexec"\nvars(m)[fmt % ""](payload)', "exec"),
    ('t = "xexec"[0:]\nvars(m)[t[1:]](payload)', "exec"),
    # A name bound more than once is not worked out from any one binding.
    ('s = "xexec"\ns = "ok"\nvars(m)[s[1:]](payload)', "exec"),
    ('fmt = "%sexecute"[:6]\nvars(m)[fmt % ""](payload)', "exec"),
    # Conversion flags, and a format the reader cannot parse.
    ('vars(m)["%-sexec" % ""](payload)', "exec"),
    ('vars(m)["%(xexec" % d](payload)', "exec"),
    ('fmt = "%(xexec"\nvars(m)[fmt % d](payload)', "exec"),
    # Where the arguments are not literals, the literal is matched anywhere.
    ('vars(m)["xexec".lstrip(c)](payload)', "exec"),
    ('vars(m)["xexec"[i:]](payload)', "exec"),
    ('vars(m)["xexec".translate(table)](payload)', "exec"),
    # ... and so is a value an earlier step worked out, or one a saved case
    # method or str.method gives.
    ('vars(m)[("xex" + "ec")[i:]](payload)', "exec"),
    ('vars(m)["XEXEC".lower()[i:]](payload)', "exec"),
    # Cutting on word characters can leave a whole name; on others, not.
    ('w = ("qexec",)[0]\nvars(m)[w.split("q")[1]](payload)', "exec"),
    ('w = ("xexec",)[0]\nvars(m)[w.lstrip("x")](payload)', "exec"),
    ('low = "EXEC".lower\nvars(m)[low()](payload)', "exec"),
    ('vars(m)[str.lower("EXEC")](payload)', "exec"),
    # partition and rpartition give a tuple.
    ('a, b, c = "qexec".partition("q")\nvars(m)[c](payload)', "exec"),
    ('a, b, c = "execq".rpartition("q")\nvars(m)[a](payload)', "exec"),
    ('for part in "qexec".partition("q"):\n    vars(m)[part](payload)', "exec"),
    # A %-format with literal arguments is worked out; without, a conversion
    # may also become nothing, and a precision cuts what it inserts.
    ('vars(m)["ex%sec" % ""](payload)', "exec"),
    ('vars(m)["ex%sec" % sep](payload)', "exec"),
    ('vars(m)["%.4s" % "execute"](payload)', "exec"),
    ('w = ("execute",)[0]\nvars(m)["%.4s" % w](payload)', "exec"),
    ('vars(m)["%c%c%c%c" % (101, 120, 101, 99)](payload)', "exec"),
    ('vars(m)["%(a)s%(b)s" % {"a": "ex", "b": "ec"}](payload)', "exec"),
    # str.format, format() and f-strings are read the same way.
    ('vars(m)["{:.4}".format("execute")](payload)', "exec"),
    ('vars(m)["ex{}ec".format("")](payload)', "exec"),
    ('vars(m)["{a:.4}".format_map({"a": "execute"})](payload)', "exec"),
    ('vars(m)[format("execute", ".4")](payload)', "exec"),
    ("vars(m)[f\"{'execute':.4}\"](payload)", "exec"),
    ("vars(m)[f\"ex{''}ec\"](payload)", "exec"),
    ('w = ("execute",)[0]\nvars(m)[f"{w:.4}"](payload)', "exec"),
    # A format's own text, its fields joined, can leave a name for a later
    # step; and %c or %x insert letters, whatever number they are given.
    ('vars(m)[("xex%sec" % sep)[1:]](payload)', "exec"),
    ('vars(m)["xex{}ec".format(sep)[1:]](payload)', "exec"),
    ('vars(m)[f"xex{sep}ec"[1:]](payload)', "exec"),
    ('s = "%cexec"\ns = s\nvars(m)[(s % 32).strip()](payload)', "exec"),
    ('vars(m)[(("%cexec" if c else "q") % 32).strip()](payload)', "exec"),
    # An index that is not a literal may be a slice object.
    ('vars(m)["xexec"[slice(1, None)]](payload)', "exec"),
    ('s = slice(1, None)\nvars(m)["xexec"[s]](payload)', "exec"),
    # A literal that reaches the step any other way is matched anywhere:
    # bound by unpacking, +=, a loop, a default, an argument, a match or an
    # exception, returned, or as a docstring ...
    ('a, b = "xexec", 1\nvars(m)[a[1:]](payload)', "exec"),
    ('s = "xexecx"\ns += "x"\nvars(m)[s[1:-2]](payload)', "exec"),
    ('s = "q"\ns += "xexec"\nvars(m)[s[2:]](payload)', "exec"),
    ('for s in ["xexec"]:\n    vars(m)[s[1:]](payload)', "exec"),
    ('[vars(m)[s[1:]](payload) for s in ["xexec"]]', "exec"),
    ('def f(s="xexec"):\n    return vars(m)[s[1:]](payload)', "exec"),
    ('def f(s):\n    return vars(m)[s[1:]](payload)\nf("xexec")', "exec"),
    ('list(map(lambda s: vars(m)[s[1:]](payload), ["xexec"]))', "exec"),
    ('f = lambda s: vars(m)[s[1:]](payload)\nf("xexec")', "exec"),
    # ... or a call whose function is not named: through a table or a factory.
    ('ops = {"cut": lambda s: vars(m)[s[1:]](payload)}\nops["cut"]("xexec")', "exec"),
    ('def make():\n    return lambda s: vars(m)[s[1:]](payload)\nmake()("xexec")', "exec"),
    ('def cut(s):\n    return vars(m)[s[1:]](payload)\nops = [cut]\nops[0]("xexec")', "exec"),
    ('def add(l):\n    l.append("xexec")\nitems = []\n[add][0](items)\nvars(m)[items[0][1:]](payload)', "exec"),
    ('class C:\n    def cut(self, s):\n        return vars(m)[s[1:]](payload)\nops = {"a": C().cut}\nops["a"]("xexec")', "exec"),
    ('class C:\n    @staticmethod\n    def cut(s):\n        return vars(m)[s[1:]](payload)\n[C.cut][0]("xexec")', "exec"),
    ("from inspect import *\ndef f(xexec: int):\n    pass\nvars(m)[list(get_annotations(f))[0][1:]](payload)", "exec"),
    ("from inspect import *\ndef f():\n    pass  # xexec\nvars(m)[getsource(f)[-6:-2]](payload)", "exec"),
    ('match "xexec":\n    case s:\n        vars(m)[s[1:]](payload)', "exec"),
    ('try:\n    raise ValueError("xexec")\nexcept ValueError as e:\n    vars(m)[str(e)[1:]](payload)', "exec"),
    ('def f():\n    return "xexec"\nvars(m)[f()[1:]](payload)', "exec"),
    ('def f():\n    """xexec"""\nvars(m)[f.__doc__[1:]](payload)', "exec"),
    ('import inspect\ndef f():\n    """xexec"""\nvars(m)[inspect.getdoc(f)[1:]](payload)', "exec"),
    ('"""xexec"""\nvars(m)[__doc__[1:]](payload)', "exec"),
    # ... held in an expression ...
    ('vars(m)[["xexec"][0][1:]](payload)', "exec"),
    ('vars(m)[{"k": "xexec"}["k"][1:]](payload)', "exec"),
    ('vars(m)[("xexec" if c else "")[1:]](payload)', "exec"),
    ('def ident(x):\n    return x\nvars(m)[ident("xexec")[1:]](payload)', "exec"),
    ('vars(m)[b"xexec".decode()[1:]](payload)', "exec"),
    ('vars(m)["abc".replace("b", "xexec")[2:6]](payload)', "exec"),
    # ... stored in an attribute, a container or a namespace ...
    ('o.s = "xexec"\nvars(m)[o.s[1:]](payload)', "exec"),
    ('@dataclass\nclass C:\n    s: str\nvars(m)[C("xexec").s[1:]](payload)', "exec"),
    ('class C:\n    def __init__(self, s):\n        global g\n        g = s\nC("xexec")\nvars(m)[g[1:]](payload)', "exec"),
    ('items = []\nitems.append("xexec")\nvars(m)[items[0][1:]](payload)', "exec"),
    ('a = []\nb = a\nb.append("xexec")\nvars(m)[a[0][1:]](payload)', "exec"),
    ('def add(l):\n    l.append("xexec")\nitems = []\nadd(items)\nvars(m)[items[0][1:]](payload)', "exec"),
    ('def add(l):\n    l.append("xexec")\nput = add\nitems = []\nput(items)\nvars(m)[items[0][1:]](payload)', "exec"),
    ('import heapq\nh = []\nheapq.heappush(h, "xexec")\nvars(m)[h[0][1:]](payload)', "exec"),
    ('globals()["s"] = "xexec"\nvars(m)[s[1:]](payload)', "exec"),
    ('d = globals()\nd["s"] = "xexec"\nvars(m)[s[1:]](payload)', "exec"),
    ('s = "xexecx"\nglobals()["s"] = s + "x"\nvars(m)[s[1:-2]](payload)', "exec"),
    # ... read back from the source as text: an exception's message quoting
    # a value or a name, a function's or class's name, a keyword, an Enum
    # member, the source itself, or the names in a namespace ...
    ('try:\n    int("xexec")\nexcept ValueError as e:\n    vars(m)[str(e)[-5:-1]](payload)', "exec"),
    ('try:\n    {}["xexec"]\nexcept KeyError as e:\n    vars(m)[str(e)[2:-1]](payload)', "exec"),
    ("try:\n    object().xexec\nexcept AttributeError as e:\n    vars(m)[str(e)[-5:-1]](payload)", "exec"),
    ("try:\n    xexec\nexcept NameError as e:\n    vars(m)[e.name[1:]](payload)", "exec"),
    ("def xexec():\n    pass\nvars(m)[xexec.__name__[1:]](payload)", "exec"),
    ("class xexec:\n    pass\nvars(m)[xexec.__qualname__[1:]](payload)", "exec"),
    ("vars(m)[list(dict(xexec=1))[0][1:]](payload)", "exec"),
    ("from enum import Enum\nclass E(Enum):\n    xexec = 1\nvars(m)[E.xexec.name[1:]](payload)", "exec"),
    ("import inspect\ndef f():\n    pass  # xexec\nvars(m)[inspect.getsource(f)[-6:-2]](payload)", "exec"),
    ("from inspect import getsource as read\ndef f():\n    cur.execute(q)\nvars(m)[read(f)[23:27]](payload)", "exec"),
    ("import traceback\ntry:\n    1/0  # xexec\nexcept Exception:\n    t = traceback.format_exc()\nvars(m)[t[-9:-5]](payload)", "exec"),
    ('xexec = 1\nvars(m)[[k for k in globals() if k.endswith("xec")][0][1:]](payload)', "exec"),
    ("class C:\n    xexec = 1\nvars(m)[dir(C)[-1][1:]](payload)", "exec"),
    ("from dataclasses import dataclass, fields\n@dataclass\nclass C:\n    xexec: int\nvars(m)[fields(C)[0].name[1:]](payload)", "exec"),
    ("from dataclasses import *\n@dataclass\nclass C:\n    xexec: int\nvars(m)[fields(C)[0].name[1:]](payload)", "exec"),
    ("import dataclasses\n@dataclasses.dataclass\nclass C:\n    xexec: int\nvars(m)[dataclasses.fields(C)[0].name[1:]](payload)", "exec"),
    ('import sys\ntry:\n    int("xexec")\nexcept ValueError:\n    vars(m)[str(sys.exception())[-5:-1]](payload)', "exec"),
    # ... the introspection module reached by another name or a lookup ...
    ("import dataclasses\nd = dataclasses\n@d.dataclass\nclass C:\n    xexec: int\nvars(m)[d.fields(C)[0].name[1:]](payload)", "exec"),
    ("import dataclasses as d\nalias = d\n@d.dataclass\nclass C:\n    xexec: int\nvars(m)[alias.fields(C)[0].name[1:]](payload)", "exec"),
    ('import importlib, dataclasses\n@dataclasses.dataclass\nclass C:\n    xexec: int\nvars(m)[importlib.import_module("dataclasses").fields(C)[0].name[1:]](payload)', "exec"),
    ('import sys\ns = sys\ntry:\n    int("xexec")\nexcept ValueError:\n    vars(m)[str(s.exception())[-5:-1]](payload)', "exec"),
    ('from sys import *\ntry:\n    int("xexec")\nexcept ValueError:\n    vars(m)[str(exception())[-5:-1]](payload)', "exec"),
    # ... or reshaped by a regex, however re is named ...
    ('import re\nvars(m)[re.sub("q", "", "qexec")](payload)', "exec"),
    ('from re import sub as s\nvars(m)[s("q", "", "qexec")](payload)', "exec"),
    ('from re import split as cut\nvars(m)[cut("q", "qexec")[1]](payload)', "exec"),
    ('import re as r\nvars(m)[r.split("^.", "xexec")[1]](payload)', "exec"),
    ('import re\nvars(m)[re.findall("e.*", "qexec")[0]](payload)', "exec"),
    ('import re as r\nvars(m)[r.search("e.*", "qexec").group()](payload)', "exec"),
    ('import regex\nvars(m)[regex.subf("q(.*)", "{1}", "qexec")](payload)', "exec"),
    ('import regex\nvars(m)[list(regex.splititer("q", "qexec"))[1]](payload)', "exec"),
    ('from importlib import import_module as im\nvars(m)[im("re").sub("q", "", "qexec")](payload)', "exec"),
    ('from importlib import import_module as im\nimport dataclasses\n@dataclasses.dataclass\nclass C:\n    xexec: int\nvars(m)[im("dataclasses").fields(C)[0].name[1:]](payload)', "exec"),
    ("from linecache import getline as gl\nimport sys\nline = gl(sys.argv[0], 4)\nvars(m)[line[4:8]](payload)\n# xexec", "exec"),
    # ... or returned by a dunder method a class (or its subclass) calls.
    ('class C:\n    def __getitem__(self, k):\n        return "xexec"\nvars(m)[C()[0][1:]](payload)', "exec"),
    ('class B:\n    def __str__(self):\n        return "xexec"\nclass C(B):\n    pass\nvars(m)[str(C())[1:]](payload)', "exec"),
    ('class C:\n    def __enter__(self):\n        return "xexec"\nwith C() as s:\n    vars(m)[s[1:]](payload)', "exec"),
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
    # Calls that evaluate string annotations as code.
    ("import typing\ntyping.evaluate_forward_ref(ref)", "evaluate_forward_ref"),
    ("from typing import get_type_hints as hints\ndef f(x: \"y\"):\n    pass\nhints(f)", "get_type_hints"),
    ("import typing\ntyping.get_type_hints(f)", "get_type_hints"),
    ("import inspect\ninspect.get_annotations(f, eval_str=True)", "eval_str"),
    ("from inspect import get_annotations\nget_annotations(f, eval_str=True)", "eval_str"),
    ("import inspect\ninspect.signature(f, eval_str=True)", "eval_str"),
    ("import inspect\ninspect.get_annotations(f, **{\"eval_str\": True})", "eval_str"),
    ("import inspect\ninspect.get_annotations(f, **dict(eval_str=True))", "eval_str"),
    ("import inspect\ndef g(eval_str=True):\n    return inspect.get_annotations(f, **locals())", "eval_str"),
    ("import inspect\nk = \"xeval_str\"[1:]\ninspect.get_annotations(f, **{k: True})", "eval_str"),
    ("import inspect\ndef g():\n    from math import pi as eval_str\n    return inspect.get_annotations(f, **locals())", "eval_str"),
    ("import inspect\ndef g():\n    import math as eval_str\n    return inspect.get_annotations(f, **locals())", "eval_str"),
    ("import inspect\ndef g():\n    import eval_str\n    return inspect.get_annotations(f, **locals())", "eval_str"),
    # Any of the names given as a keyword or bound other than by a Name is
    # read back as a string by introspection.
    ("vars(m)[list(dict(exec=1))[0]](payload)", "exec"),
    ("import inspect\ndef f(exec):\n    pass\nvars(m)[list(inspect.signature(f).parameters)[0]](payload)", "exec"),
    ("class C:\n    def exec(self):\n        pass\nvars(m)[[k for k in vars(C) if not k.startswith(\"_\")][0]](payload)", "exec"),
    ("class C:\n    async def eval(self):\n        pass", "eval"),
    ("class compile:\n    pass", "compile"),
    ("try:\n    pass\nexcept Exception as exec:\n    pass", "exec"),
    ("f = lambda getattr: 0", "getattr"),
    ("class C(Base, exec=1):\n    pass", "exec"),
    ("match x:\n    case [exec]:\n        pass", "exec"),
    ("match x:\n    case [*exec]:\n        pass", "exec"),
    ("match x:\n    case {**exec}:\n        pass", "exec"),
    # Keywords, and bindings other than a def or an import, with a name
    # refused only in strings (an accessor, or evaluate): introspection
    # reads them back the same way.
    ("vars(object)[list(dict(__getattribute__=1))[0]](obj, name)", "__getattribute__"),
    ("vars(object)[list(dict(__setattr__=1))[0]](obj, name, value)", "__setattr__"),
    ("vars(ForwardRef)[list(dict(evaluate=1))[0]](ref)", "evaluate"),
    ("def f(__getattribute__=1):\n    pass", "__getattribute__"),
    ("def train(evaluate=False):\n    pass", "evaluate"),
    ("f = lambda __setattr__: 0", "__setattr__"),
    # os.exec* by any reference, not only a call the process check resolves.
    ("from os import execv\nrun = execv\nrun(\"/bin/sh\", [\"sh\"])", "execv"),
    ("import os as o\nf = o.execvp\nf(\"sh\", [\"sh\"])", "execvp"),
    ("import os\nvars(os)[\"execve\"](\"/bin/sh\", [\"sh\"], {})", "execve"),
    # An object carries the name it was defined or imported under: a def
    # (unless an undecorated method or a PEP 562 hook), a decorator's
    # argument, a load of the name, and a module path.
    ("def evaluate():\n    pass\nfrom typing import ForwardRef\nr = ForwardRef(\"x\")\nvars(ForwardRef)[evaluate.__name__](r)", "evaluate"),
    ("def __getattribute__():\n    pass\nvars(object)[__getattribute__.__name__](obj, \"x\")", "__getattribute__"),
    ("def outer():\n    def evaluate():\n        pass\n    return evaluate.__name__", "evaluate"),
    ("async def __setattr__():\n    pass", "__setattr__"),
    ("if x:\n    def evaluate():\n        pass", "evaluate"),
    ("class C:\n    def run(self):\n        def evaluate():\n            pass", "evaluate"),
    ("class C:\n    def run(self):\n        if x:\n            def evaluate():\n                pass\n            return evaluate", "evaluate"),
    ("registry = []\ndef reg(f):\n    registry.append(f)\n    return f\nclass C:\n    @reg\n    def evaluate(self):\n        pass\nk = registry[0].__name__", "evaluate"),
    ("class C:\n    def evaluate(self):\n        pass\n    k = evaluate.__name__", "evaluate"),
    # A method's name too, read back through dir() or vars() on its class;
    # only __getattr__ is left out.
    ("class M:\n    def evaluate(self):\n        pass\nfrom typing import ForwardRef\nref = ForwardRef(\"print(1)\")\nkey = [k for k in dir(M) if not k.startswith(\"_\")][0]\nvars(ForwardRef)[key](ref)", "evaluate"),
    ("class P:\n    def __getattribute__(self, name):\n        pass\nkey = [k for k in vars(P) if k.endswith(\"attribute__\")][0]\nvars(object)[key](obj, \"x\")", "__getattribute__"),
    ("class Model:\n    def evaluate(self, x):\n        return x", "evaluate"),
    ("import sys\nclass Model:\n    if sys.version_info >= (3, 12):\n        def evaluate(self, x):\n            return x", "evaluate"),
    ("class P:\n    def __setattr__(self, name, value):\n        pass", "__setattr__"),
    ("class P:\n    def __delattr__(self, name):\n        pass", "__delattr__"),
    ("import pkg.exec as x\nvars(m)[x.__name__.split(\".\")[1]](payload)", "exec"),
    ("from pkg.exec import y\nvars(m)[y.__module__.split(\".\")[1]](payload)", "exec"),
    ("from .compile import y", "compile"),
    ("import evaluate\nfrom typing import ForwardRef\nvars(ForwardRef)[evaluate.__name__](ForwardRef(\"x\"))", "evaluate"),
    ("import evaluate as ev\nk = ev.__name__", "evaluate"),
    ("from evaluate import load\nk = load.__module__", "evaluate"),
    # An import after other code ran, or a module looked up by name, may give
    # a module the code made itself, holding any value it made.
    ("import sys, types\nsys.modules.update(m=types.SimpleNamespace(s=\"xexec\"))\ns = \"abc\"\nfrom m import *\nvars(x)[s[1:]](payload)", "exec"),
    ("import sys, types\nsys.modules.update(m=types.SimpleNamespace(s=\"xexec\"))\nfrom m import s\nvars(x)[s[1:]](payload)", "exec"),
    ("import sys, types\ndef xexec():\n    pass\nsys.modules.update(m=types.SimpleNamespace(s=xexec.__name__))\nfrom m import *\nvars(x)[s[1:]](payload)", "exec"),
    ("import sys, types\nsys.modules.update(m=types.SimpleNamespace(s=\"xexec\"))\nimport m\nvars(x)[m.s[1:]](payload)", "exec"),
    ("import sys, types\nsys.modules.update(m=types.SimpleNamespace(s=\"xexec\"))\ndef f():\n    from m import s\n    return vars(x)[s[1:]](payload)", "exec"),
    ("import sys\nsys.modules.update(m=type(\"M\", (), {\"s\": \"xexec\"}))\nfrom m import s\nvars(x)[s[1:]](payload)", "exec"),
    ("import sys, types, pkgutil\nsys.modules.update(m=types.SimpleNamespace(s=\"xexec\"))\nvars(x)[pkgutil.resolve_name(\"m:s\")[1:]](payload)", "exec"),
    ("import sys, types\nfrom pkgutil import resolve_name as rn\nsys.modules.update(m=types.SimpleNamespace(s=\"xexec\"))\nvars(x)[rn(\"m:s\")[1:]](payload)", "exec"),
    ("import sys, types\ntry:\n    import absent\nexcept (sys.modules.update(m=types.SimpleNamespace(s=\"xexec\")) or ImportError):\n    from m import s\nvars(x)[s[1:]](payload)", "exec"),
    # A regex call's pattern is matched like its other arguments. It can
    # reach what the call gives (a group name, .re.pattern, a replacement
    # function that stores the match), and re cannot be shown to be the
    # module: one the import system gives, or a function set on it, can do
    # the cut itself (operator.getitem in place of split).
    ("import re\nm = re.search(\"evaluation\", text)", "eval"),
    ("import sys, operator, types\nvars(sys)[\"modules\"].update(re=types.SimpleNamespace(split=operator.getitem))\nimport re\nvars(m)[re.split(\"xexec\", slice(1, None))](payload)", "exec"),
    ("import sys, types\nvars(sys)[\"modules\"].update(re=types.SimpleNamespace(split=str.lstrip))\nimport re\nvars(m)[re.split(\"xexec\", \"x\")](payload)", "exec"),
    ("import re\nvars(m)[list(re.search(\"(?P<xexec>.)\", \"a\").groupdict())[0][1:]](payload)", "exec"),
    ("import re\nvars(m)[re.search(\"a(?#xexec)\", \"a\").re.pattern[5:9]](payload)", "exec"),
    ("import re\nvars(m)[re.sub(\"a(?#xexec)\", lambda g: g.re.pattern, \"a\")[5:9]](payload)", "exec"),
    ("import re\nout = []\nre.sub(\"a(?#xexec)\", out.append, \"a\")\nvars(m)[out[0].re.pattern[5:9]](payload)", "exec"),
    ("import re\nout = []\nre.sub(pattern=\"a(?#xexec)\", repl=out.append, string=\"a\")\nvars(m)[out[0].re.pattern[5:9]](payload)", "exec"),
    ("from re import sub as s\nout = []\ns(\"a(?#xexec)\", out.append, \"a\")\nvars(m)[out[0].re.pattern[5:9]](payload)", "exec"),
    ("import re\nout = []\ndef keep(g):\n    out.append(g)\n    return \"\"\nre.sub(\"a(?#xexec)\", keep, \"a\")\nvars(m)[out[0].re.pattern[5:9]](payload)", "exec"),
    ("import re\nre = re.compile(\"^.\")\nvars(m)[re.split(\"xexec\")[1]](payload)", "exec"),
    ("import re\ndef g(re):\n    return vars(m)[re.split(\"xexec\")[1]](payload)", "exec"),
    ("from re import search\ndef search(s, t):\n    return s[1:]\nvars(m)[search(\"xexec\", \"\")](payload)", "exec"),
    ("import re\nre.split = lambda s, t: s[1:]\nvars(m)[re.split(\"xexec\", \"\")](payload)", "exec"),
    ("import re\nimport re as other\nother.split = lambda s, t: s[1:]\nvars(m)[re.split(\"xexec\", \"\")](payload)", "exec"),
    ("import re\nimport re as other\nout = []\ndef keep(p, s):\n    out.append(p)\nother.split = keep\nre.split(\"xexec\", \"\")\nvars(m)[out[0][1:]](payload)", "exec"),
    ("import re\nimport types\nout = []\ndef keep(p, s):\n    out.append(p)\nglobals()[\"re\"] = types.SimpleNamespace(split=keep)\nre.split(\"xexec\", \"\")\nvars(m)[out[0][1:]](payload)", "exec"),
    ("import re\nglobals()[\"re\"] = c\nvars(m)[re.split(\"xexec\", \"\")[0][1:]](payload)", "exec"),
    ("import re\nvars(m)[re.split(*[\"^.\", \"xexec\"])[1]](payload)", "exec"),
    # A function set on the module under a regex function's name, through any
    # alias or before a from-import, may store into its arguments.
    ("import re\nimport re as other\ndef keep(p, dest):\n    dest.append(p)\nother.search = keep\nitems = []\nre.search(\"xexec\", items)\nvars(m)[items[0][1:]](payload)", "exec"),
    ("import re\ndef keep(p, dest):\n    dest.append(p)\nre.search = keep\nfrom re import search as s\nitems = []\ns(\"xexec\", items)\nvars(m)[items[0][1:]](payload)", "exec"),
    # The import system can give import re another module, whose split is
    # a function of the code's own.
    ("import sys, types\nout = []\ndef keep(p, s):\n    out.append(p)\nsys.modules.update(re=types.SimpleNamespace(split=keep))\nimport re\nre.split(\"xexec\", \"\")\nvars(m)[out[0][1:]](payload)", "exec"),
    ("import types\nfrom sys import modules as cache\nout = []\ndef keep(p, s):\n    out.append(p)\ncache.update(re=types.SimpleNamespace(split=keep))\nimport re\nre.split(\"xexec\", \"\")\nvars(m)[out[0][1:]](payload)", "exec"),
    # Python 3.14's ForwardRef.evaluate(), in every shape it can be called in.
    ("from typing import List\nList[\"print(1)\"].__args__[0].evaluate()", "evaluate"),
    ("ref.evaluate(globals=g, owner=o)", "evaluate"),
    ("type(ref).evaluate(ref)", "evaluate"),
    ("type(ref).evaluate(self=ref)", "evaluate"),
    ("ForwardRef.evaluate(self=ref, globals=g)", "evaluate"),
    ("score = model.evaluate(x)", "evaluate"),
    ("model.evaluate(*args)", "evaluate"),
    ("model.evaluate(x, *rest)", "evaluate"),
    ("model.evaluate(x, y, **kw)", "evaluate"),
    ("f = model.evaluate", "evaluate"),
    ("import operator\noperator.methodcaller(\"evaluate\")(ref)", "evaluate"),
    ("import operator\noperator.methodcaller(\"xevaluate\"[1:])(ref)", "evaluate"),
    ("from m import evaluate\nevaluate(ref)", "evaluate"),
    ("match ref:\n    case C(evaluate=e):\n        e()", "evaluate"),
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


def test_star_exports_are_read_for_every_introspection_module():
    # The exports come from modules imported by name, never from a module
    # the code names, so the table must cover the whole list, and any other
    # module is an error rather than no exports.
    graph = string_steps.LiteralGraph
    assert set(string_steps._INTROSPECTION_MODULE_OBJECTS) == graph.INTROSPECTION_MODULES
    assert "get_annotations" in string_steps.module_exports("inspect")
    with pytest.raises(ValueError):
        string_steps.module_exports("os")


@pytest.mark.skipif(sys.version_info < (3, 12), reason="type parameters are new in Python 3.12")
@pytest.mark.parametrize("code", [
    "def f[exec]():\n    pass\nvars(m)[f.__type_params__[0].__name__](payload)",
    "class C[*eval]:\n    pass",
    "type Alias[**compile] = int",
])
def test_a_type_parameter_with_one_of_the_names_is_refused(code):
    is_valid, issues = _verify(code)

    assert is_valid is False
    assert {"exec", "eval", "compile"} & {pattern for _, pattern in issues}


@pytest.mark.skipif(sys.version_info < (3, 14), reason="ForwardRef.evaluate() is new in Python 3.14")
def test_forward_ref_evaluate_raises_on_the_admitted_shapes_before_running():
    # The shapes admitted for evaluate must fail on ForwardRef.evaluate before
    # its string runs, and the keyword list must match the real signature.
    import inspect
    import typing

    method = typing.ForwardRef.evaluate
    parameters = inspect.signature(method).parameters.values()
    # Every parameter can be given by keyword, self included, and none
    # collects extra arguments, so any other keyword raises.
    assert all(p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY) for p in parameters)
    assert {p.name for p in parameters} == CodeVerifier._FORWARD_REF_EVALUATE_KEYWORDS

    ran = []
    scope = {"ran": ran}
    ref = typing.ForwardRef("ran.append(1) or int")
    for call in (
        lambda: ref.evaluate(1, 2),
        lambda: ref.evaluate(x=1),
        lambda: ref.evaluate(globals=scope, verbose=0),
        lambda: method(ref, 1),
        lambda: method(self=ref, x=1),
    ):
        with pytest.raises(TypeError):
            call()
    assert ran == []
    method(self=ref, globals=scope)
    ref.evaluate(globals=scope)
    assert ran == [1, 1]
