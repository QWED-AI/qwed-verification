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

from qwed_new.core import string_steps
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
    # the code names, so the table must cover the whole list.
    graph = string_steps.LiteralGraph
    assert set(string_steps._INTROSPECTION_MODULE_OBJECTS) == graph.INTROSPECTION_MODULES
    assert "get_annotations" in string_steps.module_exports("inspect")
    assert string_steps.module_exports("os") == frozenset()
