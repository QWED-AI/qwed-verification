"""Python code may not read a name before it binds it (GHSA-7xrf).

CodeVerifier checked the modules code imports and the builtins it reads, but
not a name the code never binds. Run where that name is bound (a notebook, a
REPL, a program that runs the code with its own globals), such a read reaches
whatever the namespace holds: `secret = os.environ.get(...)` with no import
was VERIFIED · ADMIT. Now a read that can happen before the code binds the
name is refused, unless it is a builtin or a name the caller's runtime binds.

Nothing is executed except the generated programs in the property test,
which only assign integers, define and call functions, and read names.
"""

import ast
import builtins

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from qwed_new.core import code_names
from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.consensus_verifier import ConsensusVerifier
from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.secure_code_executor import SANDBOX_BOUND_NAMES, SecureCodeExecutor
from qwed_new.core.stats_verifier import StatsVerifier


def _unbound(code, bound=frozenset()):
    return sorted(finding["pattern"] for finding in code_names.findings(ast.parse(code), bound))


def _verdict(code, **kwargs):
    result = CodeVerifier(**kwargs).verify_code(code, language="python")
    return result.status.value, result.developer_fields.get("is_valid"), admission_decision(result).value


REFUSED = {
    "advisory": ("secret = os.environ.get('AWS_SECRET_ACCESS_KEY')", ["os"]),
    "bound_after_the_read": ("value = os.environ.get('X')\nos = None", ["os"]),
    "bound_only_in_a_function": ("def f():\n    os = 1\n\nos.environ.get('X')", ["os"]),
    "read_in_a_function": ("def f():\n    return os.getcwd()\n", ["os"]),
    "called_before_the_import": ("def f():\n    return os.getcwd()\n\nf()\nimport os", ["os"]),
    "handed_to_a_bound_name": ("alias = handle\nalias.close()", ["handle"]),
    "subscript": ("token = env['AWS']", ["env"]),
    "call": ("run('id')", ["run"]),
    "loop_variable_after_the_loop": ("for i in range(3):\n    pass\nprint(i)", ["i"]),
    "one_branch_binds": ("if True:\n    x = 1\nprint(x)", ["x"]),
    "try_body_binds_handler_does_not": ("try:\n    x = 1\nexcept Exception:\n    pass\nprint(x)", ["x"]),
    "with_body_binds": ("import contextlib\nwith contextlib.suppress(Exception):\n    x = 1\nprint(x)", ["x"]),
    "class_body_reads_before_binding": ("class A:\n    y = x\n    x = 1", ["x"]),
    "method_reads_the_module": ("class A:\n    def m(self):\n        return handle\n", ["handle"]),
    "decorator_can_call_it": (
        "def deco(f):\n    f()\n    return f\n\n@deco\ndef g():\n    return late\n\nlate = 1", ["late"]
    ),
    "lambda_called_before_binding": ("f = lambda: x\nf()\nx = 1", ["x"]),
    "generator_before_binding": ("g = (x for _ in range(1))\nx = 1", ["x"]),
    "comprehension_target_after": ("[z for z in range(3)]\nprint(z)", ["z"]),
    "class_names_hidden_in_comprehension": ("class A:\n    x = 1\n    y = [x for _ in range(2)]", ["x"]),
    "global_bound_by_a_call": ("def f():\n    global x\n    x = 1\n\nf()\nprint(x)", ["x"]),
    "augmented_assignment": ("x += 1", ["x"]),
    "delete": ("del handle", ["handle"]),
    "module_builtins_name": ("table = __builtins__", ["__builtins__"]),
    "method_runs_before_class_bound": ("class A:\n    def m(self):\n        return B\n\nA().m()\n\nclass B:\n    pass", ["B"]),
    "match_class": ("match value:\n    case Point():\n        pass", ["Point", "value"]),
    "walrus_in_a_branch": ("if 0 and (x := 1):\n    pass\nprint(x)", ["x"]),
    "nested_function": ("def outer():\n    def inner():\n        return handle\n    return inner\n", ["handle"]),
    "decorator_argument": ("import functools\n@functools.lru_cache(maxsize=size)\ndef f():\n    return 1\n", ["size"]),
    "base_runs_a_def_init_subclass": (
        "class A:\n    def __init_subclass__(cls):\n        return later\n\nclass B(A):\n    pass\n\nlater = 1", ["later"]
    ),
    "base_runs_an_assigned_init_subclass": (
        "def hook(cls):\n    return later\n\nclass A:\n    __init_subclass__ = hook\n\nclass B(A):\n    pass\n\n"
        "later = 1",
        ["later"],
    ),
    "decorator_given_a_name_can_call_it": (
        "def g(fn):\n    fn()\n\n@staticmethod(g)\ndef f():\n    return late\n\nlate = 1", ["late"]
    ),
    "with_target_after_a_swallowed_failure": (
        "import contextlib\nwith contextlib.suppress(Exception) as (x,):\n    pass\nprint(x)", ["x"]
    ),
    "class_in_a_function_reads_its_own_name_from_the_module": (
        "def f():\n    x = 1\n\n    class A:\n        y = x\n        x = 2\n\nf()", ["x"]
    ),
    "class_body_global_rebinds_a_base": (
        "class B:\n    pass\n\nclass E:\n    def __init_subclass__(cls):\n        return late\n\n"
        "class X:\n    global B\n    B = E\n\nclass C(B):\n    pass\n\nlate = 1",
        ["late"],
    ),
    "set_name_of_an_earlier_object": (
        "class D:\n    def __set_name__(self, owner, name):\n        owner.m()\n\nd = D()\n\n"
        "class C:\n    attr = d\n\n    @staticmethod\n    def m():\n        return late\n\nlate = 1",
        ["late"],
    ),
    "hash_in_a_set_display": (
        "class H:\n    def __hash__(self):\n        return f()\n\nh = H()\n\ndef f():\n    return late\n\n"
        "s = {h}\nlate = 1",
        ["f", "late"],
    ),
    "iteration_in_unpacking": (
        "class It:\n    def __iter__(self):\n        return iter([f(), 0])\n\nit = It()\n\n"
        "def f():\n    return late\n\na, b = it\nlate = 1",
        ["f", "late"],
    ),
    "augmented_assignment_of_a_global_in_a_function": (
        "def f():\n    global handle\n    handle += 1\n\nf()", ["handle"]
    ),
    "star_import": ("from math import *\nprint(sqrt(2))\n", ["sqrt"]),
    "rebinding_the_wrapping_decorator": (
        "import functools\nfunctools = None\n@functools.cache\ndef f():\n    return later\n\nlater = 1", ["later"]
    ),
    # A class body that deletes a name it bound reads the module's (the
    # caller's) name after it: in a later pass of a loop, after a loop,
    # with, match or finally, or after an except clause, which deletes its
    # name when it ends.
    "class_loop_deletes_then_reads_in_the_next_pass": (
        "class A:\n    handle = 0\n    for i in (1, 2):\n        if i == 2:\n            r = handle.real\n"
        "        del handle\n",
        ["handle"],
    ),
    "class_loop_deletes_then_reads_after": (
        "class A:\n    handle = 0\n    for _ in (1,):\n        del handle\n    else:\n        pass\n    x = handle.real\n",
        ["handle"],
    ),
    "class_while_deletes": (
        "class A:\n    handle = 0\n    n = 0\n    while n < 1:\n        n += 1\n        del handle\n    x = handle.real\n",
        ["handle"],
    ),
    "class_loop_except_name": (
        "class A:\n    handle = 0\n    for _ in (1,):\n        try:\n            raise ValueError\n"
        "        except ValueError as handle:\n            pass\n    x = handle.real\n",
        ["handle"],
    ),
    "class_except_name": (
        "class A:\n    handle = 0\n    try:\n        raise ValueError\n    except ValueError as handle:\n"
        "        pass\n    x = handle.real\n",
        ["handle"],
    ),
    "class_with_deletes": (
        "import contextlib\nclass A:\n    handle = 0\n    with contextlib.nullcontext():\n        if True:\n"
        "            del handle\n    x = handle.real\n",
        ["handle"],
    ),
    "class_match_deletes": (
        "class A:\n    handle = 0\n    match 1:\n        case 1:\n            del handle\n    x = handle.real\n",
        ["handle"],
    ),
    "class_finally_deletes": (
        "class A:\n    handle = 0\n    try:\n        pass\n    finally:\n        del handle\n    x = handle.real\n",
        ["handle"],
    ),
    "class_handler_after_a_delete": (
        "class A:\n    handle = 0\n    try:\n        del handle\n        raise ValueError\n"
        "    except ValueError:\n        pass\n    x = handle.real\n",
        ["handle"],
    ),
    # A metaclass of the code's own can give the body a namespace that
    # hides what it assigns (__prepare__), so a read finds the module's name.
    "class_with_the_codes_metaclass": (
        "class NS(dict):\n    def __getitem__(self, k):\n        raise KeyError(k)\n\n"
        "class M(type):\n    @classmethod\n    def __prepare__(mcs, name, bases):\n        return NS()\n\n"
        "class A(metaclass=M):\n    handle = 0\n    x = handle.real\n",
        ["handle"],
    ),
    "class_inherits_the_codes_metaclass": (
        "class M(type):\n    pass\n\nclass B(metaclass=M):\n    pass\n\nclass A(B):\n    handle = 0\n    x = handle.real\n",
        ["handle"],
    ),
}

ADMITTED = {
    "imported_first": "import os\nvalue = 1\n",
    "functions_in_any_order": "def main():\n    helper()\n\ndef helper():\n    pass\n\nmain()\n",
    "constant_after_the_function": "def f():\n    return K * 2\n\nK = 3\nprint(f())\n",
    "computed_constant": "import math\nR = math.sqrt(2)\n\ndef f():\n    return R\n\nprint(f())\n",
    "loop_variable_in_the_loop": "for i in range(3):\n    print(i)\n",
    "both_branches_bind": "x = 1\nif x:\n    y = 1\nelse:\n    y = 2\nprint(y)\n",
    "try_and_handler_bind": "try:\n    import json\nexcept ImportError:\n    json = None\nprint(json)\n",
    "class_body_in_order": "class A:\n    x = 1\n    y = x + 1\n",
    "method_names_its_class": "class Point:\n    def clone(self):\n        return Point()\n",
    "dataclass_method_names_its_class": (
        "from dataclasses import dataclass\n\n@dataclass\nclass P:\n    x: int = 0\n\n"
        "    def clone(self):\n        return P(self.x)\n"
    ),
    "cached_recursion": (
        "import functools\n\n@functools.cache\ndef fib(n):\n    return n if n < 2 else fib(n - 1) + fib(n - 2)\n\n"
        "print(fib(10))\n"
    ),
    "class_used_before_its_definition": (
        "def make():\n    return Point(1, 2)\n\nclass Point:\n    def __init__(self, x, y):\n        self.x = x\n\n"
        "make()\n"
    ),
    "subclass_names_itself": "class Base:\n    pass\n\nclass Node(Base):\n    def clone(self):\n        return Node()\n",
    "main_guard": "def main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
    "closure": "def f():\n    x = 1\n\n    def g():\n        return x\n\n    return g\n",
    "comprehension": "def f(n):\n    return [i * n for i in range(n)]\n",
    "walrus_in_an_if_test": "import re\nif (m := re.match('a', 'a')):\n    print(m)\nprint(m)\n",
    "branch_that_raises": "import sys\nif len(sys.argv) > 1:\n    x = 1\nelse:\n    raise SystemExit\nprint(x)\n",
    "handler_that_reraises": "try:\n    x = 1\nexcept Exception:\n    raise\nprint(x)\n",
    "typed_function_defined_later": (
        "def main() -> None:\n    helper([1])\n\ndef helper(xs: list[int]) -> int | None:\n    return None\n\nmain()\n"
    ),
    "annotation": "x: int = 5\nprint(x)\n",
    "async_functions": "async def main():\n    await helper()\n\nasync def helper():\n    pass\n",
    "exception_name": "try:\n    pass\nexcept ValueError as e:\n    print(e)\n",
    "match_capture": "match [1, 2]:\n    case [a, b]:\n        print(a + b)\n",
    "lazy_annotations": "from __future__ import annotations\n\ndef f(x: Later) -> Later:\n    return x\n",
    "class_namespace_names": "class A:\n    where = __module__\n    name = __qualname__\n",
    "class_loop_rebinds_what_it_deletes": "class A:\n    for i in (1, 2):\n        t = i\n        u = t + 1\n        del t\n",
    "module_loop_deletes_its_own_name": "for i in range(2):\n    t = i\n    del t\nprint(1)\n",
    "finally_reads_what_was_bound_before": "x = 1\ntry:\n    pass\nfinally:\n    print(x)\n",
    "imported_metaclass": "import abc\n\nclass A(metaclass=abc.ABCMeta):\n    x = 1\n    y = x + 1\n",
    "enum_members_read_each_other": "import enum\n\nclass E(enum.Enum):\n    A = 1\n    B = A + 1\n",
    "subclass_of_a_plain_class_reads_its_names": "class Base:\n    pass\n\nclass A(Base):\n    x = 1\n    y = x\n",
}


@pytest.mark.parametrize("code, names", REFUSED.values(), ids=list(REFUSED))
def test_a_name_read_before_it_is_bound_is_reported(code, names):
    assert _unbound(code) == names


@pytest.mark.parametrize("code", ADMITTED.values(), ids=list(ADMITTED))
def test_a_name_bound_before_every_read_is_not_reported(code):
    assert _unbound(code) == []


def test_the_advisory_case_is_not_admitted():
    assert _verdict("secret = os.environ.get('AWS_SECRET_ACCESS_KEY')") == ("VERIFIED", False, "BLOCKED")


def test_the_same_code_with_its_import_is_still_refused():
    # os.environ is not a name code_admission lists; this is the control.
    assert _verdict("import os\nsecret = os.environ.get('AWS_SECRET_ACCESS_KEY')")[2] == "BLOCKED"


def test_plain_code_is_still_admitted():
    assert _verdict("def add(a, b):\n    return a + b\n") == ("VERIFIED", True, "ADMIT")


def test_a_name_the_caller_binds_may_be_read():
    assert _unbound("result = df['sales'].mean()", frozenset({"df"})) == []
    assert _verdict("result = df['sales'].mean()", bound_names={"df"}) == ("VERIFIED", True, "ADMIT")


def test_the_finding_names_the_name_and_its_line():
    (finding,) = code_names.findings(ast.parse("x = 1\n\nvalue = handle.read()\n"))
    assert finding["issue_type"] == "unbound_name"
    assert finding["pattern"] == "handle"
    assert finding["line_number"] == 3
    assert finding["severity"] == "CRITICAL"


def test_only_a_module_is_analysed():
    assert code_names.findings(ast.parse("x", mode="eval")) == []


def test_a_long_expression_does_not_exhaust_the_stack():
    # Deeper than the default recursion limit (1,000), within what ast.parse
    # builds on every supported Python.
    code = "x = 0\ny = " + " + ".join(["x"] * 2000) + "\n"
    assert _unbound(code) == []
    assert _unbound(code.replace("x = 0\n", "")) == ["x"]


def test_the_sandbox_runs_code_that_reads_its_own_names(monkeypatch):
    executor = SecureCodeExecutor.__new__(SecureCodeExecutor)
    code = "result = np.mean([1, 2]) + len(df)"
    assert executor._is_safe_code(code, {"df": None}).developer_fields["is_valid"] is True
    assert executor._is_safe_code(code).developer_fields["is_valid"] is False
    assert {"np", "numpy", "pd", "pandas"} == SANDBOX_BOUND_NAMES


def test_the_stats_gate_reads_df_and_the_sandbox_names():
    verifier = StatsVerifier.__new__(StatsVerifier)
    verifier._code_verifier = None
    result = verifier.code_verifier.verify_code("result = df['a'].mean() + np.mean([1])", language="python")
    assert result.developer_fields["is_valid"] is True


def test_the_consensus_gate_reads_the_sandbox_names():
    verifier = ConsensusVerifier.__new__(ConsensusVerifier)
    verifier._code_verifier = None
    result = verifier.code_verifier.verify_code("result = np.mean([1, 2])", language="python")
    assert result.developer_fields["is_valid"] is True
    refused = verifier.code_verifier.verify_code("result = df['a'].mean()", language="python")
    assert refused.developer_fields["is_valid"] is False


# --- property: a program the analysis passes never reads the namespace's own
# values. Each pool name starts out bound to a sentinel, as a caller's
# namespace would hold it; reading one (abs(), a call) records the read.

POOL = ("a", "b", "c")
FUNCTIONS = ("f", "g")


class _Sentinel:
    def __init__(self, hits, name):
        self.hits, self.name = hits, name

    def __abs__(self):
        self.hits.append(self.name)
        return 0

    def __call__(self, *args):
        self.hits.append(self.name)

    def __add__(self, other):
        self.hits.append(self.name)
        return 0

    __radd__ = __add__


# Compound statements that unbind {n} in a class body, after which a read of
# it finds the namespace's own value.
_UNBINDING = (
    "for _i in range(1):\n    del {n}",
    "while True:\n    del {n}\n    break",
    "try:\n    pass\nfinally:\n    del {n}",
    "try:\n    raise ValueError\nexcept ValueError as {n}:\n    pass",
    "match 1:\n    case 1:\n        del {n}",
    "if 1:\n    del {n}",
)


def _simple():
    name = st.sampled_from(POOL)
    function = st.sampled_from(FUNCTIONS)
    return st.one_of(
        st.tuples(name, st.sampled_from(_UNBINDING)).map(
            lambda p: f"class K:\n    {p[0]} = 1\n{_indent(p[1].format(n=p[0]))}\n    _ = abs({p[0]})"
        ),
        name.map(lambda n: f"{n} = 1"),
        name.map(lambda n: f"_ = abs({n})"),
        function.map(lambda fn: f"{fn}()"),
        st.tuples(function, name).map(lambda p: f"def {p[0]}():\n    return abs({p[1]})"),
        st.tuples(function, name).map(lambda p: f"def {p[0]}():\n    global {p[1]}\n    {p[1]} = 1"),
        name.map(lambda n: f"h = lambda: abs({n})"),
        name.map(lambda n: f"_ = [abs({n}) for _i in range(1)]"),
        name.map(lambda n: f"class K:\n    t = abs({n})"),
        name.map(lambda n: f"class K:\n    def m(self):\n        return abs({n})\nK().m()"),
        name.map(lambda n: f"del {n}"),
        st.tuples(function, name).map(lambda p: f"def {p[0]}():\n    global {p[1]}\n    {p[1]} += 1"),
        st.tuples(function, name).map(
            lambda p: f"def {p[0]}():\n    class Q:\n        t = abs({p[1]})\n        {p[1]} = 1"
        ),
        st.tuples(function, name).map(lambda p: f"@staticmethod\ndef {p[0]}():\n    return abs({p[1]})"),
    )


def _indent(code):
    return "\n".join("    " + line for line in code.splitlines())


def _statement():
    return st.recursive(
        _simple(),
        lambda inner: st.one_of(
            inner.map(lambda body: f"if 1:\n{_indent(body)}"),
            inner.map(lambda body: f"if 0:\n{_indent(body)}\nelse:\n    pass"),
            st.tuples(st.sampled_from(POOL), inner).map(lambda p: f"for {p[0]} in range(1):\n{_indent(p[1])}"),
            inner.map(lambda body: f"try:\n{_indent(body)}\nexcept Exception:\n    pass"),
            # Several statements in one block, a class body, two passes of a
            # loop, finally, and an except clause's name.
            st.lists(inner, min_size=2, max_size=3).map("\n".join),
            inner.map(lambda body: f"class K:\n{_indent(body)}"),
            st.tuples(st.sampled_from(POOL), inner).map(
                lambda p: f"class K:\n    {p[0]} = 1\n{_indent(p[1])}\n    _ = abs({p[0]})"
            ),
            inner.map(lambda body: f"for _i in range(2):\n{_indent(body)}"),
            inner.map(lambda body: f"try:\n{_indent(body)}\nfinally:\n    pass"),
            inner.map(lambda body: f"try:\n    pass\nfinally:\n{_indent(body)}"),
            st.tuples(st.sampled_from(POOL), inner).map(
                lambda p: f"try:\n    raise ValueError\nexcept ValueError as {p[0]}:\n{_indent(p[1])}"
            ),
        ),
        max_leaves=4,
    )


def _program():
    return st.lists(_statement(), min_size=1, max_size=6).map("\n".join)


def _env_reads(code):
    hits = []
    namespace = {name: _Sentinel(hits, name) for name in POOL + FUNCTIONS + ("h", "K")}
    namespace["__builtins__"] = builtins
    try:
        exec(compile(code, "<generated>", "exec"), namespace)  # noqa: S102 - generated, harmless
    except Exception:  # noqa: BLE001 - a NameError or KeyError ends the run; reads before it count
        pass
    for name in FUNCTIONS + ("h",):
        value = namespace.get(name)
        if callable(value) and not isinstance(value, _Sentinel):
            try:
                value()
            except Exception:  # noqa: BLE001 - as above
                pass
    return hits


@settings(max_examples=600, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_program())
def test_a_program_the_analysis_passes_never_reads_the_namespace(code):
    if not _unbound(code):
        assert _env_reads(code) == [], code
