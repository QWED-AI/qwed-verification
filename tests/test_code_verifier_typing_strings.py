"""GHSA-p75q-7rg5-ff46: CodeVerifier.verify_code returned VERIFIED · ADMIT for
code that hides an expression in a string which typing later compiles and
runs: a string annotation on a function registered with singledispatch (its
.register calls get_type_hints while decorating), a string in a subscript
(List["..."] creates a ForwardRef) run through its __forward_code__, and the
strings TypeVar and ForwardRef compile.

Harmless placeholders; nothing is executed.
"""
import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision

N = "\n"
HIDDEN = "\"open('/etc/passwd').read() or int\""


def _result(code):
    return CodeVerifier().verify_code(code, language="python")


REFUSED = {
    "singledispatch_register": "from functools import singledispatch" + N + "@singledispatch" + N
    + "def handle(x):" + N + "    pass" + N + "@handle.register" + N + "def _(x: " + HIDDEN + "):" + N + "    pass",
    "singledispatchmethod_register": "from functools import singledispatchmethod" + N + "class C:" + N
    + "    @singledispatchmethod" + N + "    def m(self, x):" + N + "        pass" + N + "    @m.register" + N
    + "    def _(self, x: " + HIDDEN + "):" + N + "        pass",
    "forward_code": "import types" + N + "from typing import List" + N
    + "ref = List[\"open('/etc/passwd').read()\"].__args__[0]" + N
    + "types.FunctionType(ref.__forward_code__, {\"open\": open})()",
    "subscript_string": "from typing import List" + N + "ref = List[\"print(1) or int\"]",
    "typevar_bound": "from typing import TypeVar" + N + "T = TypeVar(\"T\", bound=\"print(1) or int\")",
    "forward_ref": "from typing import ForwardRef" + N + "r = ForwardRef(\"print(1)\")",
    "return_annotation": "def f() -> \"print(1) or int\":" + N + "    return 1",
    "variable_annotation": "x: \"print(1) or int\" = 1",
    "nested_in_annotation": "from typing import Optional" + N + "def f(x: Optional[\"print(1) or int\"]):" + N + "    return x",
    "string_in_string": "def f(x: \"List['print(1)']\"):" + N + "    return x",
    "annotations_dict": "def f(x):" + N + "    return x" + N + "f.__annotations__ = {'x': 'print(1) or int'}",
    "comprehension": "from typing import Dict" + N + "d: Dict[\"str\", \"[print(1) for _ in 'a']\"] = {}",
    "lambda": "x: \"(lambda: print(1))\" = 1",
    "assignment_expression": "x: \"(y := 1)\" = 1",
    "f_string_with_a_call": "from typing import List" + N + "x: List[\"f'{print(1)}'\"] = []",
    "nested_forward_ref": "from typing import ForwardRef" + N + "r = ForwardRef(\"ForwardRef('print(1)')\")",
    # Field types given as strings become the annotations of the methods
    # these build (D.__init__, N.__new__), which .register evaluates.
    "make_dataclass": "import dataclasses" + N + "D = dataclasses.make_dataclass('D', [('a', 'print(1) or int')])",
    "make_dataclass_alias": "from dataclasses import make_dataclass as md" + N + "D = md('D', [('a', 'print(1) or int')])",
    "functional_named_tuple": "import typing" + N + "T = typing.NamedTuple('T', [('a', 'print(1) or int')])",
    "functional_typed_dict": "from typing import TypedDict" + N + "T = TypedDict('T', {'a': 'print(1) or int'})",
    "typevar_alias": "from typing import TypeVar as TV" + N + "T = TV('T', bound='print(1) or int')",
    "stored_alias": "import dataclasses" + N + "md = dataclasses.make_dataclass" + N + "D = md('D', [('a', 'print(1) or int')])",
    "stored_alias_chain": "import typing" + N + "NT = typing.NamedTuple" + N + "X = NT" + N + "T = X('T', [('a', 'print(1) or int')])",
    # From Python 3.14 (the server image) annotations come from __annotate__.
    "annotate_assignment": "def f(x):" + N + "    return x" + N + "f.__annotate__ = lambda fmt: {'x': 'int'}",
    "annotate_method": "class C:" + N + "    def __annotate__(fmt):" + N + "        return {}",
}


@pytest.mark.parametrize("code", REFUSED.values(), ids=list(REFUSED))
def test_strings_typing_evaluates_are_refused_when_they_hold_code(code):
    result = _result(code)
    fields = result.developer_fields
    assert fields["is_safe"] is False, fields
    assert fields["critical_count"] >= 1
    assert admission_decision(result).value == "BLOCKED"


ADMITTED = {
    "plain_annotations": "def f(x: \"int\") -> \"List[int]\":" + N + "    return x",
    "forward_reference": "from typing import Optional" + N + "def f(x: Optional[\"Node\"]) -> \"Node | None\":" + N + "    return x",
    "generic_string": "x: \"dict[str, int]\" = {}",
    "typevar_bound_name": "from typing import TypeVar" + N + "T = TypeVar(\"T\", bound=\"Comparable\")",
    "dict_key_with_operator": "row = {\"first-name\": 1}" + N + "print(row[\"first-name\"])",
    "dict_key_plain": "config = {\"host\": 1}" + N + "print(config[\"host\"])",
    "dict_key_not_an_expression": "data = {\"a b\": 1}" + N + "print(data[\"a b\"])",
    "docstring": "def f(x):" + N + "    \"\"\"Docstring with call(x) inside.\"\"\"" + N + "    return x",
    "plain_string": "msg = \"print(1)\"" + N + "print(len(msg))",
    # Formatting runs only __format__ of the value, as an operator runs its
    # dunder: no call, nothing new runs.
    "f_string_without_a_call": "from typing import List" + N + "name = 'a'" + N + "x: List[\"f'{name}'\"] = []",
    "make_dataclass_types": "import dataclasses" + N + "P = dataclasses.make_dataclass('P', [('x', int), ('y', 'float')])",
    "functional_named_tuple_types": "from typing import NamedTuple" + N + "P = NamedTuple('P', [('x', int), ('y', 'Optional[int]')])",
    "functional_typed_dict_types": "from typing import TypedDict" + N + "M = TypedDict('M', {'name': str, 'year': 'int'}, total=False)",
    "typevar_alias_bound_name": "from typing import TypeVar as TV" + N + "T = TV('T', bound='Comparable')",
    "stored_alias_types": "import dataclasses" + N + "md = dataclasses.make_dataclass" + N + "P = md('P', [('x', int)])",
}


@pytest.mark.parametrize("code", ADMITTED.values(), ids=list(ADMITTED))
def test_type_names_and_ordinary_strings_are_still_admitted(code):
    result = _result(code)
    assert result.developer_fields["is_safe"] is True, result.developer_fields
    assert admission_decision(result).value == "ADMIT"


def test_deeply_nested_quoting_fails_closed():
    inner = "int"
    for _ in range(12):
        inner = repr("List[" + repr(inner) + "]")
    assert CodeVerifier._string_runs_code(inner, 0) is True


def test_a_string_that_does_not_parse_is_not_code():
    assert CodeVerifier._string_runs_code("not an expression (", 0) is False
