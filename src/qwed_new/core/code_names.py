"""
Names Python code reads before it binds them (GHSA-7xrf).

CodeVerifier checks what code does with the modules it imports and the
builtins it reads. A name the code reads but has not bound is neither: it is
whatever the namespace the code runs in holds under that name, and in a
notebook, a REPL or a program that runs the code with its own globals that may
be ``os``, a database handle or anything else. So such a read is refused,
unless the name is a builtin (code_admission checks those) or the caller
declares that its runtime binds it.

The code is taken to run as a module: one namespace for its globals, and
builtins that are the builtins (``__name__`` and ``__doc__`` included). A read
must follow a binding in the order the code runs:

- Module and class bodies run in order. A read needs a binding by an earlier
  statement that always binds the name: an import, def, class or assignment,
  one that every branch of an ``if`` or ``try`` that carries on makes, or a
  ``:=`` in an ``if`` or ``while`` test that always runs. A ``for``,
  ``while``, ``with``, ``match`` or ``except`` binding counts only inside its
  own block (a loop can run no times, and a context manager can swallow an
  exception). A star import binds nothing here (what it binds depends on the
  Python that runs it). A class body reads a name it binds, but has not bound
  yet, from the module, skipping any enclosing function.
- A function body runs when it is called, so its reads of global names need a
  binding before the first top-level statement that can run code the snippet
  wrote. Only a few statements cannot: imports, defs and classes whose
  decorators, defaults, annotations, bases and values cannot call anything,
  and assignments of constants and names to names. A function nothing calls
  can still be called by whoever runs the code, so a name it reads must be
  bound by the end. A function can run during its own statement when a
  decorator could call it, when it is a method of a class whose creation can
  run code, or when it is defined inside a branch, loop or try; its reads
  then need a binding before that statement.
- A lambda, comprehension or generator expression runs no earlier than where
  it is written.

Any rule about what a name is (a builtin, a listed decorator, a class with no
hooks) holds only when the code binds that name nowhere else, in any scope.
"""

import ast
import builtins
import sys
from collections import Counter
from typing import Callable, Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple, Union

from .code_admission import ADMITTED_BUILTINS, REFUSED_BUILTINS

# This Python's builtins, and those code_admission lists for any supported
# Python (it admits or refuses them; a later version's builtin is still one).
_BUILTIN_NAMES: FrozenSet[str] = frozenset(dir(builtins)) | ADMITTED_BUILTINS | REFUSED_BUILTINS
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_TYPE_PARAMS = sys.version_info >= (3, 12)
_TYPE_ALIAS: Tuple[type, ...] = (ast.TypeAlias,) if _TYPE_PARAMS else ()
_TRY: Tuple[type, ...] = (ast.Try,) + ((ast.TryStar,) if sys.version_info >= (3, 11) else ())
_STATEMENT_LISTS = ("body", "orelse", "finalbody")
_EXITS = (ast.Raise, ast.Return, ast.Break, ast.Continue)
# Names a class body starts with.
_CLASS_NAMESPACE = frozenset({"__module__", "__qualname__"})
# Builtin classes subscripted in annotations (list[int]) through their own
# __class_getitem__, which calls nothing the code wrote.
_BUILTIN_GENERICS = frozenset({"list", "dict", "tuple", "set", "frozenset", "type"})

# Decorators that wrap or mark what they decorate and never call it while
# decorating: builtins and listed module names, written bare or called with
# constants only.
_WRAPPING_BUILTINS = frozenset({"staticmethod", "classmethod", "property"})
_WRAPPING_IMPORTS = frozenset({
    ("abc", "abstractmethod"),
    ("dataclasses", "dataclass"),
    ("functools", "cache"),
    ("functools", "cached_property"),
    ("functools", "lru_cache"),
    ("functools", "total_ordering"),
})

_DESCRIPTION = (
    "A name the code reads before binding it: it is whatever the namespace the code runs in holds under that name"
)
_RECOMMENDATION = "Import or assign every name before the code reads it."


class _After:
    """The first top-level statement after ``index`` that can run code."""

    __slots__ = ("index",)

    def __init__(self, index: int):
        self.index = index


# When a function body can first run: during the top-level statement at an
# index, or (_After) at the first one after it that can run code.
_Start = Union[int, _After]


class _Names:
    """The names one function-like scope binds and declares."""

    def __init__(self, local: Iterable[str] = ()):
        self.local: Set[str] = set(local)
        self.declared_global: Set[str] = set()
        self.declared_nonlocal: Set[str] = set()


class _Env:
    """Where a read happens: the enclosing function scopes (innermost last);
    in a class body, what it has bound so far and every name it binds or
    declares global; and either what the module has bound so far (code that
    runs now) or when the code can first run (``start``, for a function
    body)."""

    __slots__ = ("chain", "class_bound", "class_names", "module_bound", "start")

    def __init__(
        self,
        chain: Tuple[_Names, ...] = (),
        class_bound: Optional[FrozenSet[str]] = None,
        module_bound: Optional[FrozenSet[str]] = None,
        start: Optional[_Start] = None,
        class_names: FrozenSet[str] = frozenset(),
    ):
        self.chain = chain
        self.class_bound = class_bound
        self.class_names = class_names
        self.module_bound = module_bound
        self.start = start

    def inner(self, scope: _Names) -> "_Env":
        """The environment of a function-like scope inside this one: class
        names are not visible in it."""
        return _Env(self.chain + (scope,), None, self.module_bound, self.start)


class _Frame:
    """How to read a module or class body: the environment for what it has
    bound so far, when a def or class written there can first run, and the
    top-level statement it is in (None inside a function)."""

    def __init__(
        self,
        make_env: Callable[[FrozenSet[str]], _Env],
        def_start: Callable[[ast.AST], _Start],
        module: bool,
        index: Optional[int],
    ):
        self.make_env = make_env
        self.def_start = def_start
        self.module = module
        self.index = index

    def nested(self, start: _Start) -> "_Frame":
        """The frame inside a branch, loop, with or try: what is defined there
        can run during the statement."""
        return _Frame(self.make_env, lambda node: start, self.module, self.index)


def findings(tree: ast.AST, bound_names: Iterable[str] = ()) -> List[Dict[str, object]]:
    """CodeVerifier findings for the names ``tree`` (a module) reads before
    binding them. Builtins and ``bound_names`` (names the caller's runtime
    binds before the code runs) are not reported."""
    if not isinstance(tree, ast.Module):
        return []
    analysis = _Analysis(tree, _BUILTIN_NAMES | frozenset(bound_names))
    analysis.run()
    return [
        {
            "severity": "CRITICAL",
            "issue_type": "unbound_name",
            "pattern": name,
            "description": _DESCRIPTION,
            "line_number": line,
            "recommendation": _RECOMMENDATION,
        }
        for name, line in sorted(analysis.flagged.items(), key=lambda item: (item[1], item[0]))
    ]


class _Analysis:
    """One pass over a module."""

    def __init__(self, tree: ast.Module, skip: FrozenSet[str]):
        self.tree = tree
        self.skip = skip
        self.flagged: Dict[str, int] = {}
        self.deferred: List[Tuple[str, int, _Start]] = []
        self.lazy_annotations = any(
            isinstance(node, ast.ImportFrom) and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        )
        # How often each name is bound anywhere in the code, in any scope
        # (a global statement can rebind a module name from a function or a
        # class), and what each name an import binds came from.
        self.binding_counts: Counter = Counter()
        sources: Dict[str, Tuple[str, str]] = {}
        for node in ast.walk(tree):
            for name in _binds(node) | ({node.arg} if isinstance(node, ast.arg) else set()):
                self.binding_counts[name] += 1
        for node in tree.body:
            sources.update(_import_sources(node))
        self.import_sources = {
            name: source for name, source in sources.items() if self.binding_counts[name] == 1
        }
        self.inert_classes: Set[str] = set()
        # Class statements (of names bound once) and whether their bodies run
        # in a plain namespace (_plain_namespace).
        self.plain_namespaces: Dict[str, bool] = {}

    # --- the module ---------------------------------------------------------

    def run(self) -> None:
        """Read the module in order, then check the reads of function bodies
        against what is bound when they can first run."""
        top = self.tree.body
        bound: FrozenSet[str] = frozenset()
        starts: List[FrozenSet[str]] = []
        inert: List[bool] = []
        for index, stmt in enumerate(top):
            starts.append(bound)
            inert.append(self._inert(stmt))
            if isinstance(stmt, ast.ClassDef) and inert[-1] and self.binding_counts[stmt.name] == 1:
                # A subclass's creation calls its bases' __init_subclass__,
                # however the class binds it (a def or a plain function).
                if not any("__init_subclass__" in _binds(item) for item in _own_scope(list(stmt.body))):
                    self.inert_classes.add(stmt.name)
            bound = self._stmt(stmt, bound, self._module_frame(index, inert[-1]))
        starts.append(bound)
        for name, line, start in self.deferred:
            if name not in starts[self._first_run(start, inert)]:
                self._flag(name, line)

    def _module_frame(self, index: int, inert: bool) -> _Frame:
        """The frame for the top-level statement at ``index``: a def whose
        decorators only wrap it, or a class whose creation cannot run code,
        can first run at the next statement that can."""
        def def_start(node: ast.AST) -> _Start:
            if isinstance(node, _FUNCTIONS):
                return _After(index) if self._wrapping(node.decorator_list) else index
            return _After(index) if inert else index

        return _Frame(lambda bound: _Env(module_bound=bound), def_start, True, index)

    @staticmethod
    def _first_run(start: _Start, inert: List[bool]) -> int:
        """The index of the top-level statement during which code that can
        first run at ``start`` may run (len(inert) for after the module)."""
        if isinstance(start, int):
            return start
        for index in range(start.index + 1, len(inert)):
            if not inert[index]:
                return index
        return len(inert)

    def _flag(self, name: str, line: int) -> None:
        """Report ``name``, once, at the first line it was found on."""
        if name not in self.flagged or line < self.flagged[name]:
            self.flagged[name] = line

    # --- reads --------------------------------------------------------------

    def _read(self, name: str, line: int, env: _Env) -> None:
        """A read of ``name`` in ``env``: fine when it is a builtin, a name the
        caller binds, or bound where it is looked up; else reported now (code
        that runs now) or when its function can first run. A class body
        looks up a name it binds in itself and then in the module, never in
        an enclosing function."""
        if name in self.skip:
            return
        chain = env.chain
        if env.class_bound is not None:
            if name in env.class_bound:
                return
            if name in env.class_names:
                chain = ()
        for scope in reversed(chain):
            if name in scope.declared_global:
                break
            if name in scope.local or name in scope.declared_nonlocal:
                return
        if env.module_bound is not None:
            if name not in env.module_bound:
                self._flag(name, line)
        else:
            self.deferred.append((name, line, env.start if env.start is not None else 0))

    def _expr(self, root: Optional[ast.AST], env: _Env) -> None:
        """Every read in the expression ``root``. Iterative, so a long chain
        of operators does not exhaust the stack."""
        pending: List[Tuple[ast.AST, _Env]] = [(root, env)] if root is not None else []
        while pending:
            node, here = pending.pop()
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Load):
                    self._read(node.id, node.lineno, here)
            elif isinstance(node, ast.Lambda):
                pending.extend((default, here) for default in _defaults(node.args))
                self._function(node, here)
            elif isinstance(node, _COMPREHENSIONS):
                pending.extend(self._comprehension(node, here))
            elif isinstance(node, ast.NamedExpr):
                pending.append((node.value, here))
            else:
                pending.extend((child, here) for child in ast.iter_child_nodes(node))

    @staticmethod
    def _comprehension(node: ast.AST, env: _Env) -> Iterator[Tuple[ast.AST, _Env]]:
        """The parts of a comprehension to read: its first iterable where the
        comprehension is written, the rest in its own scope, where its
        targets are bound and class names are not visible."""
        generators = node.generators  # type: ignore[attr-defined]
        targets: Set[str] = set()
        for generator in generators:
            targets.update(_store_names(generator.target))
        inner = env.inner(_Names(targets))
        yield generators[0].iter, env
        for index, generator in enumerate(generators):
            if index:
                yield generator.iter, inner
            yield from ((condition, inner) for condition in generator.ifs)
            yield from ((part, inner) for part in _target_reads(generator.target))
        if isinstance(node, ast.DictComp):
            yield node.key, inner
            yield node.value, inner
        else:
            yield node.elt, inner  # type: ignore[attr-defined]

    # --- function bodies ----------------------------------------------------

    def _function(self, node: ast.AST, outer: _Env, start: Optional[_Start] = None) -> None:
        """The reads in a def's or lambda's body. A lambda in code that runs
        now is checked against what is bound where it is written; any other
        body when it can first run (``start``)."""
        scope = _function_names(node)
        if outer.module_bound is not None and start is None:
            env = outer.inner(scope)
        else:
            env = _Env(outer.chain + (scope,), None, None, start if start is not None else outer.start)
        if isinstance(node, ast.Lambda):
            self._expr(node.body, env)
        else:
            self._body(node.body, env)  # type: ignore[attr-defined]

    def _body(self, stmts: List[ast.stmt], env: _Env) -> None:
        """The reads in a function body's statements. Inside a function a
        name is local or not for the whole body, so order does not matter."""
        for stmt in stmts:
            if isinstance(stmt, _FUNCTIONS):
                self._def_header(stmt, env)
                self._function(stmt, env, env.start)
            elif isinstance(stmt, ast.ClassDef):
                self._class_header(stmt, env)
                self._class_body(stmt, env, env.start, None)
            elif isinstance(stmt, ast.AugAssign):
                self._expr(_as_read(stmt.target), env)
                self._expr(stmt.value, env)
            else:
                for part in _statement_exprs(stmt):
                    self._expr(part, env)
                for nested in _statement_lists(stmt):
                    self._body(nested, env)
                for case in stmt.cases if isinstance(stmt, ast.Match) else ():
                    self._pattern(case.pattern, env)
                    self._expr(case.guard, env)
                    self._body(case.body, env)

    def _def_header(self, node: ast.AST, env: _Env) -> None:
        """What a def evaluates where it is written: decorators, defaults
        and, unless they are lazy, annotations."""
        for part in node.decorator_list + _defaults(node.args):  # type: ignore[attr-defined]
            self._expr(part, env)
        params = _with_type_params(node, env)
        for part in _type_params(node):
            self._expr(part, params)
        if not self.lazy_annotations:
            for part in _annotations(node):
                self._expr(part, params)

    def _class_header(self, node: ast.ClassDef, env: _Env) -> None:
        """What a class statement evaluates before its body: decorators, bases
        and keywords."""
        params = _with_type_params(node, env)
        for part in _type_params(node):
            self._expr(part, params)
        for part in node.decorator_list:
            self._expr(part, env)
        for part in node.bases + [keyword.value for keyword in node.keywords]:
            self._expr(part, params)

    def _class_body(self, node: ast.ClassDef, env: _Env, start: _Start, index: Optional[int]) -> None:
        """A class body runs in order with its own names; a name it does not
        bind is looked up as the enclosing code would, and one it binds but
        has not bound yet in the module. What it defines can first run at
        ``start``."""
        own = list(_own_scope(list(node.body)))
        declared_global = frozenset(name for stmt in own if isinstance(stmt, ast.Global) for name in stmt.names)
        class_names = frozenset(name for stmt in own for name in _binds(stmt)) | declared_global
        params = _type_param_names(node)
        chain = env.chain + ((_Names(params),) if params else ())
        module_bound, outer_start = env.module_bound, env.start
        plain = self._plain_namespace(node)
        if self.binding_counts[node.name] == 1:
            self.plain_namespaces[node.name] = plain

        def make_env(bound: FrozenSet[str]) -> _Env:
            # In a namespace that is not plain, what the body assigns may not
            # be there when it reads it, so every read is looked up as if
            # the body had bound nothing.
            own = bound if plain else frozenset()
            return _Env(chain, own - declared_global, module_bound, outer_start, class_names)

        frame = _Frame(make_env, lambda child: start, False, index)
        self._block(node.body, _CLASS_NAMESPACE, frame)

    def _plain_namespace(self, node: ast.ClassDef) -> bool:
        """Whether the body of class ``node`` runs in a plain namespace, where
        a name it assigns stays there until it deletes it. A metaclass can
        give the body any mapping (__prepare__), one that drops or hides
        what the body assigns, so that a read of it finds the module's name.
        Plain: the metaclass and every base are builtins, things an import
        binds (the admitted modules' metaclasses keep what is assigned), or
        classes this code makes with a plain namespace."""
        for keyword in node.keywords:
            if keyword.arg is None:
                return False
            if keyword.arg == "metaclass" and not self._outside_object(keyword.value):
                return False
        for base in node.bases:
            if isinstance(base, ast.Subscript):
                base = base.value
            if isinstance(base, ast.Name) and base.id in self.plain_namespaces:
                if not self.plain_namespaces[base.id]:
                    return False
            elif not self._outside_object(base):
                return False
        return True

    def _outside_object(self, node: ast.AST) -> bool:
        """Whether ``node`` (or the object an attribute chain starts from) is
        a builtin or a name the caller binds, which the code binds nowhere,
        or a name a top-level import binds and nothing else does."""
        while isinstance(node, ast.Attribute):
            node = node.value
        if not isinstance(node, ast.Name):
            return False
        if node.id in self.import_sources:
            return True
        return node.id in self.skip and self.binding_counts[node.id] == 0

    # --- module and class bodies, in order ----------------------------------

    def _block(self, stmts: List[ast.stmt], bound: FrozenSet[str], frame: _Frame) -> FrozenSet[str]:
        """Read ``stmts`` in order; the names bound after them."""
        for stmt in stmts:
            bound = self._stmt(stmt, bound, frame)
        return bound

    def _stmt(self, stmt: ast.stmt, bound: FrozenSet[str], frame: _Frame) -> FrozenSet[str]:
        """Read one statement of a module or class body; the names bound after it."""
        env = frame.make_env(bound)
        if isinstance(stmt, _FUNCTIONS):
            self._def_header(stmt, env)
            self._function(stmt, env, frame.def_start(stmt))
            return bound | {stmt.name}
        if isinstance(stmt, ast.ClassDef):
            self._class_header(stmt, env)
            self._class_body(stmt, env, frame.def_start(stmt), frame.index)
            return bound | {stmt.name}
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            return bound | _imported(stmt)
        if isinstance(stmt, ast.Assign):
            self._expr(stmt.value, env)
            return bound | self._targets(stmt.targets, env)
        if isinstance(stmt, ast.AugAssign):
            self._expr(_as_read(stmt.target), env)
            self._expr(stmt.value, env)
            return bound
        if isinstance(stmt, ast.AnnAssign):
            if not self.lazy_annotations:
                self._expr(stmt.annotation, env)
            self._expr(stmt.value, env)
            if stmt.value is None:
                for part in _target_reads(stmt.target):
                    self._expr(part, env)
                return bound
            return bound | self._targets([stmt.target], env)
        if isinstance(stmt, ast.Delete):
            return self._delete(stmt, bound, frame, env)
        if _TYPE_ALIAS and isinstance(stmt, _TYPE_ALIAS):
            self._expr(stmt.value, _with_type_params(stmt, env))  # type: ignore[attr-defined]
            return bound | _store_names(stmt.name)  # type: ignore[attr-defined]
        return self._compound(stmt, bound, frame, env)

    def _compound(self, stmt: ast.stmt, bound: FrozenSet[str], frame: _Frame, env: _Env) -> FrozenSet[str]:
        """Branches, loops, with, try and match; any other statement is read
        whole and binds nothing."""
        # A name any part of a compound statement deletes (del, or an except
        # clause's name) can be unbound after it: what is read after it, or
        # in a later pass of a loop, cannot count on it.
        nested = frame.nested(frame.index if frame.index is not None else _start_of(env))
        if isinstance(stmt, ast.If):
            self._expr(stmt.test, env)
            tested = bound | _test_bindings(stmt.test)
            body = self._block(stmt.body, tested, nested)
            orelse = self._block(stmt.orelse, tested, nested)
            return _carried_on([(body, stmt.body), (orelse, stmt.orelse)], tested)
        if isinstance(stmt, ast.While):
            looping = bound - _unbound_in(stmt.body + stmt.orelse)
            self._expr(stmt.test, frame.make_env(looping))
            tested = looping | _test_bindings(stmt.test)
            self._block(stmt.body, tested, nested)
            self._block(stmt.orelse, tested, nested)
            return tested
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._expr(stmt.iter, env)
            looping = bound - _unbound_in(stmt.body + stmt.orelse)
            self._block(stmt.body, looping | self._targets([stmt.target], frame.make_env(looping)), nested)
            self._block(stmt.orelse, looping, nested)
            return looping
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            current = bound
            for item in stmt.items:
                self._expr(item.context_expr, frame.make_env(current))
                if item.optional_vars is not None:
                    current = current | self._targets([item.optional_vars], frame.make_env(current))
            self._block(stmt.body, current, nested)
            return bound - _unbound_in(stmt.body)
        if isinstance(stmt, _TRY):
            return self._try(stmt, bound, nested)
        if isinstance(stmt, ast.Match):
            self._expr(stmt.subject, env)
            for case in stmt.cases:
                captured = bound | self._pattern(case.pattern, env)
                self._expr(case.guard, frame.make_env(captured))
                self._block(case.body, captured, nested)
            return bound - _unbound_in([inner for case in stmt.cases for inner in case.body])
        for part in _statement_exprs(stmt):
            self._expr(part, env)
        lists = _statement_lists(stmt)
        for statements in lists:
            self._block(statements, bound, nested)
        return bound - _unbound_in([inner for statements in lists for inner in statements])

    def _try(self, stmt: ast.stmt, bound: FrozenSet[str], nested: _Frame) -> FrozenSet[str]:
        """A try binds what its normal path and every handler that carries on
        bind, and what its finally block binds. An exception can come before
        any binding in the body and after any deletion in it, so each handler
        starts from what was bound before it, less what the body deletes;
        the finally block starts from that, less what the handlers delete."""
        body, orelse, finalbody = stmt.body, stmt.orelse, stmt.finalbody  # type: ignore[attr-defined]
        handlers = stmt.handlers  # type: ignore[attr-defined]
        after_body = self._block(body, bound, nested)
        paths = [(self._block(orelse, after_body, nested), body + orelse)]
        caught = bound - _unbound_in(body)
        for handler in handlers:
            self._expr(handler.type, nested.make_env(caught))
            name = {handler.name} if handler.name else set()
            paths.append((self._block(handler.body, caught | name, nested) - name, handler.body))
        settled = _carried_on(paths, bound)
        handled = {handler.name for handler in handlers if handler.name}
        final_start = caught - _unbound_in(orelse + [inner for handler in handlers for inner in handler.body]) - handled
        final = self._block(finalbody, final_start, nested)
        return (settled - _unbound_in(finalbody)) | final

    def _delete(self, stmt: ast.Delete, bound: FrozenSet[str], frame: _Frame, env: _Env) -> FrozenSet[str]:
        """``del name`` at module level on a name not bound yet deletes the
        runtime's own; it is reported like a read."""
        for target in stmt.targets:
            for name_node in _store_name_nodes(target):
                if frame.module and name_node.id not in bound and name_node.id not in self.skip:
                    self._flag(name_node.id, name_node.lineno)
                bound = bound - {name_node.id}
            for part in _target_reads(target):
                self._expr(part, env)
        return bound

    def _targets(self, targets: List[ast.expr], env: _Env) -> FrozenSet[str]:
        """The names assignment ``targets`` bind; the objects and indexes they
        write into are read."""
        names: Set[str] = set()
        for target in targets:
            names.update(_store_names(target))
            for part in _target_reads(target):
                self._expr(part, env)
        return frozenset(names)

    def _pattern(self, pattern: ast.AST, env: _Env) -> FrozenSet[str]:
        """Read a match pattern's values and classes; the names it captures."""
        captured: Set[str] = set()
        for node in ast.walk(pattern):
            if isinstance(node, ast.MatchValue):
                self._expr(node.value, env)
            elif isinstance(node, ast.MatchClass):
                self._expr(node.cls, env)
            elif isinstance(node, ast.MatchMapping):
                for key in node.keys:
                    self._expr(key, env)
                if node.rest:
                    captured.add(node.rest)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                captured.add(node.name)
        return frozenset(captured)

    # --- which top-level statements cannot run code -------------------------

    def _inert(self, stmt: ast.stmt) -> bool:
        """Whether a top-level statement cannot call code the snippet wrote:
        imports, defs and classes that call nothing while they are made, and
        assignments of constants and names to names. Unpacking and set and
        dict displays can call a dunder (__iter__, __hash__), so they do not
        count."""
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global, ast.Nonlocal) + _TYPE_ALIAS):
            return True
        if isinstance(stmt, ast.Expr):
            return isinstance(stmt.value, ast.Constant)
        if isinstance(stmt, ast.Assign):
            return all(isinstance(target, ast.Name) for target in stmt.targets) and _inert_value(stmt.value)
        if isinstance(stmt, ast.AnnAssign):
            return (
                isinstance(stmt.target, ast.Name) and (stmt.value is None or _inert_value(stmt.value))
                and self._inert_annotation(stmt.annotation)
            )
        if isinstance(stmt, _FUNCTIONS):
            return self._wrapping(stmt.decorator_list) and self._inert_signature(stmt)
        if isinstance(stmt, ast.ClassDef):
            return self._inert_class(stmt)
        return False

    def _inert_signature(self, node: ast.AST) -> bool:
        """Whether a def's defaults and annotations call nothing."""
        return all(_inert_value(part) for part in _defaults(node.args)) and all(  # type: ignore[attr-defined]
            self._inert_annotation(part) for part in _annotations(node)
        )

    def _inert_annotation(self, node: Optional[ast.AST]) -> bool:
        """Whether evaluating an annotation calls nothing: lazy annotations, a
        constant, a name, a builtin generic subscripted with these
        (list[int]), or a union of builtins (int | None)."""
        if self.lazy_annotations or node is None or isinstance(node, (ast.Constant, ast.Name)):
            return True
        if isinstance(node, ast.Tuple):
            return all(self._inert_annotation(element) for element in node.elts)
        if isinstance(node, ast.Subscript):
            return (
                isinstance(node.value, ast.Name) and node.value.id in _BUILTIN_GENERICS
                and self._builtin(node.value.id) and self._inert_annotation(node.slice)
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return all(
                (isinstance(side, ast.Constant) and side.value is None)
                or (isinstance(side, ast.Name) and self._builtin(side.id))
                or (isinstance(side, ast.BinOp) and self._inert_annotation(side))
                for side in (node.left, node.right)
            )
        return False

    def _inert_class(self, node: ast.ClassDef) -> bool:
        """Whether creating the class cannot run code the snippet wrote: only
        wrapping decorators, no keywords, bases that are builtins or such
        classes defined before, and a body of methods and constant values
        (a value that is a name could be an object whose __set_name__ or
        __get__ runs)."""
        if node.keywords or not self._wrapping(node.decorator_list):
            return False
        for base in node.bases:
            if not (isinstance(base, ast.Name) and (self._builtin(base.id) or base.id in self.inert_classes)):
                return False
        for stmt in node.body:
            if isinstance(stmt, (ast.Pass, ast.ClassDef) + _FUNCTIONS) or (
                isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            ):
                if not (isinstance(stmt, (ast.Pass, ast.Expr)) or self._inert(stmt)):
                    return False
            elif isinstance(stmt, ast.Assign):
                if not (all(isinstance(target, ast.Name) for target in stmt.targets) and _class_value(stmt.value)):
                    return False
            elif isinstance(stmt, ast.AnnAssign):
                if not (
                    isinstance(stmt.target, ast.Name) and (stmt.value is None or _class_value(stmt.value))
                    and self._inert_annotation(stmt.annotation)
                ):
                    return False
            else:
                return False
        return True

    def _wrapping(self, decorators: List[ast.expr]) -> bool:
        """Whether every decorator only wraps or marks what it decorates (it
        cannot call it while decorating)."""
        return all(self._wrapping_decorator(decorator) for decorator in decorators)

    def _wrapping_decorator(self, decorator: ast.expr) -> bool:
        """Whether ``decorator`` is a listed wrapping decorator, written bare
        or called with constants only (a decorator given a name can call it:
        staticmethod(g)(f) is g(f))."""
        target = decorator
        if isinstance(decorator, ast.Call):
            target = decorator.func
            if not all(isinstance(arg, ast.Constant) for arg in decorator.args):
                return False
            if not all(keyword.arg and isinstance(keyword.value, ast.Constant) for keyword in decorator.keywords):
                return False
        if isinstance(target, ast.Name):
            return (
                target.id in _WRAPPING_BUILTINS and self._builtin(target.id)
            ) or self.import_sources.get(target.id) in _WRAPPING_IMPORTS
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            module, name = self.import_sources.get(target.value.id, ("", "?"))
            return name == "" and (module, target.attr) in _WRAPPING_IMPORTS
        return False

    def _builtin(self, name: str) -> bool:
        """Whether ``name`` is a builtin the code binds nowhere."""
        return name in _BUILTIN_NAMES and not self.binding_counts[name]


def _start_of(env: _Env) -> _Start:
    """When code in ``env`` can first run (inside a function: its start)."""
    return env.start if env.start is not None else 0


def _unbound_in(stmts: List[ast.stmt]) -> FrozenSet[str]:
    """The names ``stmts`` can unbind in their own scope: those a del deletes
    and those an except clause binds (Python deletes them when the handler
    ends)."""
    names: Set[str] = set()
    for node in _own_scope(list(stmts)):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return frozenset(names)


def _carried_on(paths: List[Tuple[FrozenSet[str], List[ast.stmt]]], bound: FrozenSet[str]) -> FrozenSet[str]:
    """What every path that carries on past a branch has bound. A path whose
    block ends by raising, returning, breaking or continuing does not carry
    on; if none does, what was bound before."""
    carried = [names for names, stmts in paths if not (stmts and isinstance(stmts[-1], _EXITS))]
    return frozenset.intersection(*carried) if carried else bound


def _test_bindings(test: ast.expr) -> FrozenSet[str]:
    """The names a ``:=`` binds in a part of an if or while test that always
    runs: the test itself, the first operand of and/or, the left of a
    comparison, the operand of not."""
    while True:
        if isinstance(test, ast.NamedExpr):
            return frozenset(_store_names(test.target))
        if isinstance(test, ast.BoolOp):
            test = test.values[0]
        elif isinstance(test, ast.Compare):
            test = test.left
        elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            test = test.operand
        else:
            return frozenset()


def _inert_value(node: Optional[ast.AST]) -> bool:
    """Whether evaluating ``node`` calls nothing: a constant, a name, a lambda
    without defaults, or a tuple or list of these. (Set and dict displays
    hash their items.)"""
    if node is None or isinstance(node, (ast.Constant, ast.Name)):
        return True
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(not isinstance(element, ast.Starred) and _inert_value(element) for element in node.elts)
    if isinstance(node, ast.Lambda):
        return not _defaults(node.args)
    return False


def _class_value(node: ast.AST) -> bool:
    """Whether a class attribute's value cannot run code while the class is
    made: like an inert value, but not a bare name (its object could have
    __set_name__, or __get__ that a decorator reads)."""
    return not isinstance(node, ast.Name) and _inert_value(node)


def _store_name_nodes(target: ast.AST) -> List[ast.Name]:
    """The Name nodes a target binds or deletes."""
    if isinstance(target, ast.Name):
        return [target]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _store_name_nodes(element)]
    if isinstance(target, ast.Starred):
        return _store_name_nodes(target.value)
    return []


def _store_names(target: ast.AST) -> Set[str]:
    """The names a target binds."""
    return {name.id for name in _store_name_nodes(target)}


def _target_reads(target: ast.AST) -> List[ast.AST]:
    """What a target reads: the object and index of an attribute or item it
    writes, at any depth of unpacking."""
    if isinstance(target, (ast.Tuple, ast.List)):
        return [part for element in target.elts for part in _target_reads(element)]
    if isinstance(target, ast.Starred):
        return _target_reads(target.value)
    if isinstance(target, ast.Attribute):
        return [target.value]
    if isinstance(target, ast.Subscript):
        return [target.value, target.slice]
    return []


def _as_read(target: ast.AST) -> ast.AST:
    """An augmented assignment reads its target first."""
    if isinstance(target, ast.Name):
        return ast.copy_location(ast.Name(id=target.id, ctx=ast.Load()), target)
    return target


def _defaults(args: ast.arguments) -> List[ast.expr]:
    """A def's or lambda's default values."""
    return list(args.defaults) + [default for default in args.kw_defaults if default is not None]


def _parameters(args: ast.arguments) -> List[ast.arg]:
    """A def's or lambda's parameters."""
    params = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    return params + [param for param in (args.vararg, args.kwarg) if param is not None]


def _annotations(node: ast.AST) -> List[ast.expr]:
    """A def's parameter and return annotations."""
    found = [param.annotation for param in _parameters(node.args) if param.annotation is not None]  # type: ignore[attr-defined]
    if node.returns is not None:  # type: ignore[attr-defined]
        found.append(node.returns)  # type: ignore[attr-defined]
    return found


def _type_params(node: ast.AST) -> List[ast.AST]:
    """A def's, class's or type alias's type parameters (Python 3.12+)."""
    if not _TYPE_PARAMS or not isinstance(node, _FUNCTIONS + (ast.ClassDef,) + _TYPE_ALIAS):
        return []
    return list(node.type_params)  # type: ignore[attr-defined]


def _type_param_names(node: ast.AST) -> Set[str]:
    """The names a def's, class's or type alias's type parameters bind."""
    return {param.name for param in _type_params(node)}  # type: ignore[attr-defined]


def _with_type_params(node: ast.AST, env: _Env) -> _Env:
    """``env`` with ``node``'s type parameters bound."""
    names = _type_param_names(node)
    if not names:
        return env
    return _Env(env.chain + (_Names(names),), env.class_bound, env.module_bound, env.start, env.class_names)


def _imported(stmt: ast.stmt) -> FrozenSet[str]:
    """The names an import binds. A star import binds nothing here: what it
    binds depends on the Python that runs it."""
    names: Set[str] = set()
    for alias in stmt.names:  # type: ignore[attr-defined]
        if alias.name == "*":
            continue
        if isinstance(stmt, ast.Import):
            names.add(alias.asname or alias.name.split(".")[0])
        else:
            names.add(alias.asname or alias.name)
    return frozenset(names)


def _import_sources(node: ast.AST) -> Dict[str, Tuple[str, str]]:
    """For each name a top-level import binds: (module, name) for ``from m
    import n``, (module, "") for ``import m``."""
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name: (alias.name, "") for alias in node.names if "." not in alias.name}
    if isinstance(node, ast.ImportFrom) and node.module and not node.level:
        return {alias.asname or alias.name: (node.module, alias.name) for alias in node.names if alias.name != "*"}
    return {}


def _function_names(node: ast.AST) -> _Names:
    """The names a def or lambda binds in its own scope, and those it
    declares global or nonlocal."""
    names = _Names({param.arg for param in _parameters(node.args)} | _type_param_names(node))  # type: ignore[attr-defined]
    roots = [node.body] if isinstance(node, ast.Lambda) else list(node.body)  # type: ignore[attr-defined]
    for child in _own_scope(roots):
        if isinstance(child, ast.Global):
            names.declared_global.update(child.names)
        elif isinstance(child, ast.Nonlocal):
            names.declared_nonlocal.update(child.names)
        else:
            names.local.update(_binds(child))
    names.local -= names.declared_global
    return names


def _own_scope(roots: List[ast.AST]) -> Iterator[ast.AST]:
    """The nodes of the scope ``roots`` are in. A nested def's, lambda's or
    class's body has its own scope, but what its statement evaluates here
    (decorators, defaults, annotations, bases) is in this one; a
    comprehension's targets are in its own scope."""
    pending = list(roots)
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, _FUNCTIONS):
            pending.extend(node.decorator_list + _defaults(node.args) + _annotations(node))
        elif isinstance(node, ast.Lambda):
            pending.extend(_defaults(node.args))
        elif isinstance(node, ast.ClassDef):
            pending.extend(node.decorator_list + node.bases + [keyword.value for keyword in node.keywords])
        elif isinstance(node, ast.comprehension):
            pending.extend([node.iter, *node.ifs, *_target_reads(node.target)])
        else:
            pending.extend(ast.iter_child_nodes(node))


def _binds(node: ast.AST) -> Set[str]:
    """The names ``node`` binds in the scope it is in."""
    if isinstance(node, ast.Name):
        return set() if isinstance(node.ctx, ast.Load) else {node.id}
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return set(_imported(node))
    if isinstance(node, _FUNCTIONS + (ast.ClassDef,)):
        return {node.name}
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return {node.name} if node.name else set()
    if isinstance(node, ast.MatchMapping):
        return {node.rest} if node.rest else set()
    return set()


def _statement_lists(stmt: ast.stmt) -> List[List[ast.stmt]]:
    """The statement lists inside a statement, handler bodies included, other
    than match cases."""
    lists: List[List[ast.stmt]] = []
    for field, value in ast.iter_fields(stmt):
        if field in _STATEMENT_LISTS and isinstance(value, list) and value and isinstance(value[0], ast.stmt):
            lists.append(value)
        elif field == "handlers":
            lists.extend(handler.body for handler in value)
    return lists


def _statement_exprs(stmt: ast.stmt) -> List[ast.AST]:
    """The expressions a statement evaluates itself (not those in its nested
    statements or match cases), handler types included."""
    found: List[ast.AST] = []
    for field, value in ast.iter_fields(stmt):
        if field == "handlers":
            found.extend(handler.type for handler in value if handler.type is not None)
        elif field not in _STATEMENT_LISTS and field != "cases":
            values = value if isinstance(value, list) else [value]
            found.extend(item for item in values if isinstance(item, ast.AST))
    return found
