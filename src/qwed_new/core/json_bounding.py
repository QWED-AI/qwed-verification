"""Pre-encode JSON bounding for bounded audit surfaces (issues #338/#339).

Shared by the VerificationLog cap (api.main._cap_log_result) and the stats
observed_result cap (stats_verifier._cap_observed_result). Three properties,
each from a PR #351 review round:

- Strings are bounded BEFORE encoding: iterencode emits a string value as a
  single token, so an unbounded string would be fully materialized despite
  the streaming output cap (Greptile P2).
- Aggregates carry a shared traversal budget: a payload of many small values
  must not drive unbounded cloning before the cap applies (Greptile P1).
- Cycles — in dicts OR lists — degrade to inline "...[circular]" markers
  instead of RecursionError (Sentry LOW).

Cognitive complexity is kept per-function (Sonar) by splitting the traversal
into per-type helpers.
"""

from typing import Any, List, Set

CYCLE_MARKER = "...[circular]"


def bound_json_value(
    value: Any,
    *,
    max_string_chars: int,
    budget_chars: int,
    string_marker: str,
    budget_marker: str,
) -> Any:
    """Return a bounded copy of *value* under the given caps."""
    return _bound(
        value,
        set(),
        [budget_chars],
        max_string_chars,
        string_marker,
        budget_marker,
    )


def _bound(
    value: Any,
    seen: Set[int],
    budget: List[int],
    max_string: int,
    string_marker: str,
    budget_marker: str,
) -> Any:
    if budget[0] <= 0:
        return budget_marker
    if isinstance(value, str):
        return _bound_string(value, budget, max_string, string_marker)
    if isinstance(value, dict):
        return _bound_dict(value, seen, budget, max_string, string_marker, budget_marker)
    if isinstance(value, (list, tuple)):
        return _bound_list(value, seen, budget, max_string, string_marker, budget_marker)
    return value


def _bound_string(value: str, budget: List[int], max_string: int, string_marker: str) -> str:
    if len(value) <= max_string:
        budget[0] -= len(value)
        return value
    budget[0] -= max_string
    return value[:max_string] + string_marker


def _bound_container_enter(value: Any, seen: Set[int]) -> bool:
    """Register *value* for cycle detection; False when already visited."""
    if id(value) in seen:
        return False
    seen.add(id(value))
    return True


def _bound_dict(
    value: dict,
    seen: Set[int],
    budget: List[int],
    max_string: int,
    string_marker: str,
    budget_marker: str,
) -> dict:
    if not _bound_container_enter(value, seen):
        return CYCLE_MARKER
    try:
        out = {}
        for k, v in value.items():
            # str(k): a non-string key must not TypeError the whole payload
            # into the unserializable fallback (CodeRabbit on PR #351)
            out[str(k)] = _bound(v, seen, budget, max_string, string_marker, budget_marker)
            if budget[0] <= 0:
                out[budget_marker] = True
                break
        return out
    finally:
        seen.discard(id(value))


def _bound_list(
    value: Any,
    seen: Set[int],
    budget: List[int],
    max_string: int,
    string_marker: str,
    budget_marker: str,
) -> list:
    if not _bound_container_enter(value, seen):
        return CYCLE_MARKER
    try:
        out = []
        for v in value:
            out.append(_bound(v, seen, budget, max_string, string_marker, budget_marker))
            if budget[0] <= 0:
                out.append(budget_marker)
                break
        return out
    finally:
        seen.discard(id(value))
