"""What the LangChain and CrewAI tools tell an agent about a QWED result (#606).

``VerificationResult.is_verified`` is the server's admission. A result that is
not admitted is one of three things:

- decided against the input: ``VERIFIED`` with ``is_valid`` false (a false
  claim, unsafe code, unsafe SQL);
- decided for an LLM's translation of the query, which nothing verifies yet
  (#585): ``VERIFIED`` and not admitted, from ``/verify/natural_language``;
- not decided at all: ``UNVERIFIABLE`` or ``BLOCKED`` (no claim, a timeout, a
  limit, input that does not parse).

The tools read ``is_verified`` alone and called all three incorrect or unsafe,
and read ``message``, ``corrected`` and ``vulnerabilities``, which no route
sends. These helpers give each case its own answer, from the fields the
server does send: ``agent_message``, ``is_valid``, ``issues`` and, for
natural language, ``translated_expression`` and ``calculated_value``.

The client's own ``UNVERIFIABLE`` result for a server it could not reach
(``verify_code``, ``verify_sql``) puts its reason in ``message`` and
``error``, so those are read after the server's fields: an agent can then
tell an outage from an input QWED could not decide.
"""

from typing import Any, List, Optional

TRANSLATION_NOT_VERIFIED = (
    "it was translated from your query by an LLM, and that translation is not verified"
)


def server_message(result: Any) -> str:
    """The server's own message for *result*, or an empty string. For a
    server the client could not reach, the client's reason (``message``,
    then ``error``)."""
    data = result.result or {}
    return str(
        data.get("agent_message")
        or data.get("error")
        or data.get("message")
        or result.error
        or ""
    )


def undecided_answer(result: Any) -> Optional[str]:
    """The answer for a result QWED did not decide (``UNVERIFIABLE``,
    ``BLOCKED`` or a status it does not know), or None for a ``VERIFIED``
    one. It is never "incorrect" or "unsafe": nothing was decided."""
    if result.status == "VERIFIED":
        return None
    message = server_message(result)
    if result.status == "UNVERIFIABLE":
        return f"⚠️ UNVERIFIABLE: {message or 'QWED could not decide this'}"
    return f"⛔ {result.status}: {message or 'verification failed'}"


def natural_language_answer(result: Any, admitted: str) -> str:
    """The answer for a ``/verify/natural_language`` result. *admitted* is
    the tool's message for an admitted one.

    A ``VERIFIED`` result covers the expression an LLM translated from the
    query, so it is not admitted, and the answer says what holds or fails
    for that expression and that the translation is not verified."""
    if result.is_verified:
        return admitted
    undecided = undecided_answer(result)
    if undecided is not None:
        return undecided
    data = result.result or {}
    expression = data.get("translated_expression")
    scope = f" for the translated expression {expression}" if expression else ""
    if data.get("is_valid") is False:
        value = data.get("calculated_value")
        found = f" Its value is {value}." if value is not None else ""
        return (
            f"❌ INCORRECT{scope}: {server_message(result) or 'the claim is false'}.{found} "
            f"Not admitted: {TRANSLATION_NOT_VERIFIED}."
        )
    return f"⚠️ HOLDS, NOT ADMITTED: the claim holds{scope}, but {TRANSLATION_NOT_VERIFIED}."


def code_issue_lines(result: Any, limit: int) -> List[str]:
    """``severity: description`` for the first *limit* entries of the
    ``issues`` a ``/verify/code`` result lists."""
    issues = (result.result or {}).get("issues")
    if not isinstance(issues, list):
        return []
    return [
        f"{issue.get('severity', '')}: {issue.get('description', '')}"
        for issue in issues[:limit]
        if isinstance(issue, dict)
    ]
