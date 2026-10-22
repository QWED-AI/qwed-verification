"""The API key behind the current request, for the audit row it writes (#484).

``get_current_tenant`` records the key's id here once it has checked the key.
``AuditLogger`` reads it when it appends a row, so every verify route records
its caller without passing the id through each ``VerificationLog`` it builds.

A ``ContextVar`` is per request: each request runs in its own context, and
worker threads (``asyncio.to_thread``, Starlette's threadpool) and tasks the
request starts get a copy of it. A request that never passed through
``get_current_tenant`` reads None: a user session, the audit seed, and
/agents/{agent_id}/verify, which authenticates with an agent token.
"""

from contextvars import ContextVar

_api_key_id: ContextVar[int | None] = ContextVar("qwed_request_api_key_id", default=None)


def set_request_api_key_id(api_key_id: int | None) -> None:
    """Record the id of the API key that authenticated this request."""
    _api_key_id.set(api_key_id)


def request_api_key_id() -> int | None:
    """The id of the API key that authenticated this request, or None."""
    return _api_key_id.get()
