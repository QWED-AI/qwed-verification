"""The API key behind the current request, and when it started, for the
audit row it writes (#484, #528).

``get_current_tenant`` records the key's id here once it has checked the key.
``AuditLogger`` reads it when it appends a row, so every verify route records
its caller without passing the id through each ``VerificationLog`` it builds.

A ``ContextVar`` is per request: each request runs in its own context, and
worker threads (``asyncio.to_thread``, Starlette's threadpool) and tasks the
request starts get a copy of it. A request that never passed through
``get_current_tenant`` reads None: a user session, the audit seed, and
/agents/{agent_id}/verify, which authenticates with an agent token.

``RequestTimingMiddleware`` records when each HTTP request started, so the
audit row can store how long the route took (``request_latency_ms``). Outside
a request (a script, a test calling the logger) there is no start, and the
row records no latency.
"""

import time
from contextvars import ContextVar
from typing import Any

_api_key_id: ContextVar[int | None] = ContextVar("qwed_request_api_key_id", default=None)
_request_started: ContextVar[float | None] = ContextVar("qwed_request_started", default=None)


def set_request_api_key_id(api_key_id: int | None) -> None:
    """Record the id of the API key that authenticated this request."""
    _api_key_id.set(api_key_id)


def request_api_key_id() -> int | None:
    """The id of the API key that authenticated this request, or None."""
    return _api_key_id.get()


def request_latency_ms() -> int | None:
    """Whole milliseconds since the current request started, or None outside one."""
    started = _request_started.get()
    if started is None:
        return None
    return max(0, round((time.perf_counter() - started) * 1000))


class RequestTimingMiddleware:
    """Record when each HTTP request starts, for ``request_latency_ms`` (#528).

    Plain ASGI, so the start is set in the request's own context, which the
    route, its dependencies and the worker threads it starts all copy.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token = _request_started.set(time.perf_counter())
        try:
            await self.app(scope, receive, send)
        finally:
            _request_started.reset(token)
