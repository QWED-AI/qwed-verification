"""#392: every /verify route has a transport-level body cap, not only
/verify/stats. An oversized JSON body is rejected with 413 before the handler
reads it; a body within the cap is not rejected by the middleware."""
import os

os.environ.setdefault("QWED_CORS_ORIGINS", "*")

from qwed_new.api import main as api_main


def _limits():
    # The configured per-path caps the middleware is registered with.
    return api_main._BODY_LIMITS


def test_json_verify_routes_are_capped():
    limits = _limits()
    for path in api_main._VERIFY_JSON_PATHS:
        assert limits[path] == api_main._JSON_BODY_LIMIT_BYTES
    # the two multipart uploads keep their own, larger caps
    assert limits["/verify/stats"] == api_main._STATS_BODY_LIMIT_BYTES
    assert limits["/verify/image"] == api_main._IMAGE_BODY_LIMIT_BYTES


def test_oversized_json_body_rejected_413_before_handler():
    import asyncio

    async def scenario():
        oversized = b'{"query": "' + b"a" * (api_main._JSON_BODY_LIMIT_BYTES + 10) + b'"}'

        async def receive():
            return {"type": "http.request", "body": oversized, "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        async def app(scope, receive, send):
            raise AssertionError("handler must not see an oversized body")

        mw = api_main._BodySizeLimitMiddleware(
            app, limits=api_main._BODY_LIMITS,
            concurrency_paths={"/verify/stats", "/verify/image"},
        )
        await mw({"type": "http", "path": "/verify/code"}, receive, send)
        return sent

    sent = asyncio.run(scenario())
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413


def test_json_route_not_concurrency_gated():
    # A JSON route must not consume the upload concurrency slot: even at the
    # cap, a within-limit JSON body is forwarded.
    import asyncio

    async def scenario():
        async def receive():
            return {"type": "http.request", "body": b'{"query":"ok"}', "more_body": False}

        forwarded = []

        async def app(scope, receive, send):
            forwarded.append(True)
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b""})

        async def send(message):
            pass

        mw = api_main._BodySizeLimitMiddleware(
            app, limits=api_main._BODY_LIMITS,
            concurrency_paths={"/verify/stats", "/verify/image"},
        )
        api_main._BodySizeLimitMiddleware._in_flight = (
            api_main._BodySizeLimitMiddleware._max_concurrent
        )
        try:
            await mw({"type": "http", "path": "/verify/sql"}, receive, send)
        finally:
            api_main._BodySizeLimitMiddleware._in_flight = 0
        return forwarded

    forwarded = asyncio.run(scenario())
    assert forwarded == [True]  # reached the handler despite the slot being full
