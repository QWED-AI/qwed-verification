"""#225: provider SDK exceptions embed internal topology — endpoint URLs,
deployment names, request IDs. That detail must stay in the server log for
operators and must NOT ride a raised exception (or a result dict) up to the API
layer or a client. sanitized_provider_error is the one place that policy lives."""
import logging

from qwed_new.providers.base import sanitized_provider_error


def test_returned_error_message_carries_no_internal_detail():
    detail = "connect to https://acct.openai.azure.com/deployments/gpt4-prod failed (request id 5f3a-internal)"
    err = sanitized_provider_error(
        logging.getLogger("t"), "Azure OpenAI translation failed", RuntimeError(detail)
    )
    assert isinstance(err, ValueError)
    assert str(err) == "Azure OpenAI translation failed."
    # None of the internal topology leaks into the message callers/clients see.
    assert "openai.azure.com" not in str(err)
    assert "deployments" not in str(err)
    assert "request id" not in str(err)
    assert detail not in str(err)


def test_full_detail_is_logged_for_operators(caplog):
    detail = "endpoint https://internal.example/deploy/x timed out"
    with caplog.at_level(logging.WARNING):
        sanitized_provider_error(
            logging.getLogger("qwed_provider_hygiene_test"), "Anthropic logic translation failed", RuntimeError(detail)
        )
    messages = [r.getMessage() for r in caplog.records]
    # Operators still get the real cause in the server log.
    assert any("internal.example" in m for m in messages)
    assert any("Anthropic logic translation failed" in m for m in messages)
