"""Contacts and links point to qwedai.tech, the only QWED domain.

Covers the strings the domain move changed in code: the docs links on the
exception classes, the 500-error hint that named a status host that never
existed, and the throwaway address ``qwed init`` signs up with.
"""

import re
from unittest.mock import MagicMock, patch

import pytest
from pydantic import EmailStr, TypeAdapter

from qwed_new.core.exceptions import (
    QWEDAPIError,
    QWEDConfigError,
    QWEDDependencyError,
    QWEDError,
    QWEDSymbolNotFoundError,
    QWEDSyntaxError,
    QWEDVerificationError,
)
from qwed_sdk import cli

DOCS = "https://docs.qwedai.tech/"


@pytest.mark.parametrize(
    "error, page",
    [
        (QWEDError("x"), "faq"),
        (QWEDSyntaxError("bad token", expression="x +"), "api/dsl-reference"),
        (QWEDSymbolNotFoundError("y"), "api/dsl-reference#variables"),
        (QWEDVerificationError("x"), "engines/overview"),
        (QWEDConfigError("x"), "getting-started/installation"),
        (QWEDAPIError("x", status_code=401), "api/authentication"),
        (QWEDDependencyError("z3-solver"), "getting-started/installation"),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, Exception) else v,
)
def test_exception_docs_links_go_straight_to_the_page(error, page):
    assert error.docs_url == DOCS + page


def test_a_syntax_error_shows_its_docs_link():
    text = str(QWEDSyntaxError("bad token", expression="x +", column=2))

    assert "Syntax Error: bad token" in text
    assert "📚 Docs: " + DOCS + "api/dsl-reference" in text


def test_the_server_error_hint_names_no_status_host():
    error = QWEDAPIError("boom", status_code=500)

    assert error.suggestion == "Server error. Check the QWED server logs and retry."
    assert "status." not in str(error)


def _signup_email(org_name):
    response = MagicMock(status_code=201)
    response.json.return_value = {"access_token": "token", "key": "qwed_live_x"}
    client = MagicMock()
    client.post.return_value = response
    client.__enter__.return_value = client
    with patch("httpx.Client", return_value=client):
        assert cli._bootstrap_api_key("http://localhost:8000", org_name)[0] == "qwed_live_x"
    return client.post.call_args_list[0].kwargs["json"]["email"]


@pytest.mark.parametrize("org_name", ["Acme", "A" * 200, "x-" * 100, "!!!"])
def test_qwed_init_signs_up_with_a_valid_example_com_address(org_name):
    email = _signup_email(org_name)

    local, _, domain = email.partition("@")
    assert domain == "example.com"
    assert len(local) <= 64
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*-[0-9a-f]{8}", local)
    # The server's signup model validates the address with EmailStr.
    assert TypeAdapter(EmailStr).validate_python(email) == email
