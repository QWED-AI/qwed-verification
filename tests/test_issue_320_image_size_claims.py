"""#320: /verify/image verified size claims that the image's dimensions had not decided.

``_verify_size_claim`` took the first dimension it found anywhere in a claim:
- "The resolution is not HD" on a 1920x1080 image was VERIFIED, as the claim
  held "hd" and the image is at least 1280x720;
- "width is 800 and height is 999" on an 800x600 image was VERIFIED, as the
  width matched and the height was never read;
- "This 800x600 image documents the CFO approving the $2M transfer" was
  VERIFIED, as it held "800x600".

The proof did not bind the claim or the image either, so different claims, or
the same claim on different images, shared one proof_ref.

These tests send each claim to the route.
"""

import pytest

from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)


def _png(width, height, filler=b"A" * 16):
    """The start of a PNG: its signature, then an IHDR chunk with the size."""
    size = width.to_bytes(4, "big") + height.to_bytes(4, "big")
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + size + filler


def _verify(client, image, claim):  # noqa: F811
    files = {"image": ("i.png", image, "image/png")}
    return client.post("/verify/image", files=files, data={"claim": claim}).json()


@pytest.mark.parametrize("claim", [
    # A negation.
    "The resolution is not HD",
    "The image is not 1920x1080",
    # "HD" is a convention, not a measurement.
    "The image is HD",
    # A claim that says more than the dimensions.
    "This 1920x1080 image documents the CFO approving the $2M transfer",
    "1920x1080, and the CEO signed it",
    # A comparison or a hedge.
    "The image is at least 1920x1080 pixels",
    "The image is about 1920 pixels wide",
])
def test_a_claim_the_dimensions_do_not_decide_is_unverifiable(client, claim):  # noqa: F811
    body = _verify(client, _png(1920, 1080), claim)

    assert body["status"] == "UNVERIFIABLE"
    assert body.get("proof_ref") is None


@pytest.mark.parametrize("claim, status", [
    # The width matched, so the height was never read.
    ("width is 800 and height is 999", "BLOCKED"),
    ("the height is 999 and the width is 800", "BLOCKED"),
    ("the width is 800 and the height is 600", "VERIFIED"),
    ("The image is 800 pixels wide and 600 pixels tall", "VERIFIED"),
])
def test_every_dimension_a_claim_names_is_checked(client, claim, status):  # noqa: F811
    body = _verify(client, _png(800, 600), claim)

    assert body["status"] == status


@pytest.mark.parametrize("claim, status", [
    ("800x600", "VERIFIED"),
    ("The image is 800x600 pixels.", "VERIFIED"),
    ("The image is 800 × 600", "VERIFIED"),
    ("the image has a height of 600 pixels", "VERIFIED"),
    ("1024 x 768", "BLOCKED"),
    ("width: 801", "BLOCKED"),
])
def test_a_plain_size_claim_is_still_decided(client, claim, status):  # noqa: F811
    body = _verify(client, _png(800, 600), claim)

    assert body["status"] == status


def test_the_proof_binds_the_claim_and_the_image(client):  # noqa: F811
    # The proof hashed only the dimensions and the reasoning, so it was the
    # same for each of these.
    image = _png(800, 600)
    other_image = _png(800, 600, filler=b"B" * 16)

    proofs = [
        _verify(client, image, "800x600"),
        _verify(client, image, "The image is 800x600 pixels"),
        _verify(client, other_image, "800x600"),
    ]

    assert [body["status"] for body in proofs] == ["VERIFIED"] * 3
    assert len({body["proof_ref"] for body in proofs}) == 3


def test_an_image_whose_dimensions_cannot_be_read_is_unverifiable(client):  # noqa: F811
    body = _verify(client, b"not an image at all", "800x600")

    assert body["status"] == "UNVERIFIABLE"
    assert body.get("proof_ref") is None
