"""ConfigGuard's AWS secret key pattern and values that are public by shape.

The pattern takes any 40 base64 characters, so the Action's scan-secrets
reported every commit a workflow pins an action to, every sha256 proof
reference, every npm integrity hash, every comment rule of "=" and an
alphabet written out as an AWS secret key. Those shapes are read out; a
value that could be a key is reported as before.
"""

import base64
import hashlib
import random
import re
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qwed_sdk.guards.config_guard import ConfigGuard

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# Generated, not written out, so no scanner reads it as a real key.
_RNG = random.Random(20261119)
KEY = "".join(_RNG.choice(B64) for _ in range(40))
SHA = hashlib.sha1(b"qwed").hexdigest()
SHA256 = hashlib.sha256(b"qwed").hexdigest()
SHA384 = hashlib.sha384(b"qwed").hexdigest()
SHA512 = hashlib.sha512(b"qwed").hexdigest()
SRI = {name: base64.b64encode(hashlib.new(name, b"qwed").digest()).decode() for name in ("sha256", "sha384", "sha512")}
ALPHABET62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def test_the_key_has_the_shape_of_a_key():
    assert len(KEY) == 40 and not re.fullmatch(r"[0-9a-fA-F]+", KEY)
    assert not all(a < b for a, b in zip(KEY, KEY[1:]))


def _types(text):
    result = ConfigGuard().scan_string(text)
    return {found["type"] for found in result.get("secrets_found", [])}


PUBLIC = {
    "pinned action": f"      - uses: actions/checkout@{SHA} # v7\n",
    "pinned action, no comment": f"    uses: actions/setup-python@{SHA}",
    "pinned reusable workflow": f"    uses: owner/repo/.github/workflows/build.yml@{SHA}\n",
    "pinned action, quoted": f'  - uses: "owner/repo@{SHA}"  # v1\n',
    "pinned action, CRLF": f"  - uses: owner/repo@{SHA}\r\n  - run: echo\r\n",
    "pinned action, upper-case commit": f"  - uses: owner/repo@{SHA.upper()}\n",
    "two pinned actions": f"- uses: a/b@{SHA}\n- uses: c/d@{SHA[::-1]}\n",
    "sha1 digest": f"sha1:{SHA}",
    "sha256 digest": f'"proof_ref": "sha256:{SHA256}"',
    "sha256 digest, upper-case label": f"SHA256:{SHA256}",
    "sha384 digest": f"sha384:{SHA384}",
    "sha512 digest": f"sha512:{SHA512}",
    "docker digest": f"image: qwedai/qwed-verification@sha256:{SHA256}",
    "npm integrity sha512": f'"integrity": "sha512-{SRI["sha512"]}",',
    "html integrity sha384": f'<script integrity="sha384-{SRI["sha384"]}"></script>',
    "yaml integrity sha256": f"integrity: sha256-{SRI['sha256']}",
    "comment rule": "# " + "=" * 44 + "\n",
    "long rule": "=" * 200,
    "padding after a short value": "abc" + "=" * 60,
    "base62 alphabet": f'"encoding": "Base62, alphabet {ALPHABET62}, zero-padded"',
}


@pytest.mark.parametrize("name", list(PUBLIC))
def test_public_shapes_are_not_secrets(name):
    assert "AWS_SECRET_KEY" not in _types(PUBLIC[name])


def test_a_workflow_of_pinned_steps_passes():
    workflow = (
        "jobs:\n  build:\n    steps:\n"
        f"      - uses: actions/checkout@{SHA} # v7\n"
        "        with:\n          persist-credentials: false\n"
        f"      - uses: actions/setup-node@{SHA[::-1]} # v6\n"
        "  # " + "=" * 44 + "\n"
    )
    assert ConfigGuard().scan_string(workflow)["verified"] is True


def test_public_shapes_pass_in_a_config_tree():
    config = {"steps": [{"uses": f"actions/checkout@{SHA}"}], "proof_ref": f"sha256:{SHA256}"}
    # In a tree the value is checked alone: "actions/checkout@<commit>" has no
    # "uses:" line around it, so only the digest is read out.
    result = ConfigGuard().verify_config_safety(config)
    assert [v["path"] for v in result.get("violations", [])] == ["steps[0].uses"]


KEY_LIKE = {
    "bare": KEY,
    "assigned in env": f"AWS_SECRET_ACCESS_KEY={KEY}",
    "assigned with spaces": f"aws_secret_access_key = {KEY}",
    "json": f'{{"secret": "{KEY}"}}',
    "yaml": f"secret: {KEY}\n",
    "glued before": "x" + KEY,
    "glued after": KEY + "x",
    "padded": KEY + "==",
    "after an equals sign": "=" + KEY,
    "in a uses line": f"  - uses: owner/repo@{KEY}\n",
    "after a sha256 label": f"sha256:{KEY}",
    "after a sha1 label": f"sha1:{KEY}",
    "after an integrity label": f"sha512-{KEY}",
    "in an integrity value": f'"integrity": "sha512-{KEY}"',
    "upper case": KEY.upper(),
    "lower case": KEY.lower(),
}


@pytest.mark.parametrize("name", list(KEY_LIKE))
def test_a_value_shaped_like_a_key_is_still_reported(name):
    assert "AWS_SECRET_KEY" in _types(KEY_LIKE[name])


@pytest.mark.parametrize("char", ["​", "­", "﻿", "⠀", chr(0xE0041)])
def test_an_invisible_character_inside_the_key_does_not_hide_it(char):
    assert "AWS_SECRET_KEY" in _types(KEY[:17] + char + KEY[17:])


# 40-character hex outside the shapes above: some services issue tokens of
# that shape, so these are reported, as before.
HEX_STILL_REPORTED = {
    "commit field": f'"commit": "{SHA}"',
    "hex token": f"DD_APP_KEY={SHA}",
    "cargo rev": f'rev = "{SHA}"',
    "commented-out step": f"#  - uses: owner/repo@{SHA}\n",
    "uses with trailing text": f"  - uses: owner/repo@{SHA} extra\n",
    "usesx key": f"  - usesx: owner/repo@{SHA}\n",
    "uses with no owner": f"  - uses: repo@{SHA}\n",
    "commit glued to a letter": f"  - uses: owner/repo@{SHA}x\n",
    "41 hex after the at sign": f"  - uses: owner/repo@{SHA}0\n",
    "sha256 label, 63 hex": f"sha256:{SHA256[:63]}",
    "sha256 label, 65 hex": f"sha256:{SHA256}0",
    "sha1 label on a sha256": f"sha1:{SHA256}",
    "label continuing a word": f"xsha256:{SHA256}",
    "integrity of the wrong length": f'"integrity": "sha512-{SRI["sha256"]}"',
    "integrity without padding": f'"integrity": "sha512-{SRI["sha512"].rstrip("=")}"',
    "integrity hash with no integrity key": f"sha512-{SRI['sha512']}",
    "integrity hash under another key": f'"checksum": "sha512-{SRI["sha512"]}"',
    "ascending but for one": ALPHABET62[:20] + ALPHABET62[21] + ALPHABET62[20] + ALPHABET62[22:],
    "one character repeated": "M" * 40,
}


@pytest.mark.parametrize("name", list(HEX_STILL_REPORTED))
def test_near_misses_are_still_reported(name):
    assert "AWS_SECRET_KEY" in _types(HEX_STILL_REPORTED[name])


def test_a_lookalike_letter_keeps_a_commit_reported():
    # U+212A KELVIN SIGN matches [a-z] without case and is not ASCII.
    text = f"  - uses: owner/repo@{SHA[:20]}K{SHA[21:]}\n"
    raw = re.compile(ConfigGuard.DEFAULT_SECRET_PATTERNS["AWS_SECRET_KEY"], re.IGNORECASE)
    assert raw.search(text) is not None
    assert ConfigGuard().compiled_patterns["AWS_SECRET_KEY"].search(text) is not None


@pytest.mark.parametrize("length,reported", [(0, False), (39, False), (40, True), (41, True)])
def test_length_bounds_are_as_before(length, reported):
    value = (KEY * 2)[:length]
    assert ("AWS_SECRET_KEY" in _types(value)) is reported


def test_counts_are_the_patterns_own_where_nothing_is_public():
    text = f"a={KEY} b={KEY * 2} c={KEY[:30]}"
    raw = re.compile(ConfigGuard.DEFAULT_SECRET_PATTERNS["AWS_SECRET_KEY"], re.IGNORECASE)
    wrapped = ConfigGuard().compiled_patterns["AWS_SECRET_KEY"]
    assert wrapped.findall(text) == raw.findall(text)
    assert [m.span() for m in wrapped.finditer(text)] == [m.span() for m in raw.finditer(text)]


def test_a_custom_aws_pattern_is_searched_as_written():
    guard = ConfigGuard(custom_patterns={"AWS_SECRET_KEY": r"[0-9a-f]{40}"})
    assert guard.scan_string(f"  - uses: owner/repo@{SHA}\n")["verified"] is False


@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    "text",
    [
        "A" * 200_000,
        "=" * 200_000,
        " ".join(f"@{SHA}" for _ in range(20_000)),
        "\n".join(f"- uses: o/r@{SHA}" for _ in range(20_000)),
        ALPHABET62 * 3_000,
        "  - uses: o/" + "a" * 100_000 + "".join(f" @{SHA}" for _ in range(5_000)),
    ],
    ids=["run", "rule", "many commits on one line", "many pinned steps", "repeated alphabet", "long uses line"],
)
def test_long_inputs_are_read_in_linear_time(text):
    started = time.perf_counter()
    ConfigGuard().scan_string(text)
    assert time.perf_counter() - started < 10


PIECES = [
    KEY, SHA, SHA256, SRI["sha512"], ALPHABET62, "=" * 44,
    "uses: o/r@", "- ", "sha256:", "sha512-", "sha1:", "@", "=", "x", " ", "\n", "#", '"', ":",
]


@settings(max_examples=400, deadline=None)
@given(pieces=st.lists(st.sampled_from(PIECES), max_size=12))
def test_only_whole_public_runs_are_dropped(pieces):
    text = "".join(pieces)
    raw = re.compile(ConfigGuard.DEFAULT_SECRET_PATTERNS["AWS_SECRET_KEY"], re.IGNORECASE)
    wrapped = ConfigGuard().compiled_patterns["AWS_SECRET_KEY"]
    kept = [m.span() for m in wrapped.finditer(text)]
    # Never a match the pattern does not find.
    assert set(kept) <= {m.span() for m in raw.finditer(text)}
    # A run that holds the key is never read out.
    if KEY in text:
        assert kept, text
