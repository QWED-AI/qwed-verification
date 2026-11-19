"""ConfigGuard's AWS secret key pattern and values that are public by shape.

The pattern takes any 40 base64 characters, so the Action's scan-secrets
reported every commit a workflow pins an action to, every sha256 proof
reference, every npm integrity hash, every comment rule of "=" and an
alphabet written out as an AWS secret key. Those shapes are read out; a
value that could be a key is reported as before.
"""

import base64
import hashlib
import json
import random
import re
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qwed_new.guards.canonical_text import decoded_json
from qwed_sdk.guards.config_guard import ConfigGuard

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# Generated, not written out, so no scanner reads them as real keys or
# commits.
_RNG = random.Random(20261119)
KEY = "".join(_RNG.choice(B64) for _ in range(40))
SHA = f"{_RNG.getrandbits(160):040x}"
PADDED_28 = base64.b64encode(_RNG.randbytes(28)).decode()  # 38 characters and "=="
PADDED_29 = base64.b64encode(_RNG.randbytes(29)).decode()  # 39 characters and "="
SHA256 = hashlib.sha256(b"qwed").hexdigest()
SHA384 = hashlib.sha384(b"qwed").hexdigest()
SHA512 = hashlib.sha512(b"qwed").hexdigest()
SRI = {name: base64.b64encode(hashlib.new(name, b"qwed").digest()).decode() for name in ("sha256", "sha384", "sha512")}
ALPHABET62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
RAW = re.compile(ConfigGuard.DEFAULT_SECRET_PATTERNS["AWS_SECRET_KEY"], re.IGNORECASE)


def test_the_values_have_the_shapes_the_tests_need():
    assert len(KEY) == 40
    assert not re.fullmatch(r"[0-9a-fA-F]+", KEY)
    assert not all(a < b for a, b in zip(KEY, KEY[1:]))
    assert len(PADDED_28) == 40
    assert PADDED_28.endswith("==")
    assert len(PADDED_29) == 40
    assert PADDED_29.endswith("=")
    assert re.fullmatch(r"[0-9a-f]{40}", SHA)


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


def test_a_lock_file_with_an_escape_passes():
    # Any backslash makes the guard read the JSON's strings too; each value is
    # read on its key's line, so "integrity" stays with its hash.
    lock = json.dumps({
        "name": "demo\tpackage",
        "packages": {"node_modules/a": {"integrity": f"sha512-{SRI['sha512']}"}},
    })
    assert "\\" in lock
    assert ConfigGuard().scan_string(lock)["verified"] is True


def test_a_key_in_a_lock_file_with_an_escape_is_reported():
    lock = json.dumps({"name": "demo\tpackage", "secret": KEY,
                       "packages": {"node_modules/a": {"integrity": f"sha512-{SRI['sha512']}"}}})
    assert "AWS_SECRET_KEY" in _types(lock)


def test_json_readings_keep_decoded_json_and_add_the_keyed_form():
    from qwed_new.guards.canonical_text import json_readings

    text = json.dumps({"a": "x\ty", "b": {"c": ["d", {"e": "f"}]}, "g": 1})
    readings = json_readings(text)
    assert readings is not None
    plain, keyed = readings
    assert plain == decoded_json(text)
    assert sorted(plain.split("\n")) == sorted(["a", "x\ty", "b", "c", "d", "e", "f", "g"])
    assert sorted(keyed.split("\n")) == sorted(["a: x\ty", "b", "c", "d", "e: f", "g"])


@pytest.mark.parametrize("text", ["no escape", "not json \\"], ids=["no escape", "not json"])
def test_json_readings_are_none_where_decoded_json_is(text):
    from qwed_new.guards.canonical_text import json_readings

    assert decoded_json(text) is None
    assert json_readings(text) is None


def test_public_shapes_pass_in_a_config_tree():
    # A value in a tree is read with its key, as in the file.
    config = {
        "steps": [{"uses": f"actions/checkout@{SHA}"}],
        "proof_ref": f"sha256:{SHA256}",
        "packages": {"node_modules/a": {"integrity": f"sha512-{SRI['sha512']}"}},
    }
    assert ConfigGuard().verify_config_safety(config)["verified"] is True


def test_a_tree_reads_no_key_but_uses_and_integrity():
    # Keys are not scanned, as on main: only a value under "uses" or
    # "integrity" is read with its key.
    assert ConfigGuard().verify_config_safety({"A" * 45: "short", "x" * 41: {"y": "z"}})["verified"] is True


@pytest.mark.parametrize("config", [
    {"steps": [{"uses": f"owner/repo@{KEY}"}]},
    {"commit": SHA},
    {"notintegrity": f"sha384-{SRI['sha384']}"},
    {"secret": PADDED_28},
    [f"actions/checkout@{SHA}"],
], ids=["key in uses", "commit field", "notintegrity", "padded token", "commit in a list"])
def test_a_tree_still_reports_what_is_not_public(config):
    violations = ConfigGuard().verify_config_safety(config).get("violations", [])
    assert "AWS_SECRET_KEY" in {v["type"] for v in violations}


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
    "after a rule": "=" * 44 + KEY,
    "28 bytes in base64, padded": f"api_secret: {PADDED_28}",
    "29 bytes in base64, padded": f"api_secret: {PADDED_29}",
    "an equals sign inside": KEY[:20] + "=" + KEY[20:39],
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


@pytest.mark.parametrize("char", ["\u200b", "\u00ad", "\ufeff", "\u2800", chr(0xE0041)])
def test_an_invisible_character_inside_the_key_does_not_hide_it(char):
    assert "AWS_SECRET_KEY" in _types(KEY[:17] + char + KEY[17:])


# Outside the shapes above a 40-character hex value is reported, as before:
# some services issue tokens of that shape.
NEAR_MISSES = {
    "commit field": f'"commit": "{SHA}"',
    "hex token": f"DD_APP_KEY={SHA}",
    "cargo rev": f'rev = "{SHA}"',
    "commented-out step": f"#  - uses: owner/repo@{SHA}\n",
    "uses with trailing text": f"  - uses: owner/repo@{SHA} extra\n",
    "uses with a comment glued on": f"  - uses: owner/repo@{SHA}#v4\n",
    "usesx key": f"  - usesx: owner/repo@{SHA}\n",
    "uses with no owner": f"  - uses: repo@{SHA}\n",
    "uses with an empty repository": f"  - uses: owner/@{SHA}\n",
    "uses with an empty repository and a path": f"  - uses: owner//path@{SHA}\n",
    "commit glued to a letter": f"  - uses: owner/repo@{SHA}x\n",
    "41 hex after the at sign": f"  - uses: owner/repo@{SHA}0\n",
    "sha256 label, 63 hex": f"sha256:{SHA256[:63]}",
    "sha256 label, 65 hex": f"sha256:{SHA256}0",
    "sha1 label on a sha256": f"sha1:{SHA256}",
    "label continuing a word": f"xsha256:{SHA256}",
    "label after an underscore": f"my_sha1:{SHA}",
    "label after a hyphen": f"x-sha256:{SHA256}",
    "integrity of the wrong length": f'"integrity": "sha512-{SRI["sha256"]}"',
    "integrity without padding": f'"integrity": "sha512-{SRI["sha512"].rstrip("=")}"',
    "integrity hash with no integrity key": f"sha512-{SRI['sha512']}",
    "integrity hash under another key": f'"checksum": "sha512-{SRI["sha512"]}"',
    "notintegrity": f'<script notintegrity="sha384-{SRI["sha384"]}">',
    "_integrity": f'_integrity="sha384-{SRI["sha384"]}"',
    "data-integrity": f'<script data-integrity="sha384-{SRI["sha384"]}">',
    "ascending but for one": ALPHABET62[:20] + ALPHABET62[21] + ALPHABET62[20] + ALPHABET62[22:],
    "one character repeated": "M" * 40,
    "a short value padded out": "abc" + "=" * 60,
}


@pytest.mark.parametrize("name", list(NEAR_MISSES))
def test_near_misses_are_still_reported(name):
    assert "AWS_SECRET_KEY" in _types(NEAR_MISSES[name])


# A label or key after, or written with, a character of another script is
# not the ASCII label or key, so the hash after it is reported, as on main.
OTHER_SCRIPTS = {
    "label after a Latin letter with an accent": f"\u00e9sha1:{SHA}",
    "label after a combining mark": f"e\u0301sha256:{SHA256}",
    "label after a Cyrillic letter": f"\u0436sha256:{SHA256}",
    "label after a Greek letter": f"\u03b1sha512:{SHA512}",
    "label after a full-width digit": f"\uff11sha1:{SHA}",
    "label after a zero-width space inside a name": f"x\u200bsha1:{SHA}",
    "label with a Cyrillic a": f"sh\u0430256:{SHA256}",
    "label with a Greek alpha": f"sh\u03b1256:{SHA256}",
    "full-width label": "\uff53\uff48\uff41\uff11\uff1a" + SHA,
    "integrity after a Latin letter with an accent": f'\u00e9integrity="sha384-{SRI["sha384"]}"',
    "integrity after a Cyrillic letter": f"\u0436integrity: sha256-{SRI['sha256']}",
    "integrity with a dotless i": f'"\u0131ntegrity": "sha512-{SRI["sha512"]}"',
    "integrity with a dotted capital I": f'"\u0130NTEGRITY": "sha512-{SRI["sha512"]}"',
    "integrity with a Cyrillic i": f'"integr\u0456ty": "sha512-{SRI["sha512"]}"',
    "full-width integrity": f'"\uff49ntegrity": "sha512-{SRI["sha512"]}"',
}


@pytest.mark.parametrize("name", list(OTHER_SCRIPTS))
def test_a_label_or_key_in_another_script_is_reported(name):
    assert "AWS_SECRET_KEY" in _types(OTHER_SCRIPTS[name])


@settings(max_examples=300, deadline=None)
@given(char=st.characters(exclude_categories=("Cs",)))
def test_a_label_or_key_counts_only_after_ascii_that_ends_a_name(char):
    # Public only after a character that ends a name: ASCII, and not a
    # letter, a digit, "_" or "-".
    ends_a_name = char.isascii() and not char.isalnum() and char not in "_-"
    for text in (f"{char}sha1:{SHA}", f"{char}integrity: sha256-{SRI['sha256']}"):
        assert ConfigGuard().scan_string(text)["verified"] is ends_a_name, (char, text)


def test_a_lookalike_letter_keeps_a_commit_reported():
    # U+212A KELVIN SIGN matches [a-z] without case and is not ASCII.
    text = f"  - uses: owner/repo@{SHA[:20]}\u212a{SHA[21:]}\n"
    assert RAW.search(text) is not None
    assert ConfigGuard().compiled_patterns["AWS_SECRET_KEY"].search(text) is not None


@pytest.mark.parametrize("length,reported", [(0, False), (39, False), (40, True), (41, True)])
def test_length_bounds_are_as_before(length, reported):
    value = (KEY * 2)[:length]
    assert ("AWS_SECRET_KEY" in _types(value)) is reported


def test_counts_are_the_patterns_own_where_nothing_is_public():
    text = f"a={KEY} b={KEY * 2} c={KEY[:30]}"
    wrapped = ConfigGuard().compiled_patterns["AWS_SECRET_KEY"]
    assert wrapped.findall(text) == RAW.findall(text)
    assert [m.span() for m in wrapped.finditer(text)] == [m.span() for m in RAW.finditer(text)]


@pytest.mark.parametrize("pattern", [r"[0-9a-f]{40}", ConfigGuard.DEFAULT_SECRET_PATTERNS["AWS_SECRET_KEY"]],
                         ids=["another pattern", "the default pattern, given"])
def test_a_custom_aws_pattern_is_searched_as_written(pattern):
    guard = ConfigGuard(custom_patterns={"AWS_SECRET_KEY": pattern})
    assert guard.scan_string(f"  - uses: owner/repo@{SHA}\n")["verified"] is False


# A caller's pattern reads a value alone, as on main; only the built-in AWS
# secret key pattern reads it with its key.
HEX_ALONE = r"(?m)^[0-9a-f]{40}$"
PINNED_ALONE = r"(?m)^actions/checkout@[0-9a-f]{40}$"


def _escaped(value):
    return "".join(f"\\u{ord(char):04x}" for char in value)


@pytest.mark.parametrize("config", [
    {"uses": SHA},
    {"integrity": SHA},
    {"steps": [{"uses": SHA}]},
], ids=["uses", "integrity", "a step"])
def test_a_custom_pattern_reads_a_tree_value_alone(config):
    violations = ConfigGuard(custom_patterns={"HEX": HEX_ALONE}).verify_config_safety(config)["violations"]
    assert "HEX" in {v["type"] for v in violations}


@pytest.mark.parametrize("key", ["uses", "integrity", "commit"])
def test_a_custom_pattern_reads_an_escaped_json_value_alone(key):
    text = json.dumps({key: "x"}).replace('"x"', f'"{_escaped(SHA)}"')
    assert json.loads(text) == {key: SHA}
    assert "HEX" in {f["type"] for f in ConfigGuard(custom_patterns={"HEX": HEX_ALONE}).scan_string(text)["secrets_found"]}


def test_each_pattern_reads_a_pinned_step_its_own_way():
    guard = ConfigGuard(custom_patterns={"PINNED": PINNED_ALONE})
    step = f"actions/checkout@{SHA}"
    tree = guard.verify_config_safety({"steps": [{"uses": step}]})["violations"]
    assert {v["type"] for v in tree} == {"PINNED"}
    text = json.dumps({"uses": "x"}).replace('"x"', f'"{_escaped(step)}"')
    assert {f["type"] for f in guard.scan_string(text)["secrets_found"]} == {"PINNED"}


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
    KEY, SHA, SHA256, SRI["sha512"], ALPHABET62, "=" * 44, PADDED_28,
    "uses: o/r@", "- ", "sha256:", "sha512-", "sha1:", "@", "=", "x", " ", "\n", "#", '"', ":",
    "integrity: ", "\u0131ntegrity: ", "\u00e9", "\u0436", "\u0301", "\u200b",
]


@settings(max_examples=400, deadline=None)
@given(pieces=st.lists(st.sampled_from(PIECES), max_size=12))
def test_only_whole_public_runs_are_dropped(pieces):
    text = "".join(pieces)
    wrapped = ConfigGuard().compiled_patterns["AWS_SECRET_KEY"]
    kept = [m.span() for m in wrapped.finditer(text)]
    # Never a match the pattern does not find.
    assert set(kept) <= {m.span() for m in RAW.finditer(text)}
    # Every place a key or a padded token sits is still reported.
    for value in (KEY, PADDED_28):
        at = text.find(value)
        while at != -1:
            assert any(s < at + len(value) and e > at for s, e in kept), (value, text)
            at = text.find(value, at + 1)
