"""Checked-in vectors vs the shipped validator (issue #370).

Loads spec/api-key-test-vectors.json and asserts every vector classifies
as labeled — against validate_api_key_format() and against the regexes in
spec/api-key-format.json. This is the acceptance criterion "vectors verified
to pass/fail against the validator": any format drift breaks this test.

Scanner-safe by construction: the exact key strings live only in the JSON
file (neutral field names); this file holds no 16+ spaceless literals.
"""

import json
import re
from pathlib import Path

from qwed_new.auth.security import validate_api_key_format

SPEC_DIR = Path(__file__).resolve().parents[2] / "spec"


def _load(name):
    with open(SPEC_DIR / name, encoding="utf-8") as fh:
        return json.load(fh)


def test_vectors_match_validator_labels():
    data = _load("api-key-test-vectors.json")
    assert data["vectors"], "vectors file must not be empty"
    for vector in data["vectors"]:
        value = vector["value"]
        expected = vector["expected"]
        if expected == "excluded":
            # Test prefix: structurally checksum-valid, excluded by policy.
            assert value.startswith("qwed_test_")
            assert not value.startswith("qwed_live_")
        else:
            assert validate_api_key_format(value) == expected, vector["id"]


def test_vectors_match_spec_patterns():
    spec = _load("api-key-format.json")
    data = _load("api-key-test-vectors.json")
    patterns = {
        entry["status"]: re.compile(entry["full_pattern"] + r"\Z")
        for entry in spec["types"]
        for status in [entry["status"]]
    }
    by_id = {vector["id"]: vector for vector in data["vectors"]}
    for i in range(1, 6):
        assert patterns["current"].match(by_id[f"v2-valid-{i}"]["value"])
    for i in range(1, 4):
        assert patterns["legacy-accepted"].match(by_id[f"v1-valid-{i}"]["value"])
    # Shape-level negatives (checksum-bad still matches the regex by design:
    # checksums are post-processing, not pattern).
    assert not patterns["current"].match(by_id["v2-invalid-charset"]["value"])
    assert not patterns["current"].match(by_id["v2-invalid-short"]["value"])
    assert not patterns["current"].match(by_id["v2-invalid-long"]["value"])


def test_spec_names_match_partnership_filing():
    spec = _load("api-key-format.json")
    assert [entry["slug"] for entry in spec["types"]] == [
        "qwed_live_api_key",
        "qwed_live_api_key_v1",
    ]
    assert spec["excluded_prefixes"] == ["qwed_test_"]
