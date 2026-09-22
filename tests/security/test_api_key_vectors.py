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
    patterns = {entry["status"]: entry["full_pattern"] for entry in spec["types"]}
    compiled = {status: re.compile(pattern + r"\Z") for status, pattern in patterns.items()}
    # Derived from the data, not hard-coded IDs: every vector declares the
    # spec status whose regex it must satisfy (or null for shape negatives),
    # so a newly added vector cannot silently skip pattern coverage
    # (Greptile P2 on #387). Checksum-bad matches shape by design —
    # checksums are post-processing, not pattern (CodeRabbit on #387).
    for vector in data["vectors"]:
        value = vector["value"]
        status = vector["pattern"]
        if status is None:
            assert not compiled["current"].match(value), vector["id"]
            assert not compiled["legacy-accepted"].match(value), vector["id"]
        else:
            assert compiled[status].match(value), vector["id"]


def test_spec_names_match_partnership_filing():
    spec = _load("api-key-format.json")
    assert [entry["slug"] for entry in spec["types"]] == [
        "qwed_live_api_key",
        "qwed_live_api_key_v1",
    ]
    assert spec["excluded_prefixes"] == ["qwed_test_"]
