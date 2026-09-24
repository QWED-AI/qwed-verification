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
    anchored = {
        entry["status"]: re.compile(entry["anchored_pattern"])
        for entry in spec["types"]
    }
    re2 = {
        entry["status"]: re.compile(entry["re2_pattern"])
        for entry in spec["types"]
    }
    group = {
        entry["status"]: entry["re2_token_group"]
        for entry in spec["types"]
    }
    for entry in spec["types"]:
        # RE2 has no lookarounds of any kind — a delimiter-class pattern
        # carrying one is un-compilable on the engines it targets (same
        # constraint GitHub secret-scanning patterns face). The class covers
        # (?=, (?! , (?<=, (?<! while leaving (?: and ( allowed.
        assert not re.search(
            r"\(\?(?:<[=!]|[=!])", entry["re2_pattern"]
        ), entry["status"]
    # Derived from the data, not hard-coded IDs: every vector declares the
    # spec status whose regex it must satisfy (or null for shape negatives).
    # Checksum-bad matches shape by design —
    # checksums are post-processing, not pattern (CodeRabbit on #387).
    # Anchored patterns are additionally exercised as find-in-text searches
    # wrapped in ordinary delimiters (Sentry MEDIUM + Greptile P1 on #387:
    # trailing word boundaries miss dash-ending bodies). The re2_pattern
    # alternates must yield the exact key in their token group — the whole
    # match includes consumed delimiters, which would break checksum
    # validation if submitted verbatim (Greptile P1 on docs #290).
    for vector in data["vectors"]:
        value = vector["value"]
        status = vector["pattern"]
        if status is None:
            assert not compiled["current"].match(value), vector["id"]
            assert not compiled["legacy-accepted"].match(value), vector["id"]
            for name, expression in anchored.items():
                assert expression.search(f"leaked {value} here.") is None, (
                    vector["id"],
                    name,
                )
            for name, expression in re2.items():
                assert expression.search(f"leaked {value} here.") is None, (
                    vector["id"],
                    name,
                )
        else:
            assert compiled[status].match(value), vector["id"]
            assert anchored[status].search(f"leaked {value} here."), vector["id"]
            match = re2[status].search(f"leaked {value} here.")
            assert match, vector["id"]
            assert match.group(group[status]) == value, vector["id"]


def test_re2_global_scan_resumes_after_token_group():
    """Two keys sharing one delimiter must both be found (docs #397).

    The delimiter-class re2_pattern consumes a character outside the key,
    so a scan that resumes after the WHOLE match swallows the delimiter the
    next key needs and misses it (the rule the scanning guidance documents:
    resume after the token group's end).
    """
    spec = _load("api-key-format.json")
    data = _load("api-key-test-vectors.json")
    entry = next(e for e in spec["types"] if e["status"] == "current")
    expression = re.compile(entry["re2_pattern"])
    g = entry["re2_token_group"]
    keys = [v["value"] for v in data["vectors"] if v["expected"] == "v2"][:2]
    assert len(keys) == 2
    text = "leaked " + " ".join(keys) + " here."

    found, pos = [], 0
    while (match := expression.search(text, pos)):
        found.append(match.group(g))
        pos = match.end(g)
    assert found == keys

    # Whole-match resume (the buggy alternative) silently drops key #2.
    assert [m.group(g) for m in expression.finditer(text)] == keys[:1]


def test_spec_names_match_partnership_filing():
    spec = _load("api-key-format.json")
    assert [entry["slug"] for entry in spec["types"]] == [
        "qwed_live_api_key",
        "qwed_live_api_key_v1",
    ]
    assert spec["excluded_prefixes"] == ["qwed_test_"]
