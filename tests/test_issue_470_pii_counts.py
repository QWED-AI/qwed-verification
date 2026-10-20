"""#470: `qwed pii` printed a count of 1 for every entity type.

`PIIDetector.detect_and_mask` reported `types` as a de-duplicated list, and
the CLI counted each type in that list, so two emails printed
`EMAIL_ADDRESS: 1`. The report now has `type_counts`, one count per type
over every hit, and the CLI prints those.

Presidio is replaced with fakes here, so these tests run without the
`qwed[pii]` extra.
"""

from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import qwed_sdk.pii_detector as pii_module
from qwed_sdk.cli import cli
from qwed_sdk.pii_detector import PIIDetector

TEXT = "Mail a@example.com or b@example.com, call 555-0100, card 4532-1234-5678-9010"


def _hit(entity_type, start, end):
    return SimpleNamespace(entity_type=entity_type, start=start, end=end)


HITS = [
    _hit("EMAIL_ADDRESS", 5, 18),
    _hit("PHONE_NUMBER", 42, 50),
    _hit("EMAIL_ADDRESS", 22, 35),
    _hit("CREDIT_CARD", 57, 76),
]


class _FakeAnalyzer:
    def __init__(self, hits):
        self.hits = hits

    def analyze(self, text, entities, language):
        return list(self.hits)


class _FakeAnonymizer:
    def anonymize(self, text, analyzer_results, operators):
        return SimpleNamespace(text="<masked>")


def _detector(monkeypatch, hits):
    monkeypatch.setattr(pii_module, "OperatorConfig", lambda *args, **kwargs: (args, kwargs), raising=False)
    detector = object.__new__(PIIDetector)
    detector.analyzer = _FakeAnalyzer(hits)
    detector.anonymizer = _FakeAnonymizer()
    detector.entities = PIIDetector.DEFAULT_ENTITIES
    return detector


def test_the_report_counts_every_hit_per_type(monkeypatch):
    _, report = _detector(monkeypatch, HITS).detect_and_mask(TEXT)

    assert report["pii_detected"] == 4
    assert report["type_counts"] == {"CREDIT_CARD": 1, "EMAIL_ADDRESS": 2, "PHONE_NUMBER": 1}
    assert sum(report["type_counts"].values()) == report["pii_detected"]


def test_types_lists_each_type_once_in_a_stable_order(monkeypatch):
    _, report = _detector(monkeypatch, HITS).detect_and_mask(TEXT)

    assert report["types"] == ["CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER"]
    assert len(report["positions"]) == 4


def test_no_hits_gives_empty_counts(monkeypatch):
    masked, report = _detector(monkeypatch, []).detect_and_mask("nothing here")

    assert masked == "nothing here"
    assert report == {"pii_detected": 0, "types": [], "type_counts": {}}


class _FakeDetector:
    report = None  # set by run_pii before each call

    def detect_and_mask(self, text):
        return "<masked>", self.report


@pytest.fixture
def run_pii(monkeypatch):
    def run(report):
        _FakeDetector.report = report
        monkeypatch.setattr(pii_module, "PIIDetector", _FakeDetector)
        result = CliRunner().invoke(cli, ["pii", TEXT])
        assert result.exit_code == 0, result.output
        return result.output

    return run


def test_the_cli_prints_the_real_count_for_each_type(run_pii):
    output = run_pii({
        "pii_detected": 4,
        "types": ["CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER"],
        "type_counts": {"CREDIT_CARD": 1, "EMAIL_ADDRESS": 2, "PHONE_NUMBER": 1},
        "positions": [],
    })

    assert "EMAIL_ADDRESS: 2" in output
    assert "EMAIL_ADDRESS: 1" not in output
    assert "PHONE_NUMBER: 1" in output
    assert "CREDIT_CARD: 1" in output
    # Sorted by type.
    assert output.index("CREDIT_CARD") < output.index("EMAIL_ADDRESS") < output.index("PHONE_NUMBER")


def test_the_cli_counts_from_positions_for_an_older_report(run_pii):
    # A report without type_counts (an older detector) is counted from positions.
    output = run_pii({
        "pii_detected": 2,
        "types": ["EMAIL_ADDRESS"],
        "positions": [
            {"start": 5, "end": 18, "type": "EMAIL_ADDRESS"},
            {"start": 22, "end": 35, "type": "EMAIL_ADDRESS"},
        ],
    })

    assert "EMAIL_ADDRESS: 2" in output


def test_the_cli_prints_no_types_when_nothing_was_found(run_pii):
    output = run_pii({"pii_detected": 0, "types": [], "type_counts": {}})

    assert "Detected: 0 entities" in output
    assert " - " not in output
