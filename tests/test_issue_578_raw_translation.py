"""#578 Part 1: the audit row keeps what the model translated.

``VerificationLog.raw_llm_output`` existed and the audit chain hashed it, but
no route set it, so a verdict on a model's translation could not be
re-checked from its row. Every route that asks a model to translate now
stores the translation, as QWED parsed it, with the provider and model that
answered, as canonical JSON. It is never returned to the caller.

The rest of #585 comes with it: consensus, stats, fact and a natural-language
result the model calls not maths name the provider and model too.
"""

import hashlib
import io
import json
import threading
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings as hypothesis_settings, strategies as st

from qwed_new.api import main as api_main
from qwed_new.config import settings
from qwed_new.core import audit_logger as audit_module
from qwed_new.core.consensus_verifier import ConsensusResult, EngineResult, chain_record
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.fact_verifier import FactVerifier
from qwed_new.core.schemas import LogicVerificationTask, MathVerificationTask
from qwed_new.core.stats_verifier import StatsVerifier
from qwed_new.core.translation_record import (
    MAX_RECORD_CHARS,
    RAW_LLM_OUTPUT_KEY,
    Translation,
    audit_record,
    translation_of,
)
from qwed_new.core.translator import TranslationLayer
from tests.test_issue_320_logic_route_admission import QUESTION, _rows, client  # noqa: F401  (fixture)
from tests.test_issue_477_audit_batch_agents import (  # noqa: F401  (fixtures)
    _agent_verify,
    _batch,
    _trail_is_valid,
    agent,
    env,
)
from tests.test_issue_477_audit_batch_agents import _rows as _org_rows
from tests.test_issue_585_translation_model import _Configured

MODEL = "configured-model-578"
# Text the output sanitiser escapes or strips; the audit row keeps it as the
# model wrote it, and no response carries it.
MARKUP = "<script>alert(1)</script>"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _contains_key(value, key):
    if isinstance(value, dict):
        return key in value or any(_contains_key(v, key) for v in value.values())
    if isinstance(value, list):
        return any(_contains_key(v, key) for v in value)
    return False


def _entries(record):
    return json.loads(record)["translations"]


class _Model(_Configured):
    """The configured provider, with no network: it translates every kind."""

    confidence = 0.95
    fails = False

    def __init__(self):
        super().__init__(MODEL)

    def translate(self, user_query):
        if self.fails:
            raise RuntimeError("provider down")
        return MathVerificationTask(
            expression="0.15 * 200", claimed_answer=30.0, reasoning=f"15% of 200 {MARKUP}",
            confidence=self.confidence,
        )

    def translate_logic(self, user_query):
        if self.fails:
            raise RuntimeError("provider down")
        return LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5"], claim="x > 3", goal="VALIDITY")

    def translate_stats(self, query, columns):
        return "result = df['a'].mean()"

    def verify_fact(self, claim, context):
        return {"verdict": "SUPPORTED", "confidence": 0.9, "reasoning": MARKUP}


@pytest.fixture
def model(monkeypatch):
    """The configured provider for every translation layer: the control
    planes' own, and the ones each request builds."""
    instance = _Model()
    monkeypatch.setattr(settings, "ACTIVE_PROVIDER", "ollama")
    monkeypatch.setattr("qwed_new.core.translator.OllamaProvider", lambda: instance)
    for control_plane in (api_main.control_plane, api_main.batch_service.control_plane):
        monkeypatch.setattr(control_plane.router, "route", lambda query, preferred=None: "ollama")
        monkeypatch.setitem(control_plane.translator._providers, "ollama", instance)
    return instance


# ---------------------------------------------------------------- the record


def test_no_translation_is_no_record():
    assert audit_record([]) is None
    assert audit_record([None, None]) is None


def test_the_record_is_canonical_json_a_reader_can_rebuild():
    task = MathVerificationTask(expression="2 + 2", claimed_answer=4.0, reasoning="caf\u00e9 \u03c0", confidence=1.0)
    record = audit_record([Translation("math", task, "ollama", MODEL)])

    assert record.isascii()
    assert record == _canonical(json.loads(record))
    (entry,) = _entries(record)
    assert entry == {
        "kind": "math",
        "provider_used": "ollama",
        "translation_model": MODEL,
        "output": task.model_dump(mode="json"),
    }
    assert entry["output"]["reasoning"] == "caf\u00e9 \u03c0"


def test_a_consensus_entry_names_its_engine():
    (entry,) = _entries(audit_record([Translation("logic", {"x": 1}, "ollama", MODEL, engine="Z3")]))
    assert entry["engine"] == "Z3"


@pytest.mark.parametrize("extra", [-1, 0])
def test_a_record_up_to_the_bound_is_stored_whole(extra):
    base = audit_record([Translation("stats", "", None, None)])
    output = "x" * (MAX_RECORD_CHARS - len(base) + extra)
    record = audit_record([Translation("stats", output, None, None)])

    assert len(record) == MAX_RECORD_CHARS + extra
    assert _entries(record)[0]["output"] == output


@pytest.mark.parametrize("output", [
    "x" * (MAX_RECORD_CHARS + 1),
    # Each quote and backslash is escaped again in the preview.
    '"\\' * MAX_RECORD_CHARS,
    "\u00e9" * MAX_RECORD_CHARS,
], ids=["one-over", "escapes-twice", "non-ascii"])
def test_a_record_over_the_bound_is_its_length_hash_and_preview(output):
    full = _canonical({"translations": [Translation("stats", output, None, None).entry()]})
    record = audit_record([Translation("stats", output, None, None)])

    assert len(record) <= MAX_RECORD_CHARS
    stored = json.loads(record)
    assert stored["truncated"] is True
    assert stored["length"] == len(full)
    assert stored["sha256"] == hashlib.sha256(full.encode("ascii")).hexdigest()
    assert full.startswith(stored["preview"])


def test_a_lone_surrogate_is_escaped_so_the_row_can_be_stored():
    record = audit_record([Translation("fact", {"reasoning": "\ud800"}, None, None)])
    assert record.isascii()
    record.encode("utf-8")
    assert _entries(record)[0]["output"]["reasoning"] == "\ud800"


def test_a_number_the_model_wrote_as_nan_is_kept():
    record = audit_record([Translation("fact", {"confidence": float("nan")}, None, None)])
    assert "NaN" in record


def _deep(levels):
    nested = []
    for _ in range(levels):
        nested = [nested]
    return nested


@pytest.mark.parametrize("output", [
    {1: "a", "b": 2},  # keys of mixed types cannot be sorted
    _deep(100_000),  # deeper than json can write
])
def test_an_output_json_cannot_write_is_stored_as_that_fact(output):
    record = audit_record([Translation("fact", output, None, None)])
    assert json.loads(record) == {"unserializable": True, "translations": 1}


@hypothesis_settings(max_examples=150, deadline=None)
@given(st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=25,
))
def test_any_output_gives_a_bounded_ascii_record_that_reads_back(output):
    record = audit_record([Translation("fact", output, "ollama", MODEL)])

    assert record.isascii()
    assert len(record) <= MAX_RECORD_CHARS
    (entry,) = _entries(record)
    assert entry["output"] == output
    assert record == _canonical(json.loads(record))


# ---------------------------------------------------------------- naming


def test_the_translation_layer_names_the_provider_and_model():
    layer = TranslationLayer()
    layer._providers["openai"] = _Configured(MODEL)

    translation = layer.translation("math", "out", "OpenAI")

    assert translation.provider_used == "openai"
    assert translation.translation_model == MODEL


def test_a_shared_translation_layer_names_each_threads_own_provider():
    # last_resolved_provider is one attribute on a shared instance; the
    # provider is computed from each call's own key instead.
    layer = TranslationLayer()
    layer._providers.update({"openai": _Configured("model-a"), "anthropic": _Configured("model-b")})
    seen = []
    barrier = threading.Barrier(8)

    def run(key):
        barrier.wait()
        for _ in range(200):
            layer.last_resolved_provider = "anthropic" if key == "openai" else "openai"
            seen.append((key, layer.translation("math", key, key).provider_used))

    threads = [threading.Thread(target=run, args=(key,)) for key in ["openai", "anthropic"] * 4]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert seen and all(key == provider for key, provider in seen)


@pytest.mark.parametrize("translator", [
    None,
    SimpleNamespace(),
    MagicMock(),  # its translation() gives no Translation
    SimpleNamespace(translation=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("x"))),
])
def test_a_stand_in_translator_keeps_the_output_and_names_nothing(translator):
    translation = translation_of(translator, "math", {"expression": "1"}, engine="SymPy")
    assert translation == Translation("math", {"expression": "1"}, None, None, engine="SymPy")


# ---------------------------------------------------------------- DiagnosticResult


def test_the_record_is_on_the_result_for_the_audit_row_only():
    dr = replace(DiagnosticResult.unverifiable("not proven"), raw_llm_output='{"translations":[]}')

    assert "translations" not in json.dumps(dr.to_dict())
    assert DiagnosticResult.from_dict(dr.to_dict()).raw_llm_output is None


def test_the_record_survives_the_attestation_step():
    dr = replace(DiagnosticResult.verified("ok", developer_fields={}, evidence={"x": 1}), raw_llm_output="{}")
    assert dr.with_attestation("token").raw_llm_output == "{}"


def test_a_record_is_text():
    with pytest.raises(ValueError):
        replace(DiagnosticResult.unverifiable("not proven"), raw_llm_output={"x": 1})


# ---------------------------------------------------------------- routes


def test_the_natural_language_row_keeps_the_translation(client, isolated_audit_chain, model):  # noqa: F811
    body = client.post("/verify/natural_language", json={"query": "What is 15% of 200?"}).json()

    (row,) = _rows(isolated_audit_chain)
    (entry,) = _entries(row.raw_llm_output)
    assert entry["kind"] == "math"
    assert entry["provider_used"] == "ollama"
    assert entry["translation_model"] == MODEL
    assert entry["output"]["expression"] == "0.15 * 200"
    # As the model wrote it: the sanitiser never saw the audit copy.
    assert MARKUP in entry["output"]["reasoning"]
    assert not _contains_key(body, RAW_LLM_OUTPUT_KEY)
    assert MARKUP not in json.dumps(body)
    assert audit_module.get_audit_logger().verify_audit_trail(organization_id=1)["valid"] is True


def test_a_not_maths_result_names_the_model_and_keeps_the_translation(client, isolated_audit_chain, model):  # noqa: F811
    model.confidence = 0.3
    body = client.post("/verify/natural_language", json={"query": "Tell me a story"}).json()

    assert body["status"] == "UNVERIFIABLE"
    assert body["developer_fields"]["provider_used"] == "ollama"
    assert body["developer_fields"]["translation_model"] == MODEL
    (row,) = _rows(isolated_audit_chain)
    assert _entries(row.raw_llm_output)[0]["output"]["confidence"] == 0.3
    assert json.loads(row.result)["developer_fields"]["translation_model"] == MODEL


def test_a_failed_translation_stores_nothing(client, isolated_audit_chain, model):  # noqa: F811
    model.fails = True
    client.post("/verify/natural_language", json={"query": "What is 15% of 200?"})

    (row,) = _rows(isolated_audit_chain)
    assert row.raw_llm_output is None


def test_the_row_keeps_the_translation_when_the_trust_step_blocks(client, isolated_audit_chain, model):  # noqa: F811
    blocked = DiagnosticResult.blocked("attestation unavailable", {"constraint_id": "test.blocked"})
    with patch.object(api_main, "attest_and_enforce", return_value=blocked):
        body = client.post("/verify/natural_language", json={"query": "What is 15% of 200?"}).json()

    assert body["status"] == "BLOCKED"
    (row,) = _rows(isolated_audit_chain)
    assert _entries(row.raw_llm_output)[0]["output"]["expression"] == "0.15 * 200"


def test_the_logic_row_keeps_the_translation(client, isolated_audit_chain, model):  # noqa: F811
    body = client.post("/verify/logic", json={"query": QUESTION}).json()

    assert body["developer_fields"]["translation_model"] == MODEL
    (row,) = _rows(isolated_audit_chain)
    (entry,) = _entries(row.raw_llm_output)
    assert entry["kind"] == "logic"
    assert entry["output"] == {"variables": {"x": "Int"}, "constraints": ["x > 5"], "claim": "x > 3", "goal": "VALIDITY"}
    assert not _contains_key(body, RAW_LLM_OUTPUT_KEY)


def test_a_logic_translation_the_dsl_step_refuses_is_kept(client, isolated_audit_chain, model, monkeypatch):  # noqa: F811
    # The model returned a goal the DSL step cannot take: that output
    # decided the error, so the row keeps it.
    monkeypatch.setattr(
        model, "translate_logic",
        lambda query: LogicVerificationTask.model_construct(
            variables={"x": "Int"}, constraints=["x > 5"], claim=None, goal="OPTIMISE",
        ),
    )
    body = client.post("/verify/logic", json={"query": QUESTION}).json()

    assert body["status"] == "BLOCKED"
    (row,) = _rows(isolated_audit_chain)
    assert _entries(row.raw_llm_output)[0]["output"]["goal"] == "OPTIMISE"


def test_a_failed_logic_translation_stores_nothing(client, isolated_audit_chain, model):  # noqa: F811
    model.fails = True
    client.post("/verify/logic", json={"query": QUESTION})

    (row,) = _rows(isolated_audit_chain)
    assert row.raw_llm_output is None


def test_the_stats_result_names_the_model_and_the_row_keeps_the_code(client, isolated_audit_chain, model):  # noqa: F811
    with patch.object(StatsVerifier, "_select_sandbox", return_value=("blocked", None)):
        body = client.post(
            "/verify/stats",
            data={"query": "What is the mean of a?"},
            files={"file": ("data.csv", io.BytesIO(b"a\n1\n2\n3\n"), "text/csv")},
        ).json()

    assert body["status"] == "BLOCKED"
    assert body["developer_fields"]["provider_used"] == "ollama"
    assert body["developer_fields"]["translation_model"] == MODEL
    (row,) = _rows(isolated_audit_chain)
    (entry,) = _entries(row.raw_llm_output)
    assert entry == {
        "kind": "stats", "provider_used": "ollama", "translation_model": MODEL,
        "output": "result = df['a'].mean()",
    }
    assert not _contains_key(body, RAW_LLM_OUTPUT_KEY)


def test_the_fact_advisory_names_the_model_and_the_row_keeps_it(client, isolated_audit_chain, model):  # noqa: F811
    body = client.post(
        "/verify/fact",
        json={"claim": "The sky is green", "context": "Grass grows in fields.", "provider": "ollama"},
    ).json()

    (advisory,) = [c for c in body["developer_fields"]["advisory_checks"] if c["name"] == "llm_fallback"]
    assert advisory["details"]["provider_used"] == "ollama"
    assert advisory["details"]["translation_model"] == MODEL
    # The verdict is the deterministic one, so its own fields name no model.
    assert "translation_model" not in body["developer_fields"]
    (row,) = _rows(isolated_audit_chain)
    assert _entries(row.raw_llm_output)[0]["output"]["reasoning"] == MARKUP
    assert not _contains_key(body, RAW_LLM_OUTPUT_KEY)


def test_a_fact_check_without_the_model_stores_nothing(client, isolated_audit_chain, model):  # noqa: F811
    client.post("/verify/fact", json={"claim": "The sky is green", "context": "Grass grows in fields."})

    (row,) = _rows(isolated_audit_chain)
    assert row.raw_llm_output is None


def test_each_consensus_engine_names_its_model_and_the_row_keeps_them(client, isolated_audit_chain, model):  # noqa: F811
    body = client.post("/verify/consensus", json={"query": "What is 15% of 200?"}).json()

    (sympy,) = body["verification_chain"]
    assert sympy["provider_used"] == "ollama"
    assert sympy["translation_model"] == MODEL
    (row,) = _rows(isolated_audit_chain)
    (entry,) = _entries(row.raw_llm_output)
    assert entry["engine"] == "SymPy"
    assert entry["output"]["expression"] == "0.15 * 200"
    assert not _contains_key(body, RAW_LLM_OUTPUT_KEY)


def test_a_consensus_chain_without_translations_has_no_record():
    engine = EngineResult("Stats", "statistical_analysis", 1.0, 0.9, 1.0, True)
    assert chain_record([engine, SimpleNamespace(translation=Translation("math", 1, None, None))]) is None
    assert engine.provenance() == {"provider_used": None, "translation_model": None}
    result = ConsensusResult(None, 0.0, 1, "split", [engine], 1.0)
    assert result.raw_llm_output() is None


def test_a_batch_row_keeps_the_translation_and_the_job_does_not_return_it(env, model):  # noqa: F811
    body = _batch(env, [
        {"query": "What is 15% of 200?", "type": "natural_language"},
        {"query": QUESTION, "type": "logic"},
    ]).json()

    rows = _org_rows(env)
    kinds = sorted(_entries(row.raw_llm_output)[0]["kind"] for row in rows)
    assert kinds == ["logic", "math"]
    assert not _contains_key(body, RAW_LLM_OUTPUT_KEY)
    assert MARKUP not in json.dumps(body)
    assert _trail_is_valid(env)


def test_an_agent_row_keeps_the_translation(env, agent, monkeypatch):  # noqa: F811
    record = audit_record([Translation("math", {"expression": "2+2"}, "ollama", MODEL)])

    async def nl(query, organization_id=None, preferred_provider=None):
        return {"diagnostic": DiagnosticResult.unverifiable("not proven").to_dict(), RAW_LLM_OUTPUT_KEY: record}

    monkeypatch.setattr(api_main.control_plane, "process_natural_language", nl)
    body = _agent_verify(env, agent).json()

    (row,) = _org_rows(env)
    assert row.raw_llm_output == record
    assert not _contains_key(body, RAW_LLM_OUTPUT_KEY)
    assert _trail_is_valid(env)


# ---------------------------------------------------------------- the chain


def test_an_edited_translation_fails_verification(client, isolated_audit_chain, model):  # noqa: F811
    from sqlmodel import Session

    client.post("/verify/natural_language", json={"query": "What is 15% of 200?"})
    (row,) = _rows(isolated_audit_chain)
    with Session(isolated_audit_chain) as session:
        stored = session.get(type(row), row.id)
        stored.raw_llm_output = stored.raw_llm_output.replace("0.15 * 200", "0.25 * 200")
        session.add(stored)
        session.commit()

    trail = audit_module.get_audit_logger().verify_audit_trail(organization_id=1)
    assert trail["valid"] is False
