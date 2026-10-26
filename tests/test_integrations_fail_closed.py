"""The LlamaIndex, CrewAI and LangChain integrations report verified only when QWED verified (GHSA-83v6-6h23-pvp4).

- ``QWEDQueryEngine`` returned ``verified=True, status="PASSED"`` for every
  non-math response and every fact-style query, with no engine called.
- ``QWEDVerificationTransform`` marked a node verified when its check raised,
  and every code check raised: it read ``result.verified``, which
  ``VerificationResult`` does not have (the field is ``is_verified``).
- ``QWEDVerifiedAgent.verify_output`` started from ``verified: True`` and kept
  it on that same ``AttributeError``, or when verification was disabled.

Now anything no engine verified is unverified, errors fail closed, and every
integration reads ``is_verified``.
"""

from types import SimpleNamespace

import pytest

from qwed_sdk import crewai, langchain, llamaindex
from qwed_sdk.models import VerificationResult

ADMITTED = VerificationResult(status="VERIFIED", is_verified=True, result={"message": "ok"})
REFUSED = VerificationResult(status="UNVERIFIABLE", is_verified=False, result={"message": "no"})


class FakeEngine:
    def __init__(self, answer):
        self.answer = answer

    def query(self, query, **kwargs):
        return self.answer


def _never(*args, **kwargs):
    raise AssertionError("no QWED engine should run")


def _raises(*args, **kwargs):
    raise RuntimeError("server error")


# ---------------------------------------------------------------- LlamaIndex query engine

def test_a_response_no_engine_checks_is_not_verified(monkeypatch):
    engine = llamaindex.QWEDQueryEngine(FakeEngine("The Eiffel Tower is in Berlin."), api_key="x")
    monkeypatch.setattr(engine._client, "verify", _never)

    response = engine.query("Where is the Eiffel Tower?")

    assert (response.verified, response.status) == (False, "UNVERIFIABLE")


def test_a_fact_query_is_not_verified_without_context(monkeypatch):
    engine = llamaindex.QWEDQueryEngine(FakeEngine("Paris"), api_key="x", verify_facts=True)
    monkeypatch.setattr(engine._client, "verify", _never)

    assert engine.query("What is the capital of France?").verified is False


@pytest.mark.parametrize(("result", "verified"), [(ADMITTED, True), (REFUSED, False)])
def test_a_math_response_takes_the_engines_answer(monkeypatch, result, verified):
    engine = llamaindex.QWEDQueryEngine(FakeEngine("2 + 2 = 4"), api_key="x")
    monkeypatch.setattr(engine._client, "verify", lambda text: result)

    assert engine.query("What is 2+2?").verified is verified


def test_a_math_check_that_raises_is_not_verified(monkeypatch):
    engine = llamaindex.QWEDQueryEngine(FakeEngine("2 + 2 = 5"), api_key="x")
    monkeypatch.setattr(engine._client, "verify", _raises)

    response = engine.query("What is 2+2?")

    assert (response.verified, response.status) == (False, "ERROR")


# ---------------------------------------------------------------- LlamaIndex node postprocessor

def _node(text, score=1.0):
    return SimpleNamespace(node=SimpleNamespace(get_content=lambda: text, metadata={}), score=score)


CODE_NODE = "Run this:\n```python\nimport os\nos.system('echo hi')\n```\n"


@pytest.mark.parametrize("verify_code", [_raises, lambda code: REFUSED])
def test_a_code_node_that_fails_or_errors_is_not_verified(monkeypatch, verify_code):
    transform = llamaindex.QWEDVerificationTransform(api_key="x", min_score_threshold=0.0)
    monkeypatch.setattr(transform._client, "verify_code", verify_code)
    node = _node(CODE_NODE)

    transform._postprocess_nodes([node])

    assert node.node.metadata["qwed_verified"] is False
    assert node.score == 0.5


def test_a_code_node_the_server_admits_is_verified(monkeypatch):
    transform = llamaindex.QWEDVerificationTransform(api_key="x")
    monkeypatch.setattr(transform._client, "verify_code", lambda code: ADMITTED)
    node = _node(CODE_NODE)

    transform._postprocess_nodes([node])

    assert node.node.metadata["qwed_verified"] is True
    assert node.score == 1.0


def test_a_node_with_nothing_to_check_is_not_marked_verified(monkeypatch):
    transform = llamaindex.QWEDVerificationTransform(api_key="x")
    monkeypatch.setattr(transform._client, "verify_code", _never)
    node = _node("Plain retrieved text.")

    kept = transform._postprocess_nodes([node])

    assert kept == [node]
    assert node.node.metadata == {"qwed_verified": False, "qwed_checked": False}
    assert node.score == 1.0


@pytest.mark.parametrize(("result", "expected"), [(ADMITTED, "VERIFIED"), (REFUSED, "FAILED")])
def test_the_llamaindex_tool_reads_is_verified(monkeypatch, result, expected):
    tool = llamaindex.QWEDVerifyTool(api_key="x")
    monkeypatch.setattr(tool._client, "verify", lambda query: result)

    assert expected in tool("2+2=4")


# ---------------------------------------------------------------- CrewAI

def _agent(monkeypatch, verify, enabled=True):
    agent = crewai.QWEDVerifiedAgent(
        role="analyst", goal="check", api_key="x",
        verification_config=crewai.VerificationConfig(enabled=enabled, log_results=False),
    )
    monkeypatch.setattr(agent._client, "verify", verify)
    return agent


def test_an_output_the_server_does_not_verify_is_not_verified(monkeypatch):
    agent = _agent(monkeypatch, lambda output: REFUSED)

    result = agent.verify_output("2 + 2 = 5")

    assert result["verified"] is False
    assert agent.verification_summary()["verified"] == 0
    assert agent.verification_summary()["failed"] == 1


def test_an_output_whose_check_raises_is_not_verified(monkeypatch):
    agent = _agent(monkeypatch, _raises)

    result = agent.verify_output("2 + 2 = 4")

    assert (result["verified"], result["status"]) == (False, "ERROR")
    assert agent.verification_summary()["verification_rate"] == 0


def test_a_disabled_check_is_skipped_not_verified(monkeypatch):
    agent = _agent(monkeypatch, _never, enabled=False)

    assert agent.verify_output("anything")["verified"] is False
    assert agent.verify_output("anything")["status"] == "SKIPPED"


def test_an_output_the_server_admits_is_verified(monkeypatch):
    agent = _agent(monkeypatch, lambda output: ADMITTED)

    assert agent.verify_output("2 + 2 = 4")["verified"] is True
    assert agent.verification_summary()["verification_rate"] == 1


@pytest.mark.parametrize(
    ("tool_class", "method"),
    [
        (crewai.QWEDVerificationTool, "verify"),
        (crewai.QWEDMathTool, "verify_math"),
        (crewai.QWEDCodeTool, "verify_code"),
        (crewai.QWEDSQLTool, "verify_sql"),
    ],
)
def test_the_crewai_tools_read_is_verified(monkeypatch, tool_class, method):
    tool = tool_class(api_key="x")
    monkeypatch.setattr(tool._client, method, lambda *args, **kwargs: ADMITTED)

    assert "ERROR" not in tool._run("x")
    assert tool._run("x").startswith("✅")


# ---------------------------------------------------------------- LangChain

@pytest.mark.parametrize(
    ("tool_class", "method"),
    [
        (langchain.QWEDTool, "verify"),
        (langchain.QWEDMathTool, "verify_math"),
        (langchain.QWEDLogicTool, "verify_logic"),
        (langchain.QWEDCodeTool, "verify_code"),
    ],
)
@pytest.mark.parametrize(("result", "mark"), [(ADMITTED, "✅"), (REFUSED, "")])
def test_the_langchain_tools_read_is_verified(monkeypatch, tool_class, method, result, mark):
    tool = tool_class(api_key="x")
    monkeypatch.setattr(tool._client, method, lambda *args, **kwargs: result)

    answer = tool._run("x")

    assert "ERROR" not in answer
    assert answer.startswith("✅") is (mark == "✅")


def test_the_langchain_chain_reads_is_verified(monkeypatch):
    chain = langchain.QWEDVerifiedChain(SimpleNamespace(run=lambda *a, **k: "2 + 2 = 5"), api_key="x")
    monkeypatch.setattr(chain._client, "verify", lambda output: REFUSED)

    assert chain.run().verified is False


# ---------------------------------------------------------------- qwed_sdk.integrations
# The second set of integrations had the same pass-through: a response no
# engine checked was "PASSED (No claims verified)". Its math and fact paths
# called result.dict() on the client's dataclass result, and the CrewAI agent
# called .model_dump(), so those checks raised instead of reading is_verified.

from qwed_sdk.integrations import crewai as crewai_integration  # noqa: E402
from qwed_sdk.integrations import llamaindex as llamaindex_integration  # noqa: E402


class _Response:
    def __init__(self, text, source_nodes=()):
        self.text, self.source_nodes = text, list(source_nodes)

    def __str__(self):
        return self.text


class _Engine:
    def __init__(self, response):
        self.response = response

    def query(self, query, **kwargs):
        return self.response


def test_the_integrations_engine_does_not_pass_what_no_engine_checked(monkeypatch):
    engine = llamaindex_integration.QWEDQueryEngine(_Engine(_Response("Paris is the capital.")), api_key="x")
    monkeypatch.setattr(engine.client, "verify_math", _never)
    monkeypatch.setattr(engine.client, "verify_fact", _never)

    response = engine.query("What is the capital of France?")

    assert response.verified is False
    assert response.status.startswith("UNVERIFIABLE")


@pytest.mark.parametrize(("result", "verified"), [(ADMITTED, True), (REFUSED, False)])
def test_the_integrations_engine_reads_is_verified_for_math(monkeypatch, result, verified):
    engine = llamaindex_integration.QWEDQueryEngine(_Engine(_Response("2 + 2 = 4")), api_key="x")
    monkeypatch.setattr(engine.client, "verify_math", lambda text: result)

    assert engine.query("What is 2+2?").verified is verified


@pytest.mark.parametrize(("result", "verified"), [(ADMITTED, True), (REFUSED, False)])
def test_the_integrations_engine_reads_is_verified_for_facts(monkeypatch, result, verified):
    nodes = [_node("Paris is the capital of France.")]
    engine = llamaindex_integration.QWEDQueryEngine(_Engine(_Response("Paris", nodes)), api_key="x", verify_math=False)
    monkeypatch.setattr(engine.client, "verify_fact", lambda claim, context: result)

    assert engine.query("What is the capital of France?").verified is verified


def test_the_integrations_engine_fails_closed_on_an_error(monkeypatch):
    engine = llamaindex_integration.QWEDQueryEngine(_Engine(_Response("2 + 2 = 4")), api_key="x")
    monkeypatch.setattr(engine.client, "verify_math", _raises)

    assert engine.query("What is 2+2?").verified is False


@pytest.mark.parametrize(("verify", "verified"), [(lambda c: ADMITTED, True), (lambda c: REFUSED, False), (_raises, False)])
def test_the_integrations_crewai_agent_reads_is_verified(verify, verified):
    # The agent needs CrewAI to construct; its check does not.
    agent = crewai_integration.QWEDVerifiedAgent.__new__(crewai_integration.QWEDVerifiedAgent)
    agent.client = SimpleNamespace(verify=verify)

    assert agent._verify_safety("2 + 2 = 4")["verified"] is verified
