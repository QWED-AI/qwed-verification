"""
QWED LangChain Integration

Provides seamless integration with LangChain for automatic verification
of LLM outputs in chains and agents.

Usage:
    from qwed_sdk.langchain import QWEDTool, QWEDVerificationCallback

    # As a Tool
    agent = initialize_agent(tools=[QWEDTool()], llm=llm)

    # As a Callback (auto-verify all outputs)
    chain = LLMChain(llm=llm, callbacks=[QWEDVerificationCallback()])
"""

import logging
import re
from typing import Any, Callable, Dict, Iterator, List, NamedTuple, Optional, Tuple
from dataclasses import dataclass

from ._tool_answers import (
    NO_SQL_SCHEMA,
    code_issue_lines,
    natural_language_answer,
    server_message,
    undecided_answer,
)

# Import QWED client
try:
    from qwed_sdk import QWEDClient
except ImportError:
    from ..client import QWEDClient


# ============================================================================
# LangChain Tool
# ============================================================================

try:
    from langchain.tools import BaseTool
    from langchain.callbacks.base import BaseCallbackHandler
    from langchain.schema import LLMResult, AgentFinish
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    # Stub classes for type hints
    class BaseTool:
        pass
    class BaseCallbackHandler:
        pass


class QWEDTool(BaseTool if LANGCHAIN_AVAILABLE else object):
    """
    LangChain Tool that verifies mathematical and logical claims.
    
    Use in agents to give them deterministic verification capabilities.
    
    Example:
        from langchain.agents import initialize_agent
        from qwed_sdk.langchain import QWEDTool
        
        agent = initialize_agent(
            tools=[QWEDTool()],
            llm=ChatOpenAI(),
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        )
        
        result = agent.run("Verify: Is 2+2 equal to 5?")
    """
    
    name: str = "qwed_verify"
    description: str = (
        "Deterministically verify mathematical expressions, logical statements, "
        "and factual claims. Use this tool when you need to confirm the correctness "
        "of a calculation or logical reasoning. Input should be the expression or "
        "claim to verify."
    )
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ):
        if LANGCHAIN_AVAILABLE:
            super().__init__(**kwargs)
        self._client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
    
    def _run(self, query: str) -> str:
        """Synchronous verification."""
        try:
            result = self._client.verify(query)
            # /verify/natural_language admits nothing while the translation is
            # unverified, so not admitted is not "failed" (#606).
            return natural_language_answer(result, f"✅ VERIFIED: {server_message(result) or 'Correct'}")
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"
    
    async def _arun(self, query: str) -> str:
        """Async verification (uses sync under the hood)."""
        return self._run(query)


class QWEDMathTool(QWEDTool):
    """Specialized tool for mathematical verification."""
    
    name: str = "qwed_math"
    description: str = (
        "Verify mathematical expressions and calculations with 100% accuracy. "
        "Input should be a mathematical expression like '2+2=4' or 'sqrt(16)=4'."
    )
    
    def _run(self, expression: str) -> str:
        try:
            result = self._client.verify_math(expression)
            if result.is_verified:
                return f"✅ VERIFIED: {expression} is correct"
            # Incorrect only when proven false; undecided is not wrong (#606).
            return undecided_answer(result) or f"❌ INCORRECT: {server_message(result) or 'the claim is false'}"
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


class QWEDLogicTool(QWEDTool):
    """Specialized tool for logical verification."""
    
    name: str = "qwed_logic"
    description: str = (
        "Verify logical constraints and find satisfying assignments. "
        "Input should be in QWED-Logic DSL format: (AND (GT x 5) (LT y 10))"
    )
    
    def _run(self, query: str) -> str:
        try:
            return _logic_answer(self._client.verify_logic(query))
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


# An LLM writes the constraints from the query, and nothing verifies that they
# mean what was asked yet (#585), so /verify/logic admits no result.
_LOGIC_TRANSLATION_NOT_VERIFIED = (
    "the constraints were translated from your query by an LLM, "
    "and that translation is not verified"
)


def _logic_answer(result) -> str:
    """What QWEDLogicTool tells the agent about a /verify/logic result (#600).

    ``is_verified`` is the server's admission, and a logic result is not
    admitted while its translation is unverified. Read as SAT or UNSAT, it
    told the agent that no assignment existed for every satisfiable query.
    The answer follows the status instead, and says why a satisfiable result
    is not admitted.
    """
    data = result.result or {}
    message = data.get("agent_message") or data.get("error") or ""
    if result.status == "VERIFIED":
        model = data.get("model")
        if result.is_verified:
            return f"✅ SAT: Satisfying assignment: {model}"
        reason = (
            _LOGIC_TRANSLATION_NOT_VERIFIED
            if data.get("query_semantics_verified") is not True
            else "the server did not admit it"
        )
        return (
            f"⚠️ SAT, NOT ADMITTED: the translated constraints are satisfiable, "
            f"with the assignment {model}, but {reason}."
        )
    engine = data.get("developer_fields")
    if result.status == "UNVERIFIABLE" and isinstance(engine, dict) and engine.get("status") == "UNSAT":
        return (
            "❌ UNSAT: no assignment satisfies the translated constraints. "
            f"Not admitted: {_LOGIC_TRANSLATION_NOT_VERIFIED}."
        )
    if result.status == "UNVERIFIABLE":
        return f"⚠️ UNVERIFIABLE: {message or 'the constraints could not be decided'}"
    return f"⛔ {result.status}: {message or 'logic verification failed'}"


class QWEDCodeTool(QWEDTool):
    """Specialized tool for code security verification."""
    
    name: str = "qwed_code"
    description: str = (
        "Check code for security vulnerabilities. "
        "Input should be Python or JavaScript code to analyze."
    )
    
    def _run(self, code: str) -> str:
        try:
            result = self._client.verify_code(code)
            if result.is_verified:
                return "✅ SAFE: No security issues detected"
            # Unsafe only when proven unsafe: code that does not parse is
            # BLOCKED, not a list of issues (#606).
            undecided = undecided_answer(result)
            if undecided is not None:
                return undecided
            lines = code_issue_lines(result, 5)
            if lines:
                return "⚠️ SECURITY ISSUES:\n" + "\n".join(f"- {line}" for line in lines)
            return f"⚠️ SECURITY ISSUES: {server_message(result) or 'the code is not safe'}"
        except Exception as e:
            return f"⚠️ ERROR: {str(e)}"


# ============================================================================
# LangChain Callback Handler
# ============================================================================

# A fenced block (#608). A fence is three or more backticks or tildes, and
# the info string after it starts with the language. The block closes at a
# line of the same character, at least as long, with nothing after it, or else
# at the end of the text. A fence may be indented, as in a list item, and its
# body loses that indent. Each line is read once, so a long output costs
# linear time.
_FENCE = re.compile(r"[ \t]*(`{3,}|~{3,})(.*)")
# Tags of a SQL block. Each is checked in the dialect the callback is given,
# as that is how the user's database reads it.
_SQL_TAGS = frozenset({"sql", "postgresql", "postgres", "pgsql", "mysql", "sqlite", "tsql", "plsql"})

# SQL outside a fenced block (#608). QWED cannot tell where such SQL starts
# and ends: a blank line can sit inside a statement, and a ";" in a string or
# a comment, so a part could pass where the whole statement would not. So it
# is found, not extracted, and recorded as UNVERIFIABLE. The text outside
# fenced blocks is cut into pieces at each ";" and blank line. A piece holds a
# statement when a keyword in capitals, as SQL is written in text, starts one
# with the shape of a statement: SELECT ... FROM, WITH ... AS (, INSERT INTO,
# UPDATE ... SET, DELETE FROM, MERGE INTO, REPLACE INTO, TRUNCATE, GRANT,
# REVOKE, or CREATE, DROP or ALTER of a table, view, index, schema or
# database. "Select a few items from your list" is prose. A statement that
# creates, drops, alters or truncates a table is found in any case, as prose
# does not say "drop table". Each piece is read a fixed number of times, so a
# long output costs linear time, with no limit on length.
_SQL_BREAK = re.compile(r";|```|\n[ \t]*\n")
_SQL_START = re.compile(
    r"\b(?:SELECT|WITH|INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|REPLACE\s+INTO|TRUNCATE|GRANT|REVOKE"
    r"|(?:CREATE|DROP|ALTER)\s+(?:TABLE|VIEW|INDEX|SCHEMA|DATABASE))\b"
)
_SQL_TABLE_CHANGE = re.compile(r"\b(?:CREATE|DROP|ALTER|TRUNCATE)\s+TABLE\b", re.IGNORECASE)
_SQL_FROM = re.compile(r"\bFROM\b")
_SQL_AS = re.compile(r"\bAS\s*\(")
_SQL_UPDATE = re.compile(r"UPDATE\s+\S+\s+SET\b")
_SQL_OUTSIDE_A_BLOCK = "the SQL is not in a ```sql block, so QWED cannot tell where it starts and ends"

_logger = logging.getLogger(__name__)


class _Block(NamedTuple):
    """A fenced block (#608): its language in lower case ("" without a tag),
    its body, and whether it is SQL."""

    language: str
    body: str
    is_sql: bool


def _opening(line: str) -> Optional[Tuple[str, str]]:
    """The fence and language of the block *line* opens, or None."""
    match = _FENCE.fullmatch(line)
    if match is None or (match.group(1)[0] == "`" and "`" in match.group(2)):
        # A backtick after a backtick fence makes it inline code, as ```x```.
        return None
    words = match.group(2).split()
    return match.group(1), words[0].lower() if words else ""


def _closes(line: str, fence: str) -> bool:
    """Whether *line* closes a block opened by *fence*."""
    mark = line.strip()
    return len(mark) >= len(fence) and mark == fence[0] * len(mark)


def _dedent(lines: List[str], indent: int) -> str:
    """*lines* joined, each without up to *indent* leading spaces or tabs."""
    return "\n".join(line[min(indent, len(line) - len(line.lstrip(" \t"))):] for line in lines)


def _parse(text: str) -> Tuple[List[_Block], str]:
    """The fenced blocks with a body in *text*, and the text outside them,
    with a blank line where each block was."""
    lines = text.splitlines()
    blocks: List[_Block] = []
    outside: List[str] = []
    i = 0
    while i < len(lines):
        opening = _opening(lines[i])
        if opening is None:
            outside.append(lines[i])
            i += 1
            continue
        fence, language = opening
        end = i + 1
        while end < len(lines) and not _closes(lines[end], fence):
            end += 1
        body = _dedent(lines[i + 1:end], len(lines[i]) - len(lines[i].lstrip(" \t"))).strip()
        if body:
            blocks.append(_Block(language, body, _is_sql_block(language, body)))
        outside.append("")
        i = end + 1
    return blocks, "\n".join(outside)


def _is_sql_block(language: str, body: str) -> bool:
    """Whether a block is SQL: its tag names SQL, or it has no tag and starts
    with a SQL statement, in any case, after any "--" comments (#608). SQL
    words later in a block, as in Python that runs a query, do not make it
    SQL. A block taken for the wrong language does not parse in the other
    check, so it fails closed."""
    if language:
        return language in _SQL_TAGS
    lines = body.splitlines()
    first = next((n for n, line in enumerate(lines) if not line.lstrip().startswith("--")), len(lines))
    piece = next(_sql_pieces("\n".join(lines[first:]))).strip().upper()
    start = _SQL_START.match(piece)
    return start is not None and _starts_a_statement(
        start, piece, _last_start(_SQL_FROM, piece), _last_start(_SQL_AS, piece)
    )


def _sql_pieces(text: str) -> Iterator[str]:
    """*text* cut at each ";" (kept with the piece before it), code fence
    and blank line."""
    start = 0
    for cut in _SQL_BREAK.finditer(text):
        yield text[start:cut.end() if cut.group() == ";" else cut.start()]
        start = cut.end()
    yield text[start:]


def _last_start(pattern: "re.Pattern[str]", piece: str) -> int:
    """Where *pattern* last starts in *piece*, or -1."""
    return max((match.start() for match in pattern.finditer(piece)), default=-1)


def _starts_a_statement(start: "re.Match[str]", piece: str, last_from: int, last_as: int) -> bool:
    """Whether the keyword at *start* begins a statement in *piece*, given
    where FROM and AS ( last start in it."""
    keyword = start.group()
    if keyword == "SELECT":
        return last_from >= start.end()
    if keyword == "WITH":
        return last_as >= start.end()
    if keyword == "UPDATE":
        return _SQL_UPDATE.match(piece, start.start()) is not None
    return True


def _holds_a_statement(piece: str) -> bool:
    """Whether a SQL statement starts in *piece*."""
    if _SQL_TABLE_CHANGE.search(piece):
        return True
    last_from, last_as = _last_start(_SQL_FROM, piece), _last_start(_SQL_AS, piece)
    return any(_starts_a_statement(start, piece, last_from, last_as) for start in _SQL_START.finditer(piece))


def _sql_in(text: str) -> bool:
    """Whether *text*, the text outside the fenced blocks, holds a SQL
    statement. SQL in a block, such as a query in Python, is part of that
    block, which its own check reads."""
    return any(_holds_a_statement(piece) for piece in _sql_pieces(text))


def _unverified_check(kind: str, reason: str) -> Dict[str, Any]:
    """The record of a check the callback could not make (#608). It is not
    verified, so get_summary does not count the output as verified."""
    return {"type": kind, "verified": False, "status": "UNVERIFIABLE", "reason": reason}


def _check_not_run(kind: str, exc: Exception) -> Dict[str, Any]:
    """The record of a check that raised: not verified (#608). The exception
    is logged, so a bug in the check stays visible without interrupting the
    LangChain run."""
    _logger.warning("QWED %s check could not be run", kind, exc_info=exc)
    return _unverified_check(kind, f"the check could not be run ({type(exc).__name__})")


class QWEDVerificationCallback(BaseCallbackHandler if LANGCHAIN_AVAILABLE else object):
    """
    LangChain Callback that automatically verifies all LLM outputs.

    Attaches verification results to each generation. Every fenced block is
    checked: a SQL block (tagged ``sql`` or a SQL dialect, or untagged and
    holding a SQL statement) as SQL, against ``sql_schema_ddl``, the tables
    it runs on, and any other block as code (#608). SQL outside a fenced
    block is recorded as UNVERIFIABLE, as QWED cannot tell where it starts
    and ends, and so is SQL without a schema. A check that cannot run is
    recorded as UNVERIFIABLE too, never left out.
    
    Example:
        from langchain.llms import OpenAI
        from langchain.chains import LLMChain
        from qwed_sdk.langchain import QWEDVerificationCallback
        
        callback = QWEDVerificationCallback(
            verify_math=True,
            verify_code=True,
            block_on_failure=False,
            sql_schema_ddl="CREATE TABLE users (id INT, name TEXT)",
        )
        
        chain = LLMChain(
            llm=OpenAI(),
            prompt=prompt,
            callbacks=[callback]
        )
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        verify_math: bool = True,
        verify_code: bool = True,
        verify_sql: bool = True,
        block_on_failure: bool = False,
        log_results: bool = True,
        sql_schema_ddl: str = "",
        sql_dialect: str = "sqlite",
    ):
        self._client = QWEDClient(
            api_key=api_key or "",
            base_url=base_url or "http://localhost:8000"
        )
        self.verify_math = verify_math
        self.verify_code = verify_code
        self.verify_sql = verify_sql
        self.block_on_failure = block_on_failure
        self.log_results = log_results
        self.sql_schema_ddl = sql_schema_ddl or ""
        self.sql_dialect = sql_dialect or "sqlite"
        
        # Track verifications
        self.verification_results: List[Dict[str, Any]] = []
    
    def on_llm_end(self, response: "LLMResult", **kwargs) -> None:
        """Called after LLM generates output."""
        for generation_list in response.generations:
            for generation in generation_list:
                text = generation.text
                self._verify_output(text)
    
    def on_chain_end(self, outputs: Dict[str, Any], **kwargs) -> None:
        """Called after chain completes."""
        for key, value in outputs.items():
            if isinstance(value, str):
                self._verify_output(value)
    
    def on_agent_finish(self, finish: "AgentFinish", **kwargs) -> None:
        """Called when agent completes."""
        if isinstance(finish.return_values, dict):
            output = finish.return_values.get("output", "")
            if output:
                self._verify_output(output)
    
    def _verify_output(self, text: str) -> Dict[str, Any]:
        """Verify an output and record the result. Every fenced block is
        checked, a SQL block as SQL and any other block as code (#608)."""
        checks: List[Dict[str, Any]] = []
        results = {
            "text": text[:100] + "..." if len(text) > 100 else text,
            "verifications": checks
        }
        blocks, outside = _parse(text)

        # Auto-detect and verify mathematical content
        if self.verify_math and self._contains_math(text):
            checks.append(self._check("math", self._math_check, text))

        # Verify each code block, in its language
        if self.verify_code:
            checks.extend(self._check("code", self._code_check, block) for block in blocks if not block.is_sql)

        # Verify each SQL block, and record SQL outside them
        if self.verify_sql:
            checks.extend(self._sql_checks(outside, [block.body for block in blocks if block.is_sql]))

        self.verification_results.append(results)

        if self.log_results and checks:
            self._log_results(results)

        return results

    @staticmethod
    def _check(kind: str, run: Callable[[Any], Dict[str, Any]], content: Any) -> Dict[str, Any]:
        """The record of *run* on *content*. Optional auto-verification should
        not interrupt LangChain execution, but a check that could not run is
        not verified (#608)."""
        try:
            return run(content)
        except Exception as exc:
            return _check_not_run(kind, exc)

    def _math_check(self, text: str) -> Dict[str, Any]:
        """Check the math in an output."""
        result = self._client.verify(text)
        return {"type": "math", "verified": result.is_verified, "status": result.status}

    def _code_check(self, block: _Block) -> Dict[str, Any]:
        """Check a code block in the language of its tag; an untagged block
        is checked as Python (#608). /verify/code refuses a language it does
        not support."""
        result = self._client.verify_code(block.body, language=block.language or "python")
        # /verify/code lists them as "issues" (#608).
        issues = (result.result or {}).get("issues")
        return {
            "type": "code",
            "verified": result.is_verified,
            "vulnerabilities": len(issues) if isinstance(issues, list) else 0
        }

    def _sql_check(self, sql: str) -> Dict[str, Any]:
        """Check a SQL block against the schema (#608). It is sent whole,
        and /verify/sql does not admit more than one statement."""
        result = self._client.verify_sql(sql, self.sql_schema_ddl, self.sql_dialect)
        return {"type": "sql", "verified": result.is_verified, "status": result.status}

    def _sql_checks(self, outside: str, blocks: List[str]) -> List[Dict[str, Any]]:
        """A check for each SQL block, and an UNVERIFIABLE record for SQL in
        *outside*, the text outside the blocks (#608)."""
        sql_outside = _sql_in(outside)
        if not blocks and not sql_outside:
            return []
        if not self.sql_schema_ddl.strip():
            # /verify/sql refuses a query without its schema.
            return [_unverified_check("sql", NO_SQL_SCHEMA)]
        checks = [self._check("sql", self._sql_check, sql) for sql in blocks]
        if sql_outside:
            checks.append(_unverified_check("sql", _SQL_OUTSIDE_A_BLOCK))
        return checks

    def _contains_math(self, text: str) -> bool:
        """Check if text contains mathematical content."""
        import re
        math_patterns = [
            r'\d+\s*[+\-*/]\s*\d+',  # Basic arithmetic
            r'=\s*\d+',              # Equations
            r'\d+%',                 # Percentages
            r'sqrt|sin|cos|tan',    # Functions
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in math_patterns)
    
    def _log_results(self, results: Dict[str, Any]) -> None:
        """Log verification results."""
        for v in results["verifications"]:
            status = "✅" if v.get("verified") else "❌"
            print(f"[QWED] {status} {v['type'].upper()}: verified={v.get('verified')}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all verifications.

        An output counts as verified only when it had a check and every check
        verified it (#608). One with no check, such as SQL the callback did
        not recognise, is not: ``all()`` of no checks is true, and counted it.

        The callback checks what it recognises: the math it finds, each
        fenced block, and SQL outside a block written as SQL is in text.
        Anything else, such as a claim in prose, is not checked, so a verified
        output is one whose checks all passed, not one checked in full.
        """
        total = len(self.verification_results)
        verified = sum(
            1 for r in self.verification_results
            if r.get("verifications") and all(v.get("verified", False) for v in r["verifications"])
        )
        return {
            "total_outputs": total,
            "verified": verified,
            "verification_rate": verified / total if total > 0 else 0
        }


# ============================================================================
# LangChain Chain Wrapper
# ============================================================================

class QWEDVerifiedChain:
    """
    Wrapper that adds verification to any LangChain chain.
    
    Example:
        from langchain.chains import LLMChain
        from qwed_sdk.langchain import QWEDVerifiedChain
        
        base_chain = LLMChain(llm=llm, prompt=prompt)
        verified_chain = QWEDVerifiedChain(base_chain)
        
        result = verified_chain.run("Calculate 15% of 200")
        print(result.verified)  # True/False
        print(result.output)    # The LLM output
    """
    
    def __init__(
        self,
        chain: Any,
        api_key: Optional[str] = None,
        auto_correct: bool = False,
    ):
        self.chain = chain
        self._client = QWEDClient(api_key=api_key or "")
        self.auto_correct = auto_correct
    
    def run(self, *args, **kwargs) -> "VerifiedOutput":
        """Run chain and verify output."""
        output = self.chain.run(*args, **kwargs)
        
        verification = self._client.verify(output)
        
        if self.auto_correct and not verification.is_verified:
            corrected = verification.result.get("corrected")
            if corrected:
                output = corrected
        
        return VerifiedOutput(
            output=output,
            verified=verification.is_verified,
            status=verification.status,
            attestation=getattr(verification, 'attestation', None)
        )
    
    async def arun(self, *args, **kwargs) -> "VerifiedOutput":
        """Async run chain and verify output."""
        output = await self.chain.arun(*args, **kwargs)
        verification = self._client.verify(output)
        
        return VerifiedOutput(
            output=output,
            verified=verification.is_verified,
            status=verification.status,
            attestation=getattr(verification, 'attestation', None)
        )


@dataclass
class VerifiedOutput:
    """Output with verification metadata."""
    output: str
    verified: bool
    status: str
    attestation: Optional[str] = None
    
    def __str__(self):
        return self.output


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "QWEDTool",
    "QWEDMathTool",
    "QWEDLogicTool",
    "QWEDCodeTool",
    "QWEDVerificationCallback",
    "QWEDVerifiedChain",
    "VerifiedOutput",
    "LANGCHAIN_AVAILABLE",
]
