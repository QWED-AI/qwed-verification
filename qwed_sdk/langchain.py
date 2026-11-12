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
# body loses that indent. Each line is read once, with string methods, so a
# long output costs linear time.
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
# creates, drops, alters or truncates a table is found in any case when it
# reads as one: its piece ends with ";", or the table name, which may be
# quoted and hold spaces, is followed by the end of its line, "(", a comment
# or a clause such as ADD or AS. So "drop table t" is SQL, and "create table
# of contents" and "alter table settings in the panel" are prose. Each piece
# is read a fixed number of times, so a long output costs linear time, with
# no limit on length.
_SQL_BREAK = re.compile(r";|```|\n[ \t]*\n")
_SQL_START = re.compile(
    r"\b(?:SELECT|WITH|INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|REPLACE\s+INTO|TRUNCATE|GRANT|REVOKE"
    r"|(?:CREATE|DROP|ALTER)\s+(?:TABLE|VIEW|INDEX|SCHEMA|DATABASE))\b"
)
_SQL_TABLE_CHANGE = re.compile(r"\b(?:CREATE|DROP|ALTER|TRUNCATE)\s+TABLE\b", re.IGNORECASE)
# After TABLE: IF EXISTS or IF NOT EXISTS, then the table name, in parts
# joined by ".", each a word or a quoted name.
_SQL_IF_EXISTS = re.compile(r"IF\s+(?:NOT\s+)?EXISTS\b", re.IGNORECASE)
_SQL_QUOTES = {'"': '"', "`": "`", "[": "]"}
_SQL_WORD = re.compile(r"\w+")
_SQL_TABLE_CLAUSES = frozenset({"ADD", "DROP", "RENAME", "ALTER", "MODIFY", "AS", "CASCADE", "RESTRICT"})
# What only Python puts after the word select: an assignment, an attribute
# or a comma, as in select = Select(driver) or select.select(...).
_SQL_SELECT_PYTHON = re.compile(r"SELECT[ \t]*(?:=(?!=)|\.[A-Z_]|,)")
_SQL_FROM = re.compile(r"\bFROM\b")
_SQL_AS = re.compile(r"\bAS\s*\(")
_SQL_UPDATE = re.compile(r"UPDATE\s+\S+\s+SET\b")
_SQL_OUTSIDE_A_BLOCK = "the SQL is not in a ```sql block, so QWED cannot tell where it starts and ends"
_SPACE = re.compile(r"\s*")
_BLANK = re.compile(r"[ \t]*")
# Fence tags /verify/code does not map to a language it supports.
_LANGUAGES = {"python3": "python", "py3": "python"}

_logger = logging.getLogger(__name__)


class _Block(NamedTuple):
    """A fenced block (#608): its language in lower case ("" without a tag),
    its body, and whether it may be SQL and may be code. An untagged block
    that starts with a SQL statement may be either."""

    language: str
    body: str
    may_be_sql: bool
    may_be_code: bool


def _opening(line: str) -> Optional[Tuple[str, str]]:
    """The fence and language of the block *line* opens, or None."""
    stripped = line.lstrip(" \t")
    mark = stripped[:1]
    if mark not in ("`", "~"):
        return None
    info = stripped.lstrip(mark)
    fence = stripped[:len(stripped) - len(info)]
    if len(fence) < 3 or (mark == "`" and "`" in info):
        # A backtick after a backtick fence makes it inline code, as ```x```.
        return None
    words = info.split()
    return fence, words[0].lower() if words else ""


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
            blocks.append(_Block(language, body, _may_be_sql(language, body), language not in _SQL_TAGS))
        outside.append("")
        i = end + 1
    return blocks, "\n".join(outside)


def _may_be_sql(language: str, body: str) -> bool:
    """Whether a block may be SQL: its tag names SQL, or it has no tag and
    starts with a SQL statement, in any case, after any comments and blank
    lines (#608). The rest of the block is read whole, so a ";" in a string
    does not hide its FROM. SQL words later in a block, as in Python that runs
    a query, do not make it SQL. A SELECT needs no FROM, as in SELECT 1, so
    one counts unless what follows the word can only be Python."""
    if language:
        return language in _SQL_TAGS
    text = _after_leading_comments(body).upper()
    start = _SQL_START.match(text)
    if start is None:
        return False
    if start.group() == "SELECT":
        return _SQL_SELECT_PYTHON.match(text) is None
    return _starts_a_statement(start, text, _last_start(_SQL_FROM, text), _last_start(_SQL_AS, text))


def _after_leading_comments(body: str) -> str:
    """*body* after its leading space and SQL comments ("--" and "/* */")."""
    at = 0
    while True:
        at = _SPACE.match(body, at).end()
        if body.startswith("--", at):
            end = body.find("\n", at)
        elif body.startswith("/*", at):
            end = body.find("*/", at + 2)
            end = end + 1 if end >= 0 else end
        else:
            return body[at:]
        if end < 0:
            return ""
        at = end + 1


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
    if _changes_a_table(piece):
        return True
    last_from, last_as = _last_start(_SQL_FROM, piece), _last_start(_SQL_AS, piece)
    return any(_starts_a_statement(start, piece, last_from, last_as) for start in _SQL_START.finditer(piece))


def _changes_a_table(piece: str) -> bool:
    """Whether *piece* holds a statement, in any case, that creates, drops,
    alters or truncates a table: the piece ends with ";", or the table name is
    followed by the end of its line, "(", a comment or a clause such as ADD."""
    if piece.rstrip().endswith(";"):
        return _SQL_TABLE_CHANGE.search(piece) is not None
    name_end = 0
    for change in _SQL_TABLE_CHANGE.finditer(piece):
        if change.start() < name_end:
            # Inside the table name of the table change before it.
            continue
        name_end = _table_name_end(piece, change.end())
        if name_end >= 0 and _ends_a_statement(piece, name_end):
            return True
    return False


def _table_name_end(piece: str, at: int) -> int:
    """Where the table name after TABLE, at *at*, ends, or -1 if no name
    follows. A quote that does not close runs to the end of the piece."""
    start = _SPACE.match(piece, at).end()
    if start == at:
        return -1
    exists = _SQL_IF_EXISTS.match(piece, start)
    if exists:
        start = _SPACE.match(piece, exists.end()).end()
    end = _name_part_end(piece, start)
    while end >= 0 and piece.startswith(".", end):
        part = _name_part_end(piece, end + 1)
        if part < 0:
            break
        end = part
    return end


def _name_part_end(piece: str, at: int) -> int:
    """Where the part of a name at *at*, a word or a quoted name, ends, or -1."""
    close = _SQL_QUOTES.get(piece[at:at + 1])
    if close:
        end = piece.find(close, at + 1)
        return len(piece) if end < 0 else end + 1
    word = _SQL_WORD.match(piece, at)
    return word.end() if word else -1


def _ends_a_statement(piece: str, at: int) -> bool:
    """Whether what follows a table name, at *at*, reads as the rest of a
    statement: the end of its line, "(", a comment or a clause such as ADD."""
    at = _BLANK.match(piece, at).end()
    rest = piece[at:at + 2]
    if not rest or rest[0] in "\r\n(" or rest in ("--", "/*"):
        return True
    word = _SQL_WORD.match(piece, at)
    return word is not None and word.group().upper() in _SQL_TABLE_CLAUSES


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
    checked: a block tagged ``sql`` or a SQL dialect as SQL, against
    ``sql_schema_ddl``, the tables it runs on, and a block with another tag
    as code (#608). An untagged block that starts with a SQL statement may be
    either, so it gets both checks, and a check that cannot parse it does not
    count; any other untagged block is code. SQL outside a fenced block is
    recorded as UNVERIFIABLE, as QWED cannot tell where it starts and ends,
    and so is SQL without a schema. A check that cannot run is recorded as
    UNVERIFIABLE too, never left out.
    
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
        checked, as SQL, as code or as both (#608)."""
        checks: List[Dict[str, Any]] = []
        results = {
            "text": text[:100] + "..." if len(text) > 100 else text,
            "verifications": checks
        }
        blocks, outside = _parse(text)

        # Auto-detect and verify mathematical content
        if self.verify_math and self._contains_math(text):
            checks.append(self._check("math", self._math_check, text))

        # Verify each block, and record SQL that no check reads
        unread: List[str] = []
        for block in blocks:
            checks.extend(self._block_checks(block, unread))
        if self.verify_sql and any(_sql_in(part) for part in [outside, *unread]):
            checks.append(_unverified_check("sql", _SQL_OUTSIDE_A_BLOCK))

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
        language = _LANGUAGES.get(block.language, block.language) or "python"
        result = self._client.verify_code(block.body, language=language)
        # /verify/code lists them as "issues" (#608).
        issues = (result.result or {}).get("issues")
        return {
            "type": "code",
            "verified": result.is_verified,
            "status": result.status,
            "vulnerabilities": len(issues) if isinstance(issues, list) else 0
        }

    def _sql_check(self, sql: str) -> Dict[str, Any]:
        """Check a SQL block against the schema (#608). It is sent whole,
        and /verify/sql does not admit more than one statement."""
        result = self._client.verify_sql(sql, self.sql_schema_ddl, self.sql_dialect)
        return {"type": "sql", "verified": result.is_verified, "status": result.status}

    def _block_checks(self, block: _Block, unread: List[str]) -> List[Dict[str, Any]]:
        """The checks of a fenced block (#608): as SQL if it may be SQL, and
        as code if it may be code. An untagged block that starts with a SQL
        statement may be either, as select(x) is a call in both, and each
        check alone has passed what the other refuses. A check that cannot
        parse the block (BLOCKED) is dropped while the block may be in the
        other language, and kept when it may not. A block that may be code,
        and that no check reads, goes to *unread*, to be searched for SQL."""
        checks = []
        if block.may_be_sql and self.verify_sql:
            checks.append(self._sql_block_check(block.body))
        if block.may_be_code and self.verify_code:
            checks.append(self._check("code", self._code_check, block))
        parsed = [check for check in checks if check.get("status") != "BLOCKED"]
        unchecked = (block.may_be_sql and not self.verify_sql) or (block.may_be_code and not self.verify_code)
        if parsed or unchecked:
            checks = parsed
        if block.may_be_code and not self.verify_code and not checks:
            unread.append(block.body.upper())
        return checks

    def _sql_block_check(self, sql: str) -> Dict[str, Any]:
        """The SQL check of a block. /verify/sql refuses a query without its
        schema, so without one the record is UNVERIFIABLE."""
        if not self.sql_schema_ddl.strip():
            return _unverified_check("sql", NO_SQL_SCHEMA)
        return self._check("sql", self._sql_check, sql)

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
        fenced block, and SQL outside a block written as SQL is in text, or
        in a code block when the code check is off.
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
