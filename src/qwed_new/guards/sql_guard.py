import sqlglot
from sqlglot import exp
from typing import Dict, Any

from qwed_new.core.sql_verifier import (
    DANGEROUS_SQL_FUNCTIONS,
    SQLVerifier,
    expand_executable_comments,
    sql_function_names,
)


class SQLGuard:
    """
    Validates SQL syntax and enforces read-only mutation policies.

    A pre-filter for one statement (GHSA-45jv-2j44-4c2q). It refuses more
    than one statement, a statement that is not a read-only query (unless
    mutations are allowed), any mutation, DDL or administrative statement
    anywhere in the tree (a CTE, a subquery, SELECT INTO), MySQL executable
    comments' contents included, and any function that reaches files, code,
    the OS or another server. Its statement and function lists are the
    server's SQLVerifier's. A query that must be admitted goes through the
    server (``QWEDClient.verify_sql``), which also checks the schema.
    """
    def __init__(self, allow_mutation: bool = False):
        self.allow_mutation = allow_mutation

    def verify_query(self, sql_query: str, dialect: str = "postgres") -> Dict[str, Any]:
        """
        Validates SQL syntax and ensures it adheres to mutation policies.
        Source: QWED-MCP Tools Reference
        """
        try:
            # Parse every statement: parse_one checked only the first, so
            # "SELECT 1; DROP TABLE users" passed as "SELECT 1".
            statements = [
                statement
                for statement in sqlglot.parse(expand_executable_comments(sql_query), read=dialect)
                if statement is not None
            ]
        except Exception as e:
            return {"verified": False, "error": f"Invalid SQL Syntax: {str(e)}"}

        if len(statements) != 1:
            return {
                "verified": False,
                "risk": "MULTIPLE_STATEMENTS",
                "message": "Exactly one SQL statement is allowed.",
            }
        parsed = statements[0]
        normalized = parsed.sql()

        node_types = {type(node[0] if isinstance(node, tuple) else node) for node in parsed.walk()}

        if node_types & SQLVerifier.ADMIN_COMMANDS:
            return {
                "verified": False,
                "risk": "ADMIN_COMMAND_BLOCKED",
                "message": "Administrative statements (COPY, ATTACH, PRAGMA, GRANT, ...) are not allowed.",
            }

        if not self.allow_mutation:
            mutation_types = SQLVerifier.DESTRUCTIVE_COMMANDS | {exp.Into}
            if node_types & mutation_types or type(parsed) not in SQLVerifier.READ_ONLY_ROOT_TYPES:
                return {
                    "verified": False,
                    "risk": "DATA_MUTATION_BLOCKED",
                    "message": "Agent attempted to modify data. Only READ operations allowed."
                }

        blocked = sorted(sql_function_names(parsed) & DANGEROUS_SQL_FUNCTIONS)
        if blocked:
            return {
                "verified": False,
                "risk": "DANGEROUS_FUNCTION_BLOCKED",
                "message": f"Function(s) blocked: {', '.join(blocked)}.",
            }

        return {
            "verified": True,
            "dialect": dialect,
            "normalized_query": normalized,
            "message": "One read-only statement with no blocked function. A pre-filter; the server's SQLVerifier decides admission.",
        }
