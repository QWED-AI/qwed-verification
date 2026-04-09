import sqlglot
from sqlglot import exp
from typing import Dict, Any

class SQLGuard:
    """
    Validates SQL syntax and enforces read-only mutation policies.
    """
    def __init__(self, allow_mutation: bool = False):
        self.allow_mutation = allow_mutation

    def verify_query(self, sql_query: str, dialect: str = "postgres") -> Dict[str, Any]:
        """
        Validates SQL syntax and ensures it adheres to mutation policies.
        Source: QWED-MCP Tools Reference
        """
        try:
            # 1. Verify Syntax (Transpile is a good check for validity)
            # Use read=None to infer dialect if possible, or force one
            parsed = sqlglot.parse_one(sql_query, read=dialect)
        except Exception as e:
            return {"verified": False, "error": f"Invalid SQL Syntax: {str(e)}"}

        normalized = parsed.sql()

        # 2. Check for Mutations (if not allowed)
        if not self.allow_mutation:
            # Check for DROP, DELETE, INSERT, UPDATE, ALTER, CREATE, TRUNCATE
            mutation_types = (
                exp.Drop, exp.Delete, exp.Insert, exp.Update, exp.Alter, 
                exp.Create, exp.TruncateTable
            )
            
            # Check root node
            is_mutation = isinstance(parsed, mutation_types)
            
            # Check children (e.g. nested statements, though unlikely in parse_one unless ; lists)
            if not is_mutation:
                # find() returns the first node matching the type
                if parsed.find(mutation_types):
                     is_mutation = True
            
            if is_mutation:
                return {
                    "verified": False, 
                    "risk": "DATA_MUTATION_BLOCKED",
                    "message": "Agent attempted to modify data. Only READ operations allowed."
                }

        return {
            "verified": True, 
            "dialect": dialect,
            "normalized_query": normalized,
            "message": "SQL Query verified safe and syntax-valid."
        }
