import sqlglot
from sqlglot import exp, parse_one
from typing import List, Dict, Any, Optional

class SQLVerifier:
    """
    Engine 6: SQL Verifier.
    Verifies SQL queries against a provided schema (DDL) using static analysis.
    """
    
    def __init__(self):
        pass

    def verify_sql(self, query: str, schema_ddl: str, dialect: str = "sqlite") -> Dict[str, Any]:
        """
        Verifies a SQL query against a schema.
        
        Args:
            query: The SQL query to verify (e.g., "SELECT * FROM users")
            schema_ddl: The database schema in DDL format (e.g., "CREATE TABLE users ...")
            dialect: The SQL dialect (default: sqlite)
            
        Returns:
            Dict with is_valid, issues, and parsed structure.
        """
        issues = []
        tables_in_schema = {}
        
        # 1. Parse Schema (DDL)
        try:
            parsed_schema = sqlglot.parse(schema_ddl, read=dialect)
            for expression in parsed_schema:
                if isinstance(expression, exp.Create):
                    # In sqlglot, Create.this is often a Schema expression
                    schema_expr = expression.this
                    
                    if isinstance(schema_expr, exp.Schema):
                        table_name = schema_expr.this.name
                        columns = set()
                        for col_def in schema_expr.expressions:
                            if isinstance(col_def, exp.ColumnDef):
                                columns.add(col_def.this.name)
                        tables_in_schema[table_name] = columns
                    elif isinstance(schema_expr, exp.Table):
                         # Handle simple CREATE TABLE x AS SELECT ... if needed
                         table_name = schema_expr.name
                         tables_in_schema[table_name] = set() # No columns known if AS SELECT
            
            print(f"DEBUG: Parsed Schema Tables: {list(tables_in_schema.keys())}")
        except Exception as e:
            print(f"DEBUG: Schema Parsing Error: {e}")
            return {
                "is_valid": False,
                "issues": [f"Schema Parsing Error: {str(e)}"]
            }

        # 2. Parse Query
        try:
            parsed_query = parse_one(query, read=dialect)
        except Exception as e:
            return {
                "is_valid": False,
                "issues": [f"SQL Syntax Error: {str(e)}"]
            }

        # 3. Safety Check (No DROP/DELETE/ALTER)
        forbidden_types = (exp.Drop, exp.Delete, exp.Alter)
        if isinstance(parsed_query, forbidden_types):
             issues.append(f"Forbidden command type: {parsed_query.key}")

        # 4. Schema Validation (Table Existence Only)
        # Find all tables referenced in the query
        for table in parsed_query.find_all(exp.Table):
            table_name = table.name
            if table_name not in tables_in_schema:
                issues.append(f"Table not found in schema: {table_name}")
        
        # Note: We skip strict column validation because:
        # 1. Column resolution is complex with aliases/joins
        # 2. Wildcards (*) are valid
        # 3. We want to avoid false positives on valid queries
        # We only validate that tables exist, not individual columns

        return {
            "is_valid": len(issues) == 0,
            "issues": issues,
            "tables_found": list(tables_in_schema.keys())
        }
