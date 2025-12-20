"""
Enterprise SQL Verifier: Security Firewall with Complexity Limits.

Provides AST-based SQL analysis to prevent:
1. Injection attacks (tautologies, UNION, stacking)
2. Data leakage (sensitive column access)
3. Destructive operations (DROP, DELETE, etc.)
4. Resource exhaustion (complexity limits)
5. Schema violations
"""

import sqlglot
from sqlglot import exp, parse_one
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field


@dataclass
class SQLIssue:
    """A detected SQL security issue."""
    severity: str  # "CRITICAL", "WARNING", "INFO"
    issue_type: str
    description: str
    recommendation: Optional[str] = None


@dataclass 
class ComplexityMetrics:
    """Query complexity metrics."""
    table_count: int = 0
    join_count: int = 0
    subquery_depth: int = 0
    column_count: int = 0
    condition_count: int = 0
    aggregate_count: int = 0
    estimated_cost: float = 0.0


class SecurityViolation(Exception):
    """Raised when a security policy is violated."""
    pass


class SQLVerifier:
    """
    Enterprise SQL Verifier (Security Firewall).
    
    Features:
    1. Command type blocking (DROP, DELETE, etc.)
    2. Sensitive column access control
    3. Injection pattern detection
    4. Query complexity limits
    5. Schema validation
    6. Cost estimation

    Attributes:
        blocked_columns (Set[str]): Set of column names that are forbidden to access.
        limits (Dict[str, int]): Configuration for complexity limits.
        allow_destructive (bool): Whether to allow destructive commands.
    """
    
    # Destructive commands (Blocked by default)
    DESTRUCTIVE_COMMANDS = {
        exp.Drop, exp.Delete, exp.Update, exp.Insert, 
        exp.Alter, exp.TruncateTable, exp.Create, exp.Merge
    }

    # Administrative / Permission commands
    ADMIN_COMMANDS = {
        exp.Grant, exp.Revoke, exp.Transaction, exp.Set, exp.Command
    }

    # Sensitive columns (Forbidden in SELECT/WHERE by default)
    DEFAULT_SENSITIVE_COLUMNS = {
        "password", "password_hash", "passwd", "pwd",
        "secret", "secret_key", "api_key", "token",
        "ssn", "social_security", "salary", "credit_card",
        "bank_account", "balance", "private_key"
    }
    
    # Default complexity limits
    DEFAULT_LIMITS = {
        "max_tables": 10,
        "max_joins": 5,
        "max_subquery_depth": 3,
        "max_columns": 50,
        "max_conditions": 20,
        "max_estimated_cost": 1000.0
    }

    def __init__(
        self, 
        blocked_columns: Optional[Set[str]] = None,
        complexity_limits: Optional[Dict[str, int]] = None,
        allow_destructive: bool = False
    ):
        """
        Initialize SQL Verifier.
        
        Args:
            blocked_columns: Additional columns to block.
            complexity_limits: Override default complexity limits.
            allow_destructive: If True, allow UPDATE/INSERT (for admin contexts).

        Example:
            >>> verifier = SQLVerifier(blocked_columns={"ssn", "password"})
        """
        self.blocked_columns = self.DEFAULT_SENSITIVE_COLUMNS.union(blocked_columns or set())
        self.limits = {**self.DEFAULT_LIMITS, **(complexity_limits or {})}
        self.allow_destructive = allow_destructive

    def verify_sql(
        self, 
        query: str, 
        schema_ddl: Optional[str] = None, 
        dialect: str = "postgres",
        check_complexity: bool = True
    ) -> Dict[str, Any]:
        """
        Verify a SQL query for safety.
        
        Args:
            query: The SQL query to verify.
            schema_ddl: Optional DDL for schema validation.
            dialect: SQL dialect (postgres, mysql, sqlite, etc.).
            check_complexity: Whether to check complexity limits.
            
        Returns:
            Dict with verification results including safety status and issues list.

        Example:
            >>> result = verifier.verify_sql("SELECT * FROM users WHERE id = 1")
            >>> print(result["is_safe"])
            True
        """
        issues: List[SQLIssue] = []
        
        # 1. Parse Query
        try:
            parsed_query = parse_one(query, read=dialect)
        except Exception as e:
            return {
                "is_safe": False,
                "status": "SYNTAX_ERROR",
                "issues": [{"severity": "CRITICAL", "description": f"SQL Syntax Error: {str(e)}"}],
                "complexity": None,
                "engine": "SQLGlot-AST-Scanner"
            }

        # 2. Command Type Check
        issues.extend(self._check_command_type(parsed_query))
        
        # 3. Column Security Check
        issues.extend(self._check_column_access(parsed_query))
        
        # 4. Injection Pattern Detection
        issues.extend(self._check_injection_patterns(parsed_query, query))
        
        # 5. Complexity Analysis
        complexity = self._analyze_complexity(parsed_query)
        
        # 6. Complexity Limit Checks
        if check_complexity:
            issues.extend(self._check_complexity_limits(complexity))
        
        # 7. Schema Validation
        if schema_ddl:
            issues.extend(self._validate_against_schema(parsed_query, schema_ddl, dialect))

        # Determine overall safety
        critical_count = sum(1 for i in issues if i.severity == "CRITICAL")
        warning_count = sum(1 for i in issues if i.severity == "WARNING")
        
        is_safe = critical_count == 0
        
        return {
            "is_safe": is_safe,
            "status": "SAFE" if is_safe else "BLOCKED",
            "issues": [
                {
                    "severity": i.severity,
                    "type": i.issue_type,
                    "description": i.description,
                    "recommendation": i.recommendation
                }
                for i in issues
            ],
            "complexity": {
                "table_count": complexity.table_count,
                "join_count": complexity.join_count,
                "subquery_depth": complexity.subquery_depth,
                "column_count": complexity.column_count,
                "condition_count": complexity.condition_count,
                "aggregate_count": complexity.aggregate_count,
                "estimated_cost": round(complexity.estimated_cost, 2)
            },
            "critical_count": critical_count,
            "warning_count": warning_count,
            "engine": "SQLGlot-AST-Scanner"
        }
    
    # =========================================================================
    # Command Type Checking
    # =========================================================================
    
    def _check_command_type(self, parsed_query: exp.Expression) -> List[SQLIssue]:
        """Check for blocked command types."""
        issues = []
        query_type = type(parsed_query)
        
        if query_type in self.DESTRUCTIVE_COMMANDS:
            if not self.allow_destructive:
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="destructive_command",
                    description=f"Destructive command '{query_type.__name__}' blocked. Only SELECT is allowed.",
                    recommendation="Use parameterized API endpoints for data modification."
                ))
        
        if query_type in self.ADMIN_COMMANDS:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="admin_command",
                description=f"Administrative command '{query_type.__name__}' blocked.",
                recommendation="Administrative operations must be performed through secure channels."
            ))
        
        return issues
    
    # =========================================================================
    # Column Access Control
    # =========================================================================
    
    def _check_column_access(self, parsed_query: exp.Expression) -> List[SQLIssue]:
        """Check for access to sensitive columns."""
        issues = []
        
        for column in parsed_query.find_all(exp.Column):
            col_name = column.name.lower()
            if col_name in self.blocked_columns:
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="sensitive_column_access",
                    description=f"Access to sensitive column '{col_name}' is forbidden.",
                    recommendation="Remove sensitive column from query or request elevated permissions."
                ))
        
        return issues
    
    # =========================================================================
    # Injection Pattern Detection
    # =========================================================================
    
    def _check_injection_patterns(self, parsed_query: exp.Expression, raw_query: str) -> List[SQLIssue]:
        """Detect SQL injection patterns."""
        issues = []
        
        # Tautology detection (1=1, 'a'='a')
        for condition in parsed_query.find_all(exp.EQ):
            left_sql = condition.left.sql() if hasattr(condition.left, 'sql') else str(condition.left)
            right_sql = condition.right.sql() if hasattr(condition.right, 'sql') else str(condition.right)
            
            if left_sql == right_sql:
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="injection_tautology",
                    description=f"Tautology detected: {condition.sql()}. Likely injection attempt.",
                    recommendation="Validate input before constructing SQL."
                ))
        
        # OR TRUE pattern
        for condition in parsed_query.find_all(exp.Or):
            if hasattr(condition, 'right') and isinstance(condition.right, exp.Boolean):
                if condition.right.this:
                    issues.append(SQLIssue(
                        severity="CRITICAL",
                        issue_type="injection_or_true",
                        description="'OR TRUE' pattern detected. Likely injection attempt."
                    ))
        
        # UNION injection
        if parsed_query.find(exp.Union):
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="union_query",
                description="UNION query detected. Verify this is intentional.",
                recommendation="Ensure UNION source is trusted."
            ))
        
        # Stacked queries (multiple statements)
        if ";" in raw_query.strip()[:-1]:  # Ignore trailing semicolon
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="stacked_queries",
                description="Multiple statements detected (stacked queries).",
                recommendation="Only single statements are allowed."
            ))
        
        # Comment injection
        if "--" in raw_query:
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="comment_detected",
                description="SQL comment '--' detected. May indicate injection attempt."
            ))
        
        return issues
    
    # =========================================================================
    # Complexity Analysis
    # =========================================================================
    
    def _analyze_complexity(self, parsed_query: exp.Expression) -> ComplexityMetrics:
        """Analyze query complexity for resource protection."""
        metrics = ComplexityMetrics()
        
        # Count tables
        metrics.table_count = len(list(parsed_query.find_all(exp.Table)))
        
        # Count joins
        metrics.join_count = len(list(parsed_query.find_all(exp.Join)))
        
        # Calculate subquery depth
        metrics.subquery_depth = self._calculate_subquery_depth(parsed_query)
        
        # Count columns
        metrics.column_count = len(list(parsed_query.find_all(exp.Column)))
        
        # Count conditions (WHERE, HAVING, ON)
        for expr_type in [exp.Where, exp.Having]:
            for _ in parsed_query.find_all(expr_type):
                metrics.condition_count += 1
        
        # Count binary conditions
        metrics.condition_count += len(list(parsed_query.find_all(exp.Binary)))
        
        # Count aggregates
        aggregate_types = [exp.Sum, exp.Count, exp.Avg, exp.Min, exp.Max]
        for agg_type in aggregate_types:
            metrics.aggregate_count += len(list(parsed_query.find_all(agg_type)))
        
        # Estimate cost (simplified formula)
        metrics.estimated_cost = self._estimate_cost(metrics)
        
        return metrics
    
    def _calculate_subquery_depth(self, expression: exp.Expression, depth: int = 0) -> int:
        """Calculate maximum subquery nesting depth."""
        max_depth = depth
        
        for subquery in expression.find_all(exp.Subquery):
            nested_depth = self._calculate_subquery_depth(subquery, depth + 1)
            max_depth = max(max_depth, nested_depth)
        
        # Also check for subqueries in FROM clause
        for select in expression.find_all(exp.Select):
            if select != expression:
                nested_depth = self._calculate_subquery_depth(select, depth + 1)
                max_depth = max(max_depth, nested_depth)
        
        return max_depth
    
    def _estimate_cost(self, metrics: ComplexityMetrics) -> float:
        """
        Estimate query cost (simplified formula).
        
        Cost = tables^2 * (joins + 1) * (subquery_depth + 1) * log(columns + 1)
        """
        import math
        
        base_cost = 1.0
        
        # Table cost (each table adds O(n) rows)
        table_cost = max(1, metrics.table_count) ** 2
        
        # Join cost (each join multiplies complexity)
        join_cost = max(1, metrics.join_count + 1) * 2
        
        # Subquery depth (exponential cost)
        subquery_cost = 2 ** metrics.subquery_depth
        
        # Column overhead (logarithmic)
        column_cost = math.log(max(1, metrics.column_count) + 1)
        
        # Aggregate cost
        agg_cost = max(1, metrics.aggregate_count)
        
        return base_cost * table_cost * join_cost * subquery_cost * column_cost * agg_cost
    
    # =========================================================================
    # Complexity Limit Enforcement
    # =========================================================================
    
    def _check_complexity_limits(self, metrics: ComplexityMetrics) -> List[SQLIssue]:
        """Check if query exceeds complexity limits."""
        issues = []
        
        if metrics.table_count > self.limits["max_tables"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_tables",
                description=f"Query accesses {metrics.table_count} tables (limit: {self.limits['max_tables']}).",
                recommendation="Reduce query scope or use materialized views."
            ))
        
        if metrics.join_count > self.limits["max_joins"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_joins",
                description=f"Query has {metrics.join_count} joins (limit: {self.limits['max_joins']}).",
                recommendation="Consider breaking into multiple queries or using denormalized tables."
            ))
        
        if metrics.subquery_depth > self.limits["max_subquery_depth"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_subqueries",
                description=f"Query has {metrics.subquery_depth} levels of subqueries (limit: {self.limits['max_subquery_depth']}).",
                recommendation="Flatten subqueries using CTEs or temporary tables."
            ))
        
        if metrics.column_count > self.limits["max_columns"]:
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="complexity_columns",
                description=f"Query selects {metrics.column_count} columns (limit: {self.limits['max_columns']}).",
                recommendation="Select only necessary columns."
            ))
        
        if metrics.condition_count > self.limits["max_conditions"]:
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="complexity_conditions",
                description=f"Query has {metrics.condition_count} conditions (limit: {self.limits['max_conditions']})."
            ))
        
        if metrics.estimated_cost > self.limits["max_estimated_cost"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_cost",
                description=f"Estimated query cost {metrics.estimated_cost:.0f} exceeds limit {self.limits['max_estimated_cost']}.",
                recommendation="Simplify query or add pagination."
            ))
        
        return issues
    
    # =========================================================================
    # Schema Validation
    # =========================================================================
    
    def _validate_against_schema(
        self, 
        parsed_query: exp.Expression, 
        schema_ddl: str, 
        dialect: str
    ) -> List[SQLIssue]:
        """Validate query against provided schema."""
        issues = []
        tables_in_schema: Dict[str, Set[str]] = {}
        
        try:
            parsed_schema = sqlglot.parse(schema_ddl, read=dialect)
            for expression in parsed_schema:
                if isinstance(expression, exp.Create) and isinstance(expression.this, exp.Schema):
                    table_name = expression.this.this.name.lower()
                    columns = {
                        col.this.name.lower() 
                        for col in expression.this.expressions 
                        if isinstance(col, exp.ColumnDef)
                    }
                    tables_in_schema[table_name] = columns
        except Exception:
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="schema_parse_error",
                description="Could not parse DDL schema."
            ))
            return issues
        
        # Check table existence
        for table in parsed_query.find_all(exp.Table):
            t_name = table.name.lower()
            if t_name not in tables_in_schema:
                issues.append(SQLIssue(
                    severity="WARNING",
                    issue_type="schema_table_missing",
                    description=f"Table '{t_name}' not found in schema.",
                    recommendation="Verify table name or update schema."
                ))
        
        return issues
    
    # =========================================================================
    # Batch Verification
    # =========================================================================
    
    def verify_batch(
        self, 
        queries: List[str], 
        schema_ddl: Optional[str] = None,
        dialect: str = "postgres"
    ) -> Dict[str, Any]:
        """
        Verify multiple SQL queries.

        Args:
            queries: List of SQL queries to verify.
            schema_ddl: Optional DDL schema.
            dialect: SQL dialect.

        Returns:
            Dict containing batch results and summary statistics.

        Example:
            >>> result = verifier.verify_batch(["SELECT * FROM table1", "DROP TABLE table2"])
            >>> print(result["summary"]["blocked"])
            1
        """
        results = []
        
        for query in queries:
            result = self.verify_sql(query, schema_ddl, dialect)
            results.append({
                "query": query[:100] + "..." if len(query) > 100 else query,
                **result
            })
        
        return {
            "results": results,
            "summary": {
                "total": len(queries),
                "safe": sum(1 for r in results if r["status"] == "SAFE"),
                "blocked": sum(1 for r in results if r["status"] == "BLOCKED"),
                "syntax_errors": sum(1 for r in results if r["status"] == "SYNTAX_ERROR"),
                "total_critical": sum(r["critical_count"] for r in results if "critical_count" in r),
                "total_warnings": sum(r["warning_count"] for r in results if "warning_count" in r)
            }
        }
