"""
Enterprise SQL Verifier: Security Firewall with Complexity Limits.

Provides AST-based SQL analysis to prevent:
1. Injection attacks (tautologies, UNION, stacking)
2. Data leakage (sensitive column access)
3. Destructive operations (DROP, DELETE, etc.)
4. Resource exhaustion (complexity limits)
5. Schema violations
"""

import hashlib

import sqlglot
from sqlglot import exp, parse_one
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from .diagnostics import DiagnosticResult

from .verification_context import VerificationContextDocument


CONSTRAINT_PARSE_ERROR = "sql_verifier.parse_error"
CONSTRAINT_EXECUTION_ERROR = "sql_verifier.execution_error"
CONSTRAINT_CONNECTION_FAILURE = "sql_verifier.connection_failure"
CONSTRAINT_SQL_VALID = "sql_verifier.sql_valid"
CONSTRAINT_MALICIOUS = "sql_verifier.malicious"
CONSTRAINT_COMPLEXITY_LIMIT_EXCEEDED = "sql_verifier.complexity_limit_exceeded"
CONSTRAINT_SCHEMA_PARSE_ERROR = "sql_verifier.schema_parse_error"
CONSTRAINT_EMPTY_BATCH = "sql_verifier.empty_batch"
CONSTRAINT_BATCH_BLOCKED = "sql_verifier.batch_blocked"

# Issue types that prove malice. Resource-limit violations (complexity_*) are CRITICAL
# admission failures but are NOT evidence of malicious intent, so they must never set
# developer_fields.malicious_classification (CodeRabbit).
MALICIOUS_ISSUE_TYPES = frozenset({
    "destructive_command",
    "admin_command",
    "sensitive_column_access",
    "injection_tautology",
    "injection_or_true",
    "stacked_queries",
})


def _available_expression_types(*names: str) -> Set[type]:
    """Return the sqlglot expression classes that exist in the installed version."""
    return {
        expression
        for name in names
        if (expression := getattr(exp, name, None)) is not None
    }


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
    DESTRUCTIVE_COMMANDS = _available_expression_types(
        "Drop",
        "Delete",
        "Update",
        "Insert",
        "Alter",
        "Truncate",
        "TruncateTable",
        "Create",
        "Merge",
    )

    # Administrative / Permission commands
    ADMIN_COMMANDS = _available_expression_types(
        "Grant",
        "Revoke",
        "Set",
        "Transaction",
        "Command",
    )

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
    ) -> DiagnosticResult:
        """
        Verify a SQL query for safety.

        Returns a structured :class:`DiagnosticResult`:

        - SAFE query      → VERIFIED (``developer_fields.is_valid`` True, proof_ref from AST)
        - Malicious query → VERIFIED as-malicious (``is_valid`` False,
                          ``developer_fields.malicious_classification`` True). Proving a query
                          is malicious IS a successful proof, so it is not BLOCKED (issue #253).
                          Malicious is the only unsafe case that retains a proof_ref — unless
                          the DDL schema also fails to parse, in which case the incomplete
                          analysis is BLOCKED (schema_parse_error takes precedence).
        - Complexity-limit violation → BLOCKED (``sql_verifier.complexity_limit_exceeded``)
        - DDL schema parse failure → BLOCKED (``sql_verifier.schema_parse_error``)
        - Parse error     → BLOCKED (``sql_verifier.parse_error``)
        - Internal error  → BLOCKED (``sql_verifier.execution_error``)

        ``sql_verifier.connection_failure`` is reserved for consumers whose engines open a
        database connection; this verifier performs static AST analysis only.

        ``agent_message`` is agent-safe: it never leaks detection rules, rule IDs, or raw
        SQLGlot output. Rule-level detail lives in ``developer_fields``.

        Args:
            query: The SQL query to verify.
            schema_ddl: Optional DDL for schema validation.
            dialect: SQL dialect (postgres, mysql, sqlite, etc.).
            check_complexity: Whether to check complexity limits.

        Example:
            >>> result = verifier.verify_sql("SELECT * FROM users WHERE id = 1")
            >>> print(result.developer_fields.get("is_valid"))
            True
        """
        # 1. Parse Query
        try:
            parsed_query = parse_one(query, read=dialect)
        except Exception as exc:  # noqa: BLE001 — fail-closed by design
            return DiagnosticResult.blocked(
                agent_message=(
                    "SQL verification could not be completed because the query "
                    "could not be parsed."
                ),
                developer_fields={
                    "constraint_id": CONSTRAINT_PARSE_ERROR,
                    "is_valid": False,
                    "error_type": type(exc).__name__,
                    "issues": [{"severity": "CRITICAL", "description": "SQL Syntax Error"}],
                    "engine": "SQLGlot-AST-Scanner",
                },
            )

        # 2..7 Analysis — unexpected failures fail closed as execution errors.
        try:
            issues: List[SQLIssue] = []

            issues.extend(self._check_command_type(parsed_query))
            issues.extend(self._check_column_access(parsed_query))
            issues.extend(self._check_injection_patterns(parsed_query, query))

            complexity = self._analyze_complexity(parsed_query)

            if check_complexity:
                issues.extend(self._check_complexity_limits(complexity))

            if schema_ddl:
                issues.extend(self._validate_against_schema(parsed_query, schema_ddl, dialect))
        except Exception as exc:  # noqa: BLE001 — fail-closed by design
            return DiagnosticResult.blocked(
                agent_message=(
                    "SQL verification could not be completed due to an internal error."
                ),
                developer_fields={
                    "constraint_id": CONSTRAINT_EXECUTION_ERROR,
                    "is_valid": False,
                    "error_type": type(exc).__name__,
                },
            )

        # Determine overall safety
        critical_count = sum(1 for i in issues if i.severity == "CRITICAL")
        warning_count = sum(1 for i in issues if i.severity == "WARNING")

        is_valid = critical_count == 0

        # Malice proof requires true-malice issue types; a resource-limit violation
        # is a CRITICAL admission failure but NOT evidence of malicious intent.
        malicious = any(
            i.severity == "CRITICAL" and i.issue_type in MALICIOUS_ISSUE_TYPES
            for i in issues
        )
        schema_parse_failed = any(i.issue_type == "schema_parse_error" for i in issues)

        # A DDL schema parse failure means the analysis is incomplete: an authoritative
        # proof must never be generated from an incomplete analysis (fail-closed), so it
        # takes precedence over malice detection below (Sentry HIGH).
        if schema_parse_failed:
            constraint_id = CONSTRAINT_SCHEMA_PARSE_ERROR
        elif malicious:
            constraint_id = CONSTRAINT_MALICIOUS
        elif not is_valid:
            constraint_id = CONSTRAINT_COMPLEXITY_LIMIT_EXCEEDED
        else:
            constraint_id = CONSTRAINT_SQL_VALID

        developer_fields: Dict[str, Any] = {
            "constraint_id": constraint_id,
            "is_valid": is_valid,
            "malicious_classification": malicious,
            "issues": [
                {
                    "severity": i.severity,
                    "type": i.issue_type,
                    "description": i.description,
                    "recommendation": i.recommendation,
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
                "estimated_cost": round(complexity.estimated_cost, 2),
            },
            "critical_count": critical_count,
            "warning_count": warning_count,
            "engine": "SQLGlot-AST-Scanner",
        }

        evidence = self._build_evidence(
            parsed_query,
            query,
            dialect,
            schema_ddl,
            is_valid=is_valid,
            critical_count=critical_count,
            issues=issues,
            check_complexity=check_complexity,
        )

        # Only fully-analysed results may be VERIFIED: sql_valid and proven-malicious.
        # Schema-parse failures (incomplete analysis), complexity-limit violations, and
        # other admission failures are BLOCKED (non-authoritative, no proof_ref). A
        # malicious query whose schema also fails to parse is BLOCKED because the
        # analysis is incomplete (constraint_id is schema_parse_error in that case).
        if is_valid or constraint_id == CONSTRAINT_MALICIOUS:
            return DiagnosticResult.verified(
                agent_message=(
                    "The SQL query passed verification and is safe to execute."
                    if is_valid
                    else "The SQL query failed security verification and is not safe to execute."
                ),
                developer_fields=developer_fields,
                evidence=evidence,
            )

        return DiagnosticResult.blocked(
            agent_message="The SQL query failed admission checks and is not safe to execute.",
            developer_fields=developer_fields,
        )

    def _build_evidence(
        self,
        parsed_query: exp.Expression,
        query: str,
        dialect: str,
        schema_ddl: Optional[str],
        *,
        is_valid: bool,
        critical_count: int,
        issues: List[SQLIssue],
        check_complexity: bool,
    ) -> Dict[str, Any]:
        """Build deterministic, JSON-serializable proof evidence bound to the verdict.

        The proof_ref hashes the AST, the verdict, and the effective policy
        (``allow_destructive``, ``blocked_columns``, ``limits``) so two configurations
        that reach opposite verdicts on identical input can never share a proof_ref.
        """
        return {
            "engine": "SQLAst-Scanner",
            "query": query,
            "dialect": dialect,
            "schema_ddl": schema_ddl if schema_ddl else None,
            "ast": parsed_query.dump(),
            "is_valid": is_valid,
            "critical_count": critical_count,
            "issue_types": sorted({issue.issue_type for issue in issues}),
            "check_complexity": check_complexity,
            "allow_destructive": self.allow_destructive,
            "blocked_columns": sorted(self.blocked_columns),
            "limits": {key: self.limits[key] for key in sorted(self.limits)},
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
                severity="CRITICAL",
                issue_type="schema_parse_error",
                description="Could not parse DDL schema; schema verification is incomplete."
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
    ) -> DiagnosticResult:
        """
        Verify multiple SQL queries.

        Returns a single :class:`DiagnosticResult`. Per-query verdicts live in
        ``developer_fields.results`` (each a serialized per-query DiagnosticResult) and
        ``developer_fields.summary``.

        The batch is authoritative (VERIFIED with ``proof_ref``) only when every query is
        safe. A batch containing any malicious or blocked query returns BLOCKED (non-
        authoritative, ``proof_ref`` None) so generic consumers that admit on
        ``is_authoritative`` can never accept unsafe SQL (issue #253).

        Args:
            queries: List of SQL queries to verify.
            schema_ddl: Optional DDL schema.
            dialect: SQL dialect.

        Example:
            >>> result = verifier.verify_batch(["SELECT * FROM table1", "SELEC FROM t"])
            >>> print(
            ...     result.developer_fields["summary"]["safe"],
            ...     result.developer_fields["summary"]["unsafe"],
            ...     result.developer_fields["summary"]["blocked"],
            ... )
            1 0 1
        """
        items: List[Dict[str, Any]] = []
        for query in queries:
            dr = self.verify_sql(query, schema_ddl, dialect)
            serialized = dr.to_dict()
            serialized["query"] = query[:100] + "..." if len(query) > 100 else query
            items.append(serialized)

        if not queries:
            return DiagnosticResult.blocked(
                agent_message="Batch SQL verification requires at least one query.",
                developer_fields={
                    "constraint_id": CONSTRAINT_EMPTY_BATCH,
                    "is_valid": False,
                    "malicious_classification": False,
                    "results": [],
                    "summary": {
                        "total": 0,
                        "safe": 0,
                        "unsafe": 0,
                        "malicious": 0,
                        "blocked": 0,
                        "total_critical": 0,
                        "total_warnings": 0,
                    },
                },
            )

        total = len(queries)
        safe = sum(
            1
            for item in items
            if item["status"] == "VERIFIED" and item["developer_fields"].get("is_valid") is True
        )
        malicious = sum(
            1
            for item in items
            if item["status"] == "VERIFIED"
            and item["developer_fields"].get("malicious_classification") is True
        )
        blocked = total - safe - malicious

        is_valid_all = safe == total
        has_proven_malicious = malicious > 0

        summary = {
            "total": total,
            "safe": safe,
            "unsafe": malicious,
            "malicious": malicious,
            "blocked": blocked,
            "total_critical": sum(
                item["developer_fields"].get("critical_count", 0) for item in items
            ),
            "total_warnings": sum(
                item["developer_fields"].get("warning_count", 0) for item in items
            ),
        }

        evidence = {
            "engine": "SQLAst-Scanner",
            "dialect": dialect,
            "count": total,
            "queries": [item["query"] for item in items],
            # Full-query digests bind the complete query text (the truncated
            # ``queries`` field is display-only and not proof-bearing).
            "query_digests": [
                hashlib.sha256(query.encode("utf-8")).hexdigest() for query in queries
            ],
            "schema_ddl": schema_ddl if schema_ddl else None,
            "verdicts": [
                {"status": item["status"], "is_valid": item["developer_fields"].get("is_valid")}
                for item in items
            ],
            "allow_destructive": self.allow_destructive,
            "blocked_columns": sorted(self.blocked_columns),
            "limits": {key: self.limits[key] for key in sorted(self.limits)},
        }

        if is_valid_all:
            batch_constraint_id = CONSTRAINT_SQL_VALID
            batch_malicious = False
        else:
            # A parse/execution failure is NOT a proven-malicious verdict (Greptile P1):
            # only classify the batch as malicious when at least one item was proven so.
            batch_constraint_id = (
                CONSTRAINT_MALICIOUS if has_proven_malicious else CONSTRAINT_BATCH_BLOCKED
            )
            batch_malicious = has_proven_malicious

        batch_fields: Dict[str, Any] = {
            "constraint_id": batch_constraint_id,
            "is_valid": is_valid_all,
            "malicious_classification": batch_malicious,
            "results": items,
            "summary": summary,
            "engine": "SQLGlot-AST-Scanner",
        }

        if is_valid_all:
            return DiagnosticResult.verified(
                agent_message=(
                    "Batch SQL verification succeeded: all queries passed security checks."
                ),
                developer_fields=batch_fields,
                evidence=evidence,
            )

        # Fail-closed: an unsafe or blocked query makes the whole batch non-authoritative
        # (security policy violation per the BLOCKED status contract).
        return DiagnosticResult.blocked(
            agent_message=(
                "Batch SQL verification flagged unsafe or blocked queries; "
                "the batch is not admissible."
            ),
            developer_fields=batch_fields,
        )

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="SQLVerifier",
        )



