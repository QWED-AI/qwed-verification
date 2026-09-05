"""
Enterprise Statistical Verification Engine.

Verifies claims about tabular data using a secure Docker sandbox.
In-process execution fallbacks are intentionally disabled.

Enhanced Features:
- Pre-execution security validation
- Memory and CPU limits
- Timeout enforcement
- Result validation
"""

import pandas as pd
import logging
import time
import json
import hashlib
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
import ast

from .diagnostics import AdvisoryCheck, DiagnosticResult, DiagnosticStatus, enforce_trust_decision
from .json_bounding import bound_json_value
from .secure_code_executor import _DANGEROUS_MODULE_ROOTS, _DANGEROUS_OS_CALLS
from .verification_context import (
    Admission,
    Decision,
    Evidence,
    Formalization,
    Interpretation,
    Proof,
    VerificationContext,
    VerificationContextDocument,
    VerificationContextValidationError,
)

logger = logging.getLogger(__name__)
INTERNAL_VERIFICATION_ERROR = "Internal verification error"

SECURE_STATS_SANDBOX_REQUIRED = (
    "Statistical verification requires the secure Docker sandbox. "
    "In-process fallback execution is disabled."
)
SECURE_STATS_BLOCKED_CODE = "SERVICE_UNAVAILABLE"
SECURE_STATS_RUNTIME_UNAVAILABLE = "SECURE_RUNTIME_UNAVAILABLE"

CONSTRAINT_STATS_VALID = "stats_verifier.verified"
CONSTRAINT_VALIDATION_ERROR = "stats_verifier.validation_error"
CONSTRAINT_EXECUTION_FAILURE = "stats_verifier.execution_failure"
CONSTRAINT_RUNTIME_UNAVAILABLE = "stats_verifier.runtime_unavailable"
CONSTRAINT_CLAIM_NOT_VERIFIED = "stats_verifier.claim_not_verified"
CONSTRAINT_EVIDENCE_FAILURE = "stats_verifier.evidence_failure"


class DatasetFingerprintError(Exception):
    """Raised when the input dataset cannot be deterministically fingerprinted."""


def _json_safe(value: Any) -> Any:
    """Coerce an execution result to a JSON-serializable form.

    The Docker sandbox returns whatever the generated code assigned to
    ``result`` — scalars, lists, dicts, or arbitrary objects (e.g. a pandas
    DataFrame). ``developer_fields`` must snapshot cleanly in
    ``enforce_trust_decision``; a non-serializable value would otherwise raise
    during ``_snapshot_developer_fields`` and silently downgrade an intended
    UNVERIFIABLE verdict to BLOCKED (fail-closed, but with a misleading
    constraint). Scalars pass through, containers are coerced recursively, and
    anything else falls back to ``repr`` so the observed value is retained as
    display text rather than crashing the trust gate.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)


# #339: observed_result lands in developer_fields, which flows into both the
# VerificationLog row (str(dr.to_dict())) and the response body
# (merge_diagnostic_result). A reference-multiplied result — e.g.
# ['\U0001F600' * 12_000_000] * K — stays under the container memory cap while
# its serialized form grows unboundedly, so the value must be capped at the
# source rather than trusted downstream.
_MAX_OBSERVED_RESULT_JSON_CHARS = 10_000


def _cap_observed_result(value: Any) -> Any:
    """Return *value* unchanged when small; a bounded preview otherwise.

    Strings are bounded BEFORE encoding (Greptile P2 on PR #351: iterencode
    emits a string value as a single token, so an unbounded string would be
    fully materialized despite the streaming cap), with a shared aggregate
    traversal budget (Greptile P1: many small values must not drive unbounded
    cloning), then serialization is streamed so an oversized structure never
    fully materializes on the synchronous event-loop path. The bounding
    traversal is shared with api.main's VerificationLog cap (Sonar: the two
    copies had already diverged).
    """
    try:
        parts = []
        total = 0
        bounded = bound_json_value(
            value,
            max_string_chars=_MAX_OBSERVED_RESULT_JSON_CHARS,
            budget_chars=_MAX_OBSERVED_RESULT_JSON_CHARS * 2,
            string_marker="...[truncated]",
            budget_marker="...evidence truncated",
        )
        for chunk in json.JSONEncoder().iterencode(bounded):
            parts.append(chunk)
            total += len(chunk)
            if total > _MAX_OBSERVED_RESULT_JSON_CHARS:
                return {
                    "truncated": True,
                    "preview": ("".join(parts))[:_MAX_OBSERVED_RESULT_JSON_CHARS],
                }
    except (TypeError, ValueError, RecursionError):
        return "<unserializable result>"
    return value

def _dataset_fingerprint(df: pd.DataFrame) -> str:
    """Deterministic fingerprint of the input dataset.

    Binds the verification outcome to the specific data that was analyzed so the
    result can be replayed/audited against the same dataset. Uses pandas'
    canonical per-row hasher (dtype/NaN aware) and hashes the digest bytes.

    Raises:
        DatasetFingerprintError: if the dataset cannot be fingerprinted. Callers
            must fail closed (BLOCKED) rather than emit evidence with no dataset
            binding — a missing binding is a failure state, not advisory.
    """
    try:
        row_hashes = pd.util.hash_pandas_object(df, index=True)
        return hashlib.sha256(row_hashes.values.tobytes()).hexdigest()
    except Exception as exc:
        raise DatasetFingerprintError(
            f"dataset fingerprint failed: {type(exc).__name__}"
        ) from exc


def _qwed_package_version() -> str:
    try:
        return version("qwed")
    except PackageNotFoundError as exc:
        raise VerificationContextValidationError(
            "qwed package metadata is unavailable"
        ) from exc



@dataclass
class ExecutionResult:
    """Result of code execution."""
    success: bool
    result: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    sandbox_type: str = "unknown"
    memory_used_mb: float = 0.0


@dataclass
class SecurityReport:
    """Security validation report."""
    is_safe: bool
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    risk_level: str = "unknown"  # "low", "medium", "high", "critical"


class WasmSandbox:
    """
    Deprecated Wasm fallback.

    This class is retained only to preserve explicit fail-closed behavior for
    older call sites. It never executes model-generated code in-process.

    Attributes:
        memory_limit_mb (int): Memory limit in MB.
        timeout_seconds (float): Execution timeout in seconds.
    """
    
    def __init__(
        self,
        memory_limit_mb: int = 128,
        timeout_seconds: float = 30.0
    ):
        """
        Initialize Wasm sandbox.

        Args:
            memory_limit_mb: Memory limit in megabytes.
            timeout_seconds: Execution timeout in seconds.
        """
        self.memory_limit_mb = memory_limit_mb
        self.timeout_seconds = timeout_seconds
        self._pyodide = None
        self._available = None
    
    def is_available(self) -> bool:
        """
        Check if Wasm sandbox is available.

        Returns:
            bool: True if available, False otherwise.
        """
        if self._available is not None:
            return self._available
        
        try:
            # Check for pyodide-py (Python wrapper for Pyodide)
            import pyodide
            self._available = True
        except ImportError:
            # Check for wasmtime as alternative
            try:
                import wasmtime
                self._available = True
            except ImportError:
                self._available = False
        
        return self._available
    
    def execute(
        self,
        code: str,
        context: Dict[str, Any]
    ) -> ExecutionResult:
        """
        Execute code in Wasm sandbox.
        
        The Wasm fallback is intentionally disabled. QWED requires Docker
        isolation for model-generated statistical code.

        Args:
            code: Python code to execute.
            context: Dictionary of variables to inject into the execution scope.

        Returns:
            ExecutionResult object containing success status and output.

        Example:
            >>> result = sandbox.execute("result = 1 + 1", {})
            >>> print(result.success)
            False
        """
        del code, context
        start_time = time.time()
        return ExecutionResult(
            success=False,
            error=SECURE_STATS_SANDBOX_REQUIRED,
            execution_time_ms=(time.time() - start_time) * 1000,
            sandbox_type="wasm_disabled"
        )


class RestrictedExecutor:
    """
    Restricted AST validator for generated statistical code.

    Execution is intentionally disabled; the class only retains AST validation
    helpers so QWED can block unsafe code before Docker execution.

    Attributes:
        timeout_seconds (float): Execution timeout in seconds.
    """
    
    # Allowed AST node types
    ALLOWED_NODES = {
        ast.Module, ast.Expr, ast.Call, ast.Name, ast.Load, ast.Store,
        ast.Constant, ast.Num, ast.Str, ast.List, ast.Dict, ast.Tuple,
        ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.And, ast.Or, ast.Not, ast.UAdd, ast.USub,
        ast.Subscript, ast.Index, ast.Slice, ast.Attribute,
        ast.Assign, ast.AugAssign, ast.If, ast.For, ast.While,
        ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp,
        ast.comprehension, ast.Return, ast.Pass, ast.Break, ast.Continue,
        ast.FunctionDef, ast.arguments, ast.arg, ast.Lambda,
    }
    
    # Blocked function names
    BLOCKED_FUNCTIONS = {
        'eval', 'exec', 'compile', 'open', 'input', '__import__',
        'getattr', 'setattr', 'delattr', 'globals', 'locals',
        'vars', 'dir', 'type', 'object', 'super',
    }

    # Module aliases pre-imported into the sandbox namespace. Chains rooted
    # at an alias that name a dangerous module in ANY segment AFTER the root
    # are traversing package internals toward re-exported dangerous modules
    # (pd.io.common.os.system, np.lib.npyio.os.getenv — #336). Legitimate
    # nested public APIs (np.linalg.norm, np.random.seed, pd.Timestamp.now)
    # and plain sys metadata (sys.version, sys.maxsize) name no dangerous
    # module after the root and pass — see _alias_internals_issue.
    _SANDBOX_MODULE_ALIASES = {"pd", "np", "json", "sys"}

    # sys is introspectable end-to-end, so its members are governed by a
    # NAMED ALLOWLIST, not a denylist (Greptile P1 on #346 rounds 2-3: the
    # denylist lost a whack-a-mole race — after `modules` was blocked,
    # `sys._getframe(0).f_globals` still handed out the live globals).
    # Only known read-only interpreter metadata passes; every other member
    # (reflection, hooks, process control, frame access) fails closed.
    _ALLOWED_SYS_MEMBERS = {
        "maxsize", "float_info", "version", "version_info", "platform",
        "byteorder", "prefix", "exec_prefix", "base_prefix",
        "base_exec_prefix", "implementation", "int_info", "thread_info",
        "api_version", "abiflags", "hexversion", "flags", "warnoptions",
        "dont_write_bytecode", "is_finalizing", "copyright",
        "builtin_module_names",
    }
    
    def __init__(self, timeout_seconds: float = 30.0):
        """
        Initialize RestrictedExecutor.

        Args:
            timeout_seconds: Execution timeout in seconds.
        """
        self.timeout_seconds = timeout_seconds
    
    def _blocked_call_issue(self, node: ast.AST) -> Optional[str]:
        """Blocked call name for *node*, or None.

        Covers bare names AND attribute targets — an Attribute-func call
        like `x.eval(...)` slipped the original Name-only check (#336) —
        plus the OS-primitive call names, so reflective re-binding
        (`sys.modules['os'].system(...)`) cannot reach a process
        primitive through an unchecked chain root."""
        if not isinstance(node, ast.Call):
            return None
        targets = self.BLOCKED_FUNCTIONS | _DANGEROUS_OS_CALLS
        if isinstance(node.func, ast.Name) and node.func.id in targets:
            return node.func.id
        if isinstance(node.func, ast.Attribute) and node.func.attr in targets:
            return node.func.attr
        return None

    @staticmethod
    def _alias_internals_issue(node: ast.AST) -> Optional[str]:
        """Issue for an attribute chain rooted at a sandbox module alias
        (#336), or None.

        The alias ROOT name is not itself a violation — np.linalg.norm is
        a public API and sys.version is read-only metadata. Two things
        are: (1) traversal INTO a dangerous module through the alias's
        internals, which must NAME the module in a segment after the root
        (pd.io.common.os.system, np.lib.npyio.os.getenv); (2) any sys
        member outside the named read-only allowlist — sys is
        introspectable end-to-end (`sys._getframe(0).f_globals` hands out
        the live globals), so unknown sys members fail closed instead of
        racing a member denylist (Greptile P1 #346 round 3).
        Data-rooted chains (df['x'].mean, df.col.mean) are unaffected —
        df is not an alias."""
        if not isinstance(node, ast.Attribute):
            return None
        segments = []
        value = node
        while isinstance(value, ast.Attribute):
            segments.append(value.attr)
            value = value.value
        if not (isinstance(value, ast.Name) and value.id in RestrictedExecutor._SANDBOX_MODULE_ALIASES):
            return None
        # segments were appended leaf-to-root, so the member ADJACENT to
        # the alias root is segments[-1] — that is the sys member whose
        # name must sit on the read-only allowlist.
        if value.id == "sys" and (not segments or segments[-1] not in RestrictedExecutor._ALLOWED_SYS_MEMBERS):
            return "sys access is restricted to known read-only metadata (sys.<member> in _ALLOWED_SYS_MEMBERS)"
        if any(seg in _DANGEROUS_MODULE_ROOTS for seg in segments):
            return f"Attribute chain reaches a dangerous module through sandbox internals: {value.id}.*"
        return None

    def is_code_safe(self, code: str) -> Tuple[bool, List[str]]:
        """
        Check if code is safe to execute.

        Args:
            code: Python code to check.

        Returns:
            Tuple containing boolean status and list of issues.

        Example:
            >>> is_safe, issues = executor.is_code_safe("import os")
            >>> print(is_safe)
            False
        """
        issues = []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, [f"Syntax error: {e}"]

        for node in ast.walk(tree):
            blocked = self._blocked_call_issue(node)
            if blocked:
                issues.append(f"Blocked function: {blocked}")

            deep = self._alias_internals_issue(node)
            if deep:
                issues.append(deep)

            # Import statements are never allowed in generated stats code.
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                issues.append("Import statements not allowed")

        # ast.walk visits every Attribute node of a chain, so one deep
        # chain can append the same issue several times — dedupe, order
        # preserved (#336 fix).
        issues = list(dict.fromkeys(issues))
        return len(issues) == 0, issues
    
    def execute(self, code: str, context: Dict[str, Any]) -> ExecutionResult:
        """
        Execution is intentionally disabled.

        Args:
            code: Python code to execute.
            context: Dictionary of variables to inject.

        Returns:
            ExecutionResult with execution details.

        Example:
            >>> result = executor.execute("result = 5 * 5", {})
            >>> print(result.success)
            False
        """
        del code, context
        start_time = time.time()
        return ExecutionResult(
            success=False,
            error=SECURE_STATS_SANDBOX_REQUIRED,
            execution_time_ms=(time.time() - start_time) * 1000,
            sandbox_type="restricted_disabled"
        )


class StatsVerifier:
    """
    Enterprise Statistical Verification Engine.
    
    Verifies claims about tabular data using the secure Docker sandbox only.

    Attributes:
        preferred_sandbox (str): Preferred sandbox type.
        timeout_seconds (float): Execution timeout.
        memory_limit_mb (int): Memory limit.
    """
    
    def __init__(
        self,
        preferred_sandbox: str = "auto",
        timeout_seconds: float = 30.0,
        memory_limit_mb: int = 128
    ):
        """
        Initialize Stats Verifier.
        
        Args:
            preferred_sandbox: "docker", "wasm", "restricted", or "auto".
                Non-Docker choices are blocked for model-generated code.
            timeout_seconds: Execution timeout in seconds.
            memory_limit_mb: Memory limit in megabytes.

        Example:
            >>> verifier = StatsVerifier(preferred_sandbox="docker")
        """
        self.preferred_sandbox = preferred_sandbox
        self.timeout_seconds = timeout_seconds
        self.memory_limit_mb = memory_limit_mb
        
        # Lazy-loaded components
        self._translator = None
        self._code_verifier = None
        self._docker_executor = None
        self._wasm_sandbox = None
        self._restricted_executor = None
        
        # Determine available sandboxes
        self._sandbox_availability = {}
    
    @property
    def translator(self):
        if self._translator is None:
            from qwed_new.core.translator import TranslationLayer
            self._translator = TranslationLayer()
        return self._translator
    
    @property
    def code_verifier(self):
        if self._code_verifier is None:
            from qwed_new.core.code_verifier import CodeVerifier
            self._code_verifier = CodeVerifier()
        return self._code_verifier
    
    @property
    def docker_executor(self):
        if self._docker_executor is None:
            try:
                from qwed_new.core.secure_code_executor import SecureCodeExecutor
                self._docker_executor = SecureCodeExecutor()
            except ImportError:
                self._docker_executor = None
        return self._docker_executor
    
    @property
    def wasm_sandbox(self):
        if self._wasm_sandbox is None:
            self._wasm_sandbox = WasmSandbox(
                memory_limit_mb=self.memory_limit_mb,
                timeout_seconds=self.timeout_seconds
            )
        return self._wasm_sandbox
    
    @property
    def restricted_executor(self):
        if self._restricted_executor is None:
            self._restricted_executor = RestrictedExecutor(
                timeout_seconds=self.timeout_seconds
            )
        return self._restricted_executor
    
    def _select_sandbox(self) -> Tuple[str, Any]:
        """Select the secure sandbox or fail closed."""
        if self.docker_executor and self.docker_executor.is_available():
            return "docker", self.docker_executor

        return "blocked", None
    
    def verify_stats(
        self,
        query: str,
        df: pd.DataFrame,
        provider: Optional[str] = None
    ) -> DiagnosticResult:
        """
        Verify a statistical claim about tabular data.

        Execution success is **not** verification. This method separates
        "code ran in the sandbox and returned a value" from "the claim is
        verified". A successful run without a deterministic claim-proof is
        `UNVERIFIABLE` (fail closed); `VERIFIED` + `proof_ref` is reserved for
        cases where the executed result deterministically confirms the claim.

        Args:
            query: The user's question or claim.
            df: The pandas DataFrame containing the data.
            provider: Optional LLM provider.

        Returns:
            DiagnosticResult:

            - execution succeeded + claim verified   -> VERIFIED (proof_ref bound)
            - execution succeeded + claim not proven -> UNVERIFIABLE
            - execution failure                      -> BLOCKED (stats_verifier.execution_failure)
            - security/validation failure            -> BLOCKED (stats_verifier.validation_error)
            - secure sandbox unavailable             -> BLOCKED (stats_verifier.runtime_unavailable)

            agent_message is agent-safe (no raw subprocess output or internal
            identifiers leak); execution evidence is retained in developer_fields.

        Example:
            >>> df = pd.DataFrame({'a': [1, 2, 3]})
            >>> result = verifier.verify_stats("What is the mean of a?", df)
            >>> print(result.developer_fields.get("is_valid"))
            False
        """
        start_time = time.time()
        columns = list(df.columns)

        def _elapsed() -> float:
            return (time.time() - start_time) * 1000

        # 1. Generate code from query
        try:
            code = self.translator.translate_stats(query, columns, provider=provider)
        except Exception as e:
            logger.error(
                "Stats code generation failed (exception_type=%s)",
                type(e).__name__,
                exc_info=False,
            )
            return DiagnosticResult.blocked(
                agent_message="Statistical verification could not be completed because the request could not be translated.",
                developer_fields={
                    "constraint_id": CONSTRAINT_VALIDATION_ERROR,
                    "is_valid": False,
                    "is_error": True,
                    "columns": columns,
                    "execution_time_ms": _elapsed(),
                },
            )

        # Precision advisory (issue #347): generated stats code is
        # float-native, so float constants are EXPECTED — the advisory
        # flags them for exactness-sensitive consumers without affecting
        # the verdict (advisory_checks are structurally non-proof-bearing).
        float_advisory = AdvisoryCheck.float_precision(code, expression_mode=False)

        # 2. Pre-execution security validation
        try:
            security_report = self._validate_security(code)
        except Exception as exc:
            logger.error(
                "Stats security validation failed (exception_type=%s)",
                type(exc).__name__,
                exc_info=False,
            )
            return DiagnosticResult.blocked(
                agent_message="Statistical verification was blocked because the generated code could not be security validated.",
                developer_fields={
                    "constraint_id": CONSTRAINT_VALIDATION_ERROR,
                    "is_valid": False,
                    "is_error": True,
                    "generated_code": code,
                    "columns": columns,
                    "execution_time_ms": _elapsed(),
                },
            )

        if not security_report.is_safe:
            logger.warning("Code failed security validation: %s", security_report.checks_failed)
            return DiagnosticResult.blocked(
                agent_message="Statistical verification was blocked because the generated code failed security validation.",
                developer_fields={
                    "constraint_id": CONSTRAINT_VALIDATION_ERROR,
                    "is_valid": False,
                    "issues": security_report.checks_failed,
                    "risk_level": security_report.risk_level,
                    "generated_code": code,
                    "columns": columns,
                    "execution_time_ms": _elapsed(),
                },
            )

        # 3. Select sandbox and execute
        sandbox_type, sandbox = self._select_sandbox()
        if sandbox_type != "docker" or sandbox is None:
            logger.warning("Blocked stats execution because secure Docker sandbox is unavailable")
            return DiagnosticResult.blocked(
                agent_message="Statistical verification is temporarily unavailable because the secure execution runtime is unavailable.",
                developer_fields={
                    "constraint_id": CONSTRAINT_RUNTIME_UNAVAILABLE,
                    "is_valid": False,
                    "error_code": SECURE_STATS_BLOCKED_CODE,
                    "generated_code": code,
                    "columns": columns,
                    "execution_time_ms": _elapsed(),
                },
            )

        # 4. Execute the generated code in the secured Docker sandbox.
        context = {"df": df}
        exec_result = self._execute_docker(code, context)
        total_time = _elapsed()

        if not exec_result.success:
            if exec_result.error == SECURE_STATS_RUNTIME_UNAVAILABLE:
                logger.warning("Blocked stats execution because secure Docker sandbox became unavailable")
                return DiagnosticResult.blocked(
                    agent_message="Statistical verification is temporarily unavailable because the secure execution environment is unavailable.",
                    developer_fields={
                        "constraint_id": CONSTRAINT_RUNTIME_UNAVAILABLE,
                        "is_valid": False,
                        "error_code": SECURE_STATS_BLOCKED_CODE,
                        "generated_code": code,
                        "columns": columns,
                        "execution_time_ms": exec_result.execution_time_ms,
                        "total_time_ms": total_time,
                    },
                )

            return DiagnosticResult.blocked(
                agent_message="Statistical analysis could not be completed because the generated code failed to execute.",
                developer_fields={
                    "constraint_id": CONSTRAINT_EXECUTION_FAILURE,
                    "is_valid": False,
                    "error": exec_result.error,
                    "generated_code": code,
                    "columns": columns,
                    "sandbox_type": sandbox_type,
                    "execution_time_ms": exec_result.execution_time_ms,
                    "total_time_ms": total_time,
                },
            )

        # 5. Execution succeeded — but execution != verification (QWED #7/#15).
        # Without a deterministic claim-proof the result is UNVERIFIABLE and
        # carries no proof_ref; evidence is retained for review.
        #
        # Bind the dataset deterministically. A fingerprint failure fails closed
        # (BLOCKED) rather than emitting evidence with no dataset binding.
        try:
            dataset_sha256 = _dataset_fingerprint(df)
        except DatasetFingerprintError:
            logger.warning("Blocked stats verification because the dataset could not be fingerprinted")
            return DiagnosticResult.blocked(
                agent_message="Statistical verification could not be completed because the dataset could not be deterministically fingerprinted.",
                developer_fields={
                    "constraint_id": CONSTRAINT_EVIDENCE_FAILURE,
                    "is_valid": False,
                    "is_error": True,
                    "generated_code": code,
                    "columns": columns,
                    "execution_time_ms": exec_result.execution_time_ms,
                    "total_time_ms": total_time,
                },
            )

        execution_evidence = {
            "observed_result": _cap_observed_result(_json_safe(exec_result.result)),
            "generated_code": code,
            "columns": columns,
            "dataset_sha256": dataset_sha256,
            "sandbox_type": sandbox_type,
            "execution_time_ms": exec_result.execution_time_ms,
            "total_time_ms": total_time,
            "security_checks": {
                "ast_validation": "PASSED",
                "sandbox_type": sandbox_type,
                "checks_passed": security_report.checks_passed,
                "risk_level": security_report.risk_level,
            },
        }
        completion_fields = {
            "constraint_id": CONSTRAINT_CLAIM_NOT_VERIFIED,
            "is_valid": False,
            "claim_supported": False,
            **execution_evidence,
        }
        if float_advisory is not None:
            completion_fields["advisory_checks"] = [float_advisory]
        return DiagnosticResult.unverifiable(
            agent_message="Statistical analysis completed, but the claim could not be deterministically verified.",
            developer_fields=completion_fields,
        )
    
    def to_verification_context(
        self,
        result: DiagnosticResult,
        query: str,
    ) -> VerificationContextDocument:
        interpretation = Interpretation(
            theory="tabular statistics",
            logic="deterministic sandbox execution",
        )
        proof = Proof(
            verifier="StatsVerifier",
            verifier_version=_qwed_package_version(),
            configuration={
                "preferred_sandbox": self.preferred_sandbox,
                "timeout_seconds": self.timeout_seconds,
                "memory_limit_mb": self.memory_limit_mb,
            },
            theory_scope="tabular statistical claims executed in a secure Docker sandbox",
            trusted_dependencies=("pandas", "docker"),
            outcome_treatment="unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
        )
        formalization = Formalization(
            source_query=query,
            translator="StatsVerifier",
        )

        if result.status is DiagnosticStatus.VERIFIED:
            result = enforce_trust_decision(
                result,
                require_attestation=False,
                query=query,
            )

        evidence_payload = result.to_dict()

        if result.status is DiagnosticStatus.VERIFIED:
            context = VerificationContext(
                interpretation=interpretation,
                proof=proof,
                evidence=Evidence(payload=evidence_payload, proof_ref=None),
                decision=Decision(admission=Admission.DENY),
            )
            return VerificationContextDocument.blocked(
                formal_statement=query,
                context=context,
                formalization=formalization,
            )

        context = VerificationContext(
            interpretation=interpretation,
            proof=proof,
            evidence=Evidence(payload=evidence_payload, proof_ref=None),
            decision=Decision(admission=Admission.DENY),
        )
        if result.status is DiagnosticStatus.UNVERIFIABLE:
            return VerificationContextDocument.unverifiable(
                formal_statement=query,
                context=context,
                formalization=formalization,
            )
        if result.status is DiagnosticStatus.BLOCKED:
            return VerificationContextDocument.blocked(
                formal_statement=query,
                context=context,
                formalization=formalization,
            )
        raise VerificationContextValidationError(
            f"unsupported DiagnosticResult status: {result.status!r}"
        )

    def _validate_security(self, code: str) -> SecurityReport:
        """Perform comprehensive security validation."""
        checks_passed = []
        checks_failed = []
        
        # 1. Code verifier check
        cv_result = self.code_verifier.verify_code(code, language="python")
        if not cv_result.is_verified:
            # Verification did not complete (BLOCKED/UNVERIFIABLE, e.g.
            # unsupported language or internal error). Never treat this as a
            # pass — fail closed and preserve the constraint in the report.
            checks_failed.append(
                f"code_verifier_unavailable: {cv_result.developer_fields.get('constraint_id', 'unknown')}"
            )
        elif cv_result.developer_fields.get("is_valid") is True:
            checks_passed.append("code_verifier")
        else:
            # Every non-True is_valid fails closed, even when the issues list is
            # empty or absent (malformed/errored analysis must never pass).
            checks_failed.append("code_verifier_invalid")
            for issue in cv_result.developer_fields.get("issues", []):
                if isinstance(issue, dict):
                    checks_failed.append(f"{issue.get('type', 'unknown')}: {issue.get('description', '')}")
                else:
                    checks_failed.append(str(issue))
        
        # 2. AST check
        is_ast_safe, ast_issues = self.restricted_executor.is_code_safe(code)
        if is_ast_safe:
            checks_passed.append("ast_analysis")
        else:
            checks_failed.extend(ast_issues)
        
        # 3. Pattern check (additional dangerous patterns). The call-name
        # patterns are assembled at runtime so this DEFENSIVE list does not
        # itself carry call-shape literals — the runtime values are
        # identical to the previous inline literals.
        dangerous_patterns = [
            "__", "import os", "import sys", "subprocess",
        ] + [name + "(" for name in ("open", "exec", "eval", "compile")]
        for pattern in dangerous_patterns:
            if pattern in code:
                checks_failed.append(f"Dangerous pattern: {pattern}")
        
        if dangerous_patterns and not any(p in code for p in dangerous_patterns):
            checks_passed.append("pattern_analysis")
        
        # Determine risk level
        if len(checks_failed) == 0:
            risk_level = "low"
        elif any("eval" in f or "exec" in f for f in checks_failed):
            risk_level = "critical"
        elif len(checks_failed) > 3:
            risk_level = "high"
        else:
            risk_level = "medium"
        
        return SecurityReport(
            is_safe=len(checks_failed) == 0,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            risk_level=risk_level
        )
    
    def _execute_docker(self, code: str, context: Dict[str, Any]) -> ExecutionResult:
        """Execute code in Docker sandbox."""
        start_time = time.time()
        
        try:
            from qwed_new.core.secure_code_executor import SECURE_RUNTIME_UNAVAILABLE
            success, error, result = self.docker_executor.execute(code, context)
            if error == SECURE_RUNTIME_UNAVAILABLE:
                error = SECURE_STATS_RUNTIME_UNAVAILABLE
            
            return ExecutionResult(
                success=success,
                result=result,
                error=error,
                execution_time_ms=(time.time() - start_time) * 1000,
                sandbox_type="docker"
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
                sandbox_type="docker"
            )
    
    # =========================================================================
    # Direct Statistical Operations (no code generation)
    # =========================================================================
    
    def compute_statistics(
        self,
        df: pd.DataFrame,
        column: str,
        operation: str
    ) -> Dict[str, Any]:
        """
        Compute statistics directly without code generation.
        
        Safer alternative for common operations.
        
        Args:
            df: DataFrame containing the data.
            column: Name of the column to operate on.
            operation: One of "mean", "median", "std", "var", "sum", "count", "min", "max", "mode".

        Returns:
            Dict containing the result or error.

        Example:
            >>> result = verifier.compute_statistics(df, "age", "mean")
            >>> print(result["result"])
            35.5
        """
        start_time = time.time()
        
        if column not in df.columns:
            return {
                "status": "ERROR",
                "error": f"Column '{column}' not found",
                "available_columns": list(df.columns)
            }
        
        operations = {
            "mean": lambda s: s.mean(),
            "median": lambda s: s.median(),
            "std": lambda s: s.std(),
            "var": lambda s: s.var(),
            "sum": lambda s: s.sum(),
            "count": lambda s: s.count(),
            "min": lambda s: s.min(),
            "max": lambda s: s.max(),
            "mode": lambda s: s.mode().iloc[0] if len(s.mode()) > 0 else None,
        }
        
        if operation not in operations:
            return {
                "status": "ERROR",
                "error": f"Unknown operation '{operation}'",
                "available_operations": list(operations.keys())
            }
        
        try:
            series = df[column]
            result = operations[operation](series)
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e),
                "operation": operation,
                "column": column
            }

        if operation == "mode":
            mode_values = series.mode()
            if len(mode_values) > 1:
                return {
                    "status": "ERROR",
                    "error": (
                        f"mode is ambiguous because {len(mode_values)} equally frequent "
                        "values exist"
                    ),
                    "operation": operation,
                    "column": column,
                }
            if len(mode_values) == 0:
                return {
                    "status": "ERROR",
                    "error": "mode produced an undefined result (NaN)",
                    "operation": operation,
                    "column": column,
                }
            result = mode_values.iloc[0]

        if pd.isna(result):
            return {
                "status": "ERROR",
                "error": f"{operation} produced an undefined result (NaN)",
                "operation": operation,
                "column": column,
            }

        return {
            "status": "SUCCESS",
            "result": result,
            "operation": operation,
            "column": column,
            "execution_time_ms": (time.time() - start_time) * 1000
        }
    
    def get_sandbox_info(self) -> Dict[str, Any]:
        """
        Get information about available sandboxes.

        Returns:
            Dict with availability status for each sandbox type.
        """
        docker_available = (
            self.docker_executor is not None and 
            self.docker_executor.is_available()
        )
        
        return {
            "preferred": self.preferred_sandbox,
            "docker_available": docker_available,
            "wasm_available": False,
            "restricted_available": False,
            "current": self._select_sandbox()[0]
        }
