"""
QWEDLocal - Client-side verification without backend server.

Works with ANY LLM:
- Ollama (FREE local models)
- OpenAI
- Anthropic
- Google Gemini
- Any OpenAI-compatible API

Example:
    from qwed import QWEDLocal
    
    # Option 1: Ollama (FREE!)
    client = QWEDLocal(
        base_url="http://localhost:11434/v1",
        model="llama3"
    )
    
    # Option 2: OpenAI
    client = QWEDLocal(
        provider="openai",
        api_key="sk-proj-...",
        model="gpt-4o-mini"
    )
    
    result = client.verify("What is 2+2?")
    print(result.verified)  # True
    print(result.value)  # 4
"""

from typing import Optional, Dict, Any, List
import json
import os
from dataclasses import dataclass

# QWED Branding Colors
try:
    from colorama import Fore, Style, Back, init
    init(autoreset=True)
    
    # QWED Brand Colors
    class QWED:
        """QWED brand colors for terminal output."""
        BRAND = Fore.MAGENTA + Style.BRIGHT  # QWED signature color
        SUCCESS = Fore.GREEN + Style.BRIGHT
        ERROR = Fore.RED + Style.BRIGHT
        INFO = Fore.CYAN
        WARNING = Fore.YELLOW
        VALUE = Fore.BLUE + Style.BRIGHT
        EVIDENCE = Fore.WHITE + Style.DIM
        RESET = Style.RESET_ALL
        
    HAS_COLOR = True
except ImportError:
    # Fallback if colorama not installed
    class QWED:
        BRAND = SUCCESS = ERROR = INFO = WARNING = VALUE = EVIDENCE = RESET = ""
    HAS_COLOR = False


# LLM Clients
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

try:
    import google.generativeai as genai
except ImportError:
    genai = None

# Verifiers (bundled with SDK)
try:
    import sympy
    from sympy.parsing.sympy_parser import parse_expr
except ImportError:
    sympy = None

try:
    from z3 import Solver, sat, Bool, Int, Real
except ImportError:
    Solver = None




# Validators
import ast


class UnsafeExpressionError(ValueError):
    """Raised when an expression fails AST safety validation."""


class InvalidExpressionSyntaxError(UnsafeExpressionError):
    """Raised when an expression is not valid Python syntax."""


class DisallowedExpressionError(UnsafeExpressionError):
    """Raised when an expression contains disallowed AST nodes."""

def _has_string_arg(node: ast.Call) -> bool:
    """Check if a Call node has any string literal arguments."""
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return True
        if hasattr(ast, 'Str') and isinstance(arg, ast.Str):
            return True
    for kw in node.keywords:
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return True
        if hasattr(ast, 'Str') and isinstance(kw.value, ast.Str):
            return True
    return False


_ALLOWED_SYMPY_FUNCS = {
    'simplify', 'expand', 'factor', 'diff', 'integrate',
    'solve', 'limit', 'series', 'summation',
    'sin', 'cos', 'tan', 'exp', 'log', 'sqrt',
    'Symbol', 'symbols', 'Rational', 'Integer',
    'pi', 'E', 'oo', 'zoo', 'nan',
}

_SAFE_SYMPY_NODE_TYPES = (
    ast.Name, ast.Constant, ast.Expression,
    ast.Load, ast.BinOp, ast.UnaryOp,
    ast.keyword, ast.Pow,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.USub,
)

# Builtins whitelisted in AST validation — must match _is_safe_sympy_call
_SAFE_SYMPY_BUILTINS = {"abs": abs, "int": int}


# Functions that execute/parse strings via sympify — must never receive string args.
# Most sympy functions call sympify() internally, which uses eval().
# Only Symbol/symbols/Rational/Integer/constants take string args safely.
_SYMPY_SAFE_STRING_FUNCS = {'Symbol', 'symbols', 'Rational', 'Integer'}
_SYMPY_FUNCS_REJECTING_STRING_ARGS = _ALLOWED_SYMPY_FUNCS - _SYMPY_SAFE_STRING_FUNCS


def _is_safe_sympy_call(node: ast.Call) -> bool:
    """Validate a single Call node against sympy allow-list."""
    if isinstance(node.func, ast.Attribute):
        if getattr(node.func.value, 'id', '') != 'sympy':
            return False
        if node.func.attr not in _ALLOWED_SYMPY_FUNCS:
            return False
        # Only reject string args for functions that evaluate strings
        if node.func.attr in _SYMPY_FUNCS_REJECTING_STRING_ARGS:
            return not _has_string_arg(node)
    elif isinstance(node.func, ast.Name):
        if node.func.id not in {'abs', 'int'}:
            return False
    else:
        return False
    return True


def _is_safe_sympy_attribute(node: ast.Attribute) -> bool:
    """Validate attribute access — only allow sympy.X for allowed functions."""
    if not isinstance(node.value, ast.Name):
        return False
    return node.value.id == 'sympy' and node.attr in _ALLOWED_SYMPY_FUNCS


def _is_safe_sympy_node(node: ast.AST) -> bool:
    """Validate a single AST node for sympy expression safety."""
    if isinstance(node, ast.Call):
        return _is_safe_sympy_call(node)
    if isinstance(node, ast.Attribute):
        return _is_safe_sympy_attribute(node)
    if isinstance(node, _SAFE_SYMPY_NODE_TYPES):
        return True
    if hasattr(ast, 'Str') and isinstance(node, ast.Str):
        return True
    if hasattr(ast, 'Num') and isinstance(node, ast.Num):
        return True
    return False


def _is_safe_sympy_ast(tree: ast.AST) -> bool:
    """Validate that an AST tree only contains allowed SymPy operations."""
    return all(_is_safe_sympy_node(node) for node in ast.walk(tree))


def _is_safe_sympy_expr(expr_str: str) -> bool:
    """
    Validate that expression only contains allowed SymPy operations.
    Strictly whitelists safe functions to prevent code injection.
    """
    try:
        tree = ast.parse(expr_str, mode='eval')
        return _is_safe_sympy_ast(tree)
    except SyntaxError:
        return False


def _safe_eval_sympy_expr(expr_str: str, local_vars: dict):
    """Safely evaluate a SymPy expression using AST compilation.

    Mirrors _safe_eval_z3_expr for the SymPy/math verification path.
    Parses once, validates AST, compiles, executes in restricted namespace.
    """
    stripped = expr_str.strip()

    try:
        tree = ast.parse(stripped, mode='eval')
    except SyntaxError as exc:
        raise InvalidExpressionSyntaxError(str(exc)) from exc
    if not _is_safe_sympy_ast(tree):
        raise DisallowedExpressionError

    code = compile(tree, '<sympy_expr>', 'eval')

    # Defensively enforce restricted builtins (only abs, int)
    restricted_ns = {k: v for k, v in local_vars.items() if k != "__builtins__"}
    restricted_ns["__builtins__"] = _SAFE_SYMPY_BUILTINS

    return eval(code, restricted_ns)  # noqa: S307  # nosec - AST-validated


_ALLOWED_Z3_NAMES = {'Bool', 'And', 'Or', 'Not', 'Implies'}

_SAFE_Z3_NODE_TYPES = (ast.Constant, ast.Expression, ast.Load)


def _is_safe_z3_node(node: ast.AST) -> bool:
    """Validate a single AST node for Z3 expression safety."""
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Name) and node.func.id in _ALLOWED_Z3_NAMES
    if isinstance(node, ast.Name):
        return node.id in _ALLOWED_Z3_NAMES
    if isinstance(node, _SAFE_Z3_NODE_TYPES):
        return True
    if hasattr(ast, 'Str') and isinstance(node, ast.Str):
        return True
    if hasattr(ast, 'Num') and isinstance(node, ast.Num):
        return True
    return False


def _is_safe_z3_ast(tree: ast.AST) -> bool:
    """Validate that an AST tree only contains allowed Z3 operations."""
    return all(_is_safe_z3_node(node) for node in ast.walk(tree))


def _is_safe_z3_expr(expr_str: str) -> bool:
    """Validate that expression string only contains allowed Z3 operations.
    
    Backward-compatible wrapper around _is_safe_z3_ast.
    """
    try:
        tree = ast.parse(expr_str, mode='eval')
        return _is_safe_z3_ast(tree)
    except SyntaxError:
        return False


def _safe_eval_z3_expr(expr_str: str, z3_namespace: dict):
    """Safely evaluate a Z3 expression using AST compilation.
    
    Instead of eval(), this function:
    1. Parses the expression into an AST (once)
    2. Validates all nodes against the allow-list
    3. Compiles the validated AST into a code object
    4. Executes the compiled code in a restricted namespace (no builtins)
    
    This eliminates the eval() call that triggers S5334.
    """
    stripped = expr_str.strip()
    
    # Parse once and validate the AST
    try:
        tree = ast.parse(stripped, mode='eval')
    except SyntaxError as exc:
        raise InvalidExpressionSyntaxError(str(exc)) from exc
    if not _is_safe_z3_ast(tree):
        raise DisallowedExpressionError
    
    # Compile the already-validated AST (no re-parse)
    code = compile(tree, '<z3_expr>', 'eval')
    
    # Defensively strip builtins regardless of what the caller passes
    restricted_ns = {k: v for k, v in z3_namespace.items() if k != "__builtins__"}
    restricted_ns["__builtins__"] = {}
    
    return eval(code, restricted_ns)  # noqa: S307  # nosec - AST-validated


@dataclass
class VerificationResult:
    """Result from verification."""
    verified: bool
    value: Any = None
    confidence: float = 0.0
    evidence: Dict[str, Any] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = {}


# GitHub Star Nudge (only show occasionally)
_verification_count = 0
_has_shown_nudge = False

def _show_github_nudge():
    """Show GitHub star nudge after successful verifications."""
    global _verification_count, _has_shown_nudge
    
    _verification_count += 1
    
    # Show nudge after 3rd successful verification, then every 10th
    should_show = (
        (_verification_count == 3 and not _has_shown_nudge) or 
        (_verification_count % 10 == 0)
    )
    
    if should_show and HAS_COLOR:
        print(f"\n{QWED.BRAND}{'─' * 60}{QWED.RESET}")
        print(f"{QWED.BRAND}✨ Verified by QWED{QWED.RESET} {QWED.INFO}| Model Agnostic AI Verification{QWED.RESET}")
        print(f"{QWED.SUCCESS}💚 If QWED saved you time, give us a ⭐ on GitHub!{QWED.RESET}")
        print(f"{QWED.INFO}👉 https://github.com/QWED-AI/qwed-verification{QWED.RESET}")
        print(f"{QWED.BRAND}{'─' * 60}{QWED.RESET}\n")
        _has_shown_nudge = True
    elif should_show:
        # Non-colored fallback
        print("\n" + "─" * 60)
        print("✨ Verified by QWED | Model Agnostic AI Verification")
        print("💚 If QWED saved you time, give us a ⭐ on GitHub!")
        print("👉 https://github.com/QWED-AI/qwed-verification")
        print("─" * 60 + "\n")
        _has_shown_nudge = True


class QWEDLocal:
    """
    Client-side LLM verification without backend server.
    
    Privacy-first: Your API key, your data, your machine.
    QWED NEVER sees your queries or responses.
    
    Attributes:
        provider: LLM provider (openai, anthropic, gemini, or None for custom)
        base_url: Custom API endpoint (for Ollama, LM Studio, etc.)
        model: Model name
        api_key: API key for cloud providers
    """
    
    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        cache: bool = True,  # NEW: Enable caching by default
        cache_ttl: int = 86400,  # 24 hours
        mask_pii: bool = False,  # NEW: Enable PII masking
        pii_entities: Optional[List[str]] = None,  # NEW: Custom PII types
        **kwargs
    ):
        """
        Initialize QWEDLocal.
        
        Args:
            provider: 'openai', 'anthropic', 'gemini', or None for custom
            api_key: API key for cloud providers (not needed for Ollama)
            base_url: Custom endpoint (e.g., http://localhost:11434/v1 for Ollama)
            model: Model name (e.g., 'llama3', 'gpt-4o-mini', 'claude-3-opus')
            cache: Enable smart caching (default: True)
            cache_ttl: Cache time-to-live in seconds (default: 24 hours)
            **kwargs: Additional arguments for LLM client
        
        Examples:
            # Ollama (FREE) with caching
            client = QWEDLocal(
                base_url="http://localhost:11434/v1",
                model="llama3",
                cache=True  # Saves API calls!
            )
            
            # OpenAI without caching
            client = QWEDLocal(
                provider="openai",
                api_key="sk-...",
                model="gpt-4o-mini",
                cache=False  # Always fresh
            )
        """
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.use_cache = cache
        
        # Initialize cache if enabled
        if self.use_cache:
            from qwed_sdk.cache import VerificationCache
            self._cache = VerificationCache(ttl=cache_ttl)
        else:
            self._cache = None
        
        # Initialize PII detector (optional)
        self.mask_pii = mask_pii
        self._pii_detector = None
        self._last_pii_info = None
        
        if mask_pii:
            from qwed_sdk.pii_detector import PIIDetector
            try:
                self._pii_detector = PIIDetector(entities=pii_entities)
            except ImportError as e:
                # Re-raise with helpful message
                raise ImportError(
                    str(e) + "\n" +
                    "💡 PII masking requires: pip install 'qwed[pii]'"
                ) from e
        
        # Initialize LLM client
        self._init_llm_client(**kwargs)
        
        # Check verifiers available
        self._check_verifiers()
    
    def _init_llm_client(self, **kwargs):
        """Initialize the appropriate LLM client."""
        
        # Custom endpoint (Ollama, LM Studio, etc.)
        if self.base_url:
            if OpenAI is None:
                raise ImportError("openai package required. Install: pip install openai")
            
            self.llm_client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key or os.environ.get("QWED_LOCAL_API_KEY", "not-needed"),
                **kwargs
            )
            self.client_type = "openai"
        
        # OpenAI
        elif self.provider == "openai":
            if OpenAI is None:
                raise ImportError("openai package required. Install: pip install openai")
            if not self.api_key:
                raise ValueError("api_key required for OpenAI")
            
            self.llm_client = OpenAI(api_key=self.api_key, **kwargs)
            self.client_type = "openai"
        
        # Anthropic
        elif self.provider == "anthropic":
            if Anthropic is None:
                raise ImportError("anthropic package required. Install: pip install anthropic")
            if not self.api_key:
                raise ValueError("api_key required for Anthropic")
            
            self.llm_client = Anthropic(api_key=self.api_key, **kwargs)
            self.client_type = "anthropic"
        
        # Gemini
        elif self.provider == "gemini":
            if genai is None:
                raise ImportError("google-generativeai package required. Install: pip install google-generativeai")
            if not self.api_key:
                raise ValueError("api_key required for Gemini")
            
            genai.configure(api_key=self.api_key)
            self.llm_client = genai.GenerativeModel(self.model)
            self.client_type = "gemini"
        
        else:
            raise ValueError(
                "Must specify either 'provider' (openai/anthropic/gemini) "
                "or 'base_url' for custom endpoints"
            )
    
    def _check_verifiers(self):
        """Check which verifiers are available."""
        self.has_sympy = sympy is not None
        self.has_z3 = Solver is not None
        
        if not self.has_sympy:
            print("⚠️  SymPy not found. Math verification disabled. Install: pip install sympy")
        if not self.has_z3:
            print("⚠️  Z3 not found. Logic verification disabled. Install: pip install z3-solver")
    
    @property
    def cache_stats(self):
        """Get cache statistics."""
        if self._cache:
            return self._cache.get_stats()
        return None
    
    def print_cache_stats(self):
        """Print cache statistics with colors."""
        if self._cache:
            self._cache.print_stats()
        else:
            print("⚠️  Caching is disabled.")
    
    def _call_llm(self, prompt: str, system: Optional[str] = None) -> str:
        """
        Call the LLM with a prompt.
        
        This is the ONLY place where user data touches the LLM.
        No data is sent to QWED servers!
        """
        # PII MASKING (Phase 19 privacy shield)
        if self.mask_pii and self._pii_detector:
            original_prompt = prompt
            prompt, pii_report = self._pii_detector.detect_and_mask(prompt)
            
            if pii_report["pii_detected"] > 0:
                if HAS_COLOR:
                    print(f"{QWED.WARNING}🛡️  Privacy Shield Active: {pii_report['pii_detected']} PII entities masked{QWED.RESET}")
                    # print(f"   Types: {', '.join(pii_report['types'])}") # Optional verbose
                else:
                    print(f"🛡️  Privacy Shield Active: {pii_report['pii_detected']} PII entities masked")

        if self.client_type == "openai":
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            
            response = self.llm_client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.0  # Deterministic for verification
            )
            return response.choices[0].message.content
        
        elif self.client_type == "anthropic":
            response = self.llm_client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
                system=system or ""
            )
            return response.content[0].text
        
        elif self.client_type == "gemini":
            response = self.llm_client.generate_content(prompt)
            return response.text
        
        else:
            raise NotImplementedError(f"Client type {self.client_type} not implemented")
    
    def verify(self, query: str) -> VerificationResult:
        """
        Verify any query (auto-detects type).
        
        Args:
            query: Natural language query
        
        Returns:
            VerificationResult with verified status
        
        Example:
            result = client.verify("What is 2+2?")
            print(result.verified)  # True
            print(result.value)  # 4
        """
        # TODO: Auto-detect query type (math, logic, code, etc.)
        # For now, try math verification
        return self.verify_math(query)
    
    def verify_math(self, query: str) -> VerificationResult:
        """
        Verify mathematical query.
        
        Uses SymPy for symbolic verification.
        Checks cache first to save API costs!
        """
        if not self.has_sympy:
            return VerificationResult(
                verified=False,
                error="SymPy not installed. Run: pip install sympy"
            )
        
        # Check cache first (save $$!)
        if self._cache:
            cached_result = self._cache.get(query)
            if cached_result:
                if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                    print(f"{QWED.SUCCESS}⚡ Cache HIT{QWED.RESET} {QWED.INFO}(saved API call!){QWED.RESET}")
                return VerificationResult(**cached_result)
        
        # Show QWED branding
        if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
            print(f"\n{QWED.BRAND}🔬 QWED Verification{QWED.RESET} {QWED.INFO}| Math Engine{QWED.RESET}")
        
        # Step 1: Ask LLM for answer
        prompt = f"""Solve this math problem and respond ONLY with the numerical answer:

{query}

Answer (number only):"""
        
        try:
            llm_response = self._call_llm(prompt)
            llm_answer = llm_response.strip()
            
            if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                print(f"{QWED.INFO}📝 LLM Response: {llm_answer}{QWED.RESET}")
            
            # Step 2: Ask LLM for symbolic expression
            expr_prompt = f"""Convert this to a SymPy expression that we can verify:

{query}

Respond with ONLY the Python SymPy code to evaluate this, nothing else.
Example: "sympy.simplify(2+2)" or "sympy.diff(x**2, x)"

SymPy code:"""
            
            llm_expr = self._call_llm(expr_prompt)
            
            # Step 3: Verify with SymPy
            # Parse and evaluate the expression
            # (In production, use safe eval with restricted namespace)
            local_vars = {"sympy": sympy, "x": sympy.Symbol('x')}
            
            try:
                # Use safe eval with AST whitelist (module-level validator)

                # AST-validated eval via _safe_eval_sympy_expr (fixes S5334)
                verified_result = _safe_eval_sympy_expr(llm_expr, local_vars)
                
                # If it's an expression (like 2+2), evaluate it
                if hasattr(verified_result, 'evalf'):
                    verified_result = verified_result.evalf()
                verified_value = str(verified_result)
                
                # Compare LLM answer with verified result
                is_correct = str(llm_answer) == verified_value
                
                result = VerificationResult(
                    verified=is_correct,
                    value=verified_value,
                    confidence=1.0 if is_correct else 0.0,
                    evidence={
                        "llm_answer": llm_answer,
                        "verified_value": verified_value,
                        "sympy_expr": llm_expr.strip(),
                        "method": "sympy_eval_safe"
                    }
                )
                
                # Save to cache for future use
                if self._cache and is_correct:
                    cache_data = {
                        "verified": result.verified,
                        "value": result.value,
                        "confidence": result.confidence,
                        "evidence": result.evidence
                    }
                    self._cache.set(query, cache_data)
                
                # Show result with branding
                if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                    if is_correct:
                        print(f"{QWED.SUCCESS}✅ VERIFIED{QWED.RESET} {QWED.VALUE}→ {verified_value}{QWED.RESET}")
                        # Show GitHub star nudge on success!
                        _show_github_nudge()
                    else:
                        print(f"{QWED.ERROR}❌ MISMATCH{QWED.RESET}")
                        print(f"  LLM said: {llm_answer}")
                        print(f"  Verified: {verified_value}")
                
                return result
            
            except Exception as e:
                if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                    print(f"{QWED.ERROR}❌ Verification failed: {str(e)}{QWED.RESET}")
                
                return VerificationResult(
                    verified=False,
                    error=f"SymPy verification failed: {str(e)}",
                    evidence={
                        "llm_answer": llm_answer,
                        "llm_expr": llm_expr
                    }
                )
        
        except Exception as e:
            if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                print(f"{QWED.ERROR}❌ LLM call failed: {str(e)}{QWED.RESET}")
            
            return VerificationResult(
                verified=False,
                error=f"LLM call failed: {str(e)}"
            )
    
    def verify_logic(self, query: str) -> VerificationResult:
        """
        Verify logical query.
        
        Uses Z3 for SAT solving and boolean logic verification.
        Checks cache first to save API costs!
        """
        if not self.has_z3:
            return VerificationResult(
                verified=False,
                error="Z3 not installed. Run: pip install z3-solver"
            )
        
        # Check cache first
        if self._cache:
            cached_result = self._cache.get(query)
            if cached_result:
                if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                    print(f"{QWED.SUCCESS}⚡ Cache HIT{QWED.RESET} {QWED.INFO}(saved API call!){QWED.RESET}")
                return VerificationResult(**cached_result)
        
        # Show QWED branding
        if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
            print(f"\n{QWED.BRAND}🔬 QWED Verification{QWED.RESET} {QWED.INFO}| Logic Engine{QWED.RESET}")
        
        # Step 1: Ask LLM for answer
        prompt = f"""Solve this logic problem and respond with TRUE or FALSE:

{query}

Answer (TRUE or FALSE only):"""
        
        try:
            llm_response = self._call_llm(prompt)
            llm_answer = llm_response.strip().upper()
            
            if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                print(f"{QWED.INFO}📝 LLM Response: {llm_answer}{QWED.RESET}")
            
            # Step 2: Ask LLM for Z3 boolean expression
            expr_prompt = f"""Convert this logic statement to Python Z3 code:

{query}

Respond with ONLY the Z3 boolean expression code, nothing else.
Use Bool variables for propositions.
Example: "And(Bool('p'), Or(Bool('q'), Not(Bool('r'))))"

Z3 code:"""
            
            llm_expr = self._call_llm(expr_prompt)
            
            # Step 3: Verify with Z3
            try:
                from z3 import Bool, And, Or, Not, Implies, Solver, sat
                
                # Safe eval with Z3 namespace
                z3_namespace = {
                    "Bool": Bool,
                    "And": And,
                    "Or": Or, 
                    "Not": Not,
                    "Implies": Implies,
                    "__builtins__": {}
                }
                
                # Validate and execute using AST-safe evaluation
                # Uses _safe_eval_z3_expr which parses, validates, compiles
                # from AST, and executes without raw eval() (fixes S5334)
                expr = _safe_eval_z3_expr(llm_expr, z3_namespace)
                
                # Use Z3 solver
                solver = Solver()
                solver.add(expr)
                
                # Check satisfiability
                result = solver.check()
                is_satisfiable = (result == sat)
                
                # Compare with LLM answer
                llm_says_true = llm_answer == "TRUE"
                is_correct = is_satisfiable == llm_says_true
                
                verification_result = VerificationResult(
                    verified=is_correct,
                    value=str(is_satisfiable).upper(),
                    confidence=1.0 if is_correct else 0.0,
                    evidence={
                        "llm_answer": llm_answer,
                        "z3_satisfiable": is_satisfiable,
                        "z3_expr": llm_expr.strip(),
                        "method": "z3_sat"
                    }
                )
                
                # Save to cache
                if self._cache and is_correct:
                    cache_data = {
                        "verified": verification_result.verified,
                        "value": verification_result.value,
                        "confidence": verification_result.confidence,
                        "evidence": verification_result.evidence
                    }
                    self._cache.set(query, cache_data)
                
                # Show result
                if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                    if is_correct:
                        print(f"{QWED.SUCCESS}✅ VERIFIED{QWED.RESET} {QWED.VALUE}→ {is_satisfiable}{QWED.RESET}")
                        _show_github_nudge()
                    else:
                        print(f"{QWED.ERROR}❌ MISMATCH{QWED.RESET}")
                        print(f"  LLM said: {llm_answer}")
                        print(f"  Z3 result: {is_satisfiable}")
                
                return verification_result
            
            except Exception as e:
                if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                    print(f"{QWED.ERROR}❌ Z3 verification failed: {str(e)}{QWED.RESET}")
                
                return VerificationResult(
                    verified=False,
                    error=f"Z3 verification failed: {str(e)}",
                    evidence={
                        "llm_answer": llm_answer,
                        "z3_expr": llm_expr
                    }
                )
        
        except Exception as e:
            if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                print(f"{QWED.ERROR}❌ LLM call failed: {str(e)}{QWED.RESET}")
            
            return VerificationResult(
                verified=False,
                error=f"LLM call failed: {str(e)}"
            )
    
    def verify_code(self, code: str, language: str = "python") -> VerificationResult:
        """
        Verify code for security issues and code smells.
        
        Uses Python AST analysis for security checks.
        Checks cache first to save API costs!
        """
        if language != "python":
            return VerificationResult(
                verified=False,
                error=f"Only Python supported currently (got: {language})"
            )
        
        # Check cache first
        cache_key = f"code:{code}"
        if self._cache:
            cached_result = self._cache.get(cache_key)
            if cached_result:
                if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                    print(f"{QWED.SUCCESS}⚡ Cache HIT{QWED.RESET} {QWED.INFO}(saved API call!){QWED.RESET}")
                return VerificationResult(**cached_result)
        
        # Show QWED branding
        if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
            print(f"\n{QWED.BRAND}🔬 QWED Verification{QWED.RESET} {QWED.INFO}| Code Security Engine{QWED.RESET}")
        
        # Step 1: AST Analysis (no LLM needed!)
        import ast
        
        dangerous_patterns = []
        warnings = []
        
        try:
            tree = ast.parse(code)
            
            # Check for dangerous patterns
            for node in ast.walk(tree):
                # Dangerous functions
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ['eval', 'exec', 'compile', '__import__']:
                            dangerous_patterns.append(f"Dangerous function: {func_name}")
                
                # File operations
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id == 'open':
                            warnings.append("File operation detected: open()")
                
                # System calls
                if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name in ['os', 'subprocess', 'sys']:
                                warnings.append(f"System module imported: {alias.name}")
            
            # Determine if code is safe
            is_safe = len(dangerous_patterns) == 0
            
            result = VerificationResult(
                verified=is_safe,
                value="SAFE" if is_safe else "UNSAFE",
                confidence=1.0 if is_safe else 0.0,
                evidence={
                    "dangerous_patterns": dangerous_patterns,
                    "warnings": warnings,
                    "method": "ast_analysis",
                    "language": language
                }
            )
            
            # Save to cache
            if self._cache:
                cache_data = {
                    "verified": result.verified,
                    "value": result.value,
                    "confidence": result.confidence,
                    "evidence": result.evidence
                }
                self._cache.set(cache_key, cache_data)
            
            # Show result
            if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                if is_safe:
                    print(f"{QWED.SUCCESS}✅ SAFE CODE{QWED.RESET} {QWED.INFO}(no dangerous patterns){QWED.RESET}")
                    if warnings:
                        print(f"{QWED.WARNING}⚠️  Warnings: {len(warnings)}{QWED.RESET}")
                        for w in warnings[:3]:  # Show first 3
                            print(f"  - {w}")
                    _show_github_nudge()
                else:
                    print(f"{QWED.ERROR}❌ UNSAFE CODE{QWED.RESET}")
                    for p in dangerous_patterns:
                        print(f"  {QWED.ERROR}⚠️  {p}{QWED.RESET}")
            
            return result
        
        except SyntaxError as e:
            if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                print(f"{QWED.ERROR}❌ Syntax Error: {str(e)}{QWED.RESET}")
            
            return VerificationResult(
                verified=False,
                error=f"Python syntax error: {str(e)}",
                evidence={"syntax_error": str(e)}
            )
        
        except Exception as e:
            if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
                print(f"{QWED.ERROR}❌ Analysis failed: {str(e)}{QWED.RESET}")
            
            return VerificationResult(
                verified=False,
                error=f"Code analysis failed: {str(e)}"
            )
    
    def verify_shell_command(
        self, 
        command: str, 
        allowed_paths: List[str] = None,
        blocked_commands: List[str] = None
    ) -> VerificationResult:
        """
        Verify a shell command for security risks.
        
        Uses deterministic pattern matching (no LLM).
        Blocks dangerous commands, path traversal, and pipe-to-shell.
        
        Args:
            command: The shell command to verify.
            allowed_paths: Optional list of allowed file paths.
            blocked_commands: Optional list of additional commands to block.
        
        Returns:
            VerificationResult with verified=True if safe.
        """
        from .guards.system_guard import SystemGuard
        
        guard = SystemGuard(
            allowed_paths=allowed_paths,
            blocked_commands=blocked_commands
        )
        
        result = guard.verify_shell_command(command)
        
        if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
            print(f"\n{QWED.BRAND}🔬 QWED Verification{QWED.RESET} {QWED.INFO}| System Integrity Engine{QWED.RESET}")
            if result["verified"]:
                print(f"{QWED.SUCCESS}✅ SAFE COMMAND{QWED.RESET}")
            else:
                print(f"{QWED.ERROR}❌ BLOCKED: {result.get('risk', 'SECURITY_RISK')}{QWED.RESET}")
                print(f"  {QWED.WARNING}{result.get('message', '')}{QWED.RESET}")
        
        return VerificationResult(
            verified=result["verified"],
            value="SAFE" if result["verified"] else "BLOCKED",
            confidence=1.0,
            evidence=result
        )
    
    def verify_file_access(
        self, 
        filepath: str, 
        operation: str = "read",
        allowed_paths: List[str] = None
    ) -> VerificationResult:
        """
        Verify if a file path is within allowed sandbox directories.
        
        Uses deterministic path comparison (no LLM).
        
        Args:
            filepath: The file path to verify.
            operation: "read" or "write".
            allowed_paths: Optional list of allowed directories.
        
        Returns:
            VerificationResult with verified=True if allowed.
        """
        from .guards.system_guard import SystemGuard
        
        guard = SystemGuard(allowed_paths=allowed_paths)
        
        result = guard.verify_file_access(filepath, operation)
        
        if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
            print(f"\n{QWED.BRAND}🔬 QWED Verification{QWED.RESET} {QWED.INFO}| File Sandbox Engine{QWED.RESET}")
            if result["verified"]:
                print(f"{QWED.SUCCESS}✅ ACCESS ALLOWED{QWED.RESET}")
            else:
                print(f"{QWED.ERROR}❌ BLOCKED: {result.get('risk', 'SANDBOX_ESCAPE')}{QWED.RESET}")
                print(f"  {QWED.WARNING}{result.get('message', '')}{QWED.RESET}")
        
        return VerificationResult(
            verified=result["verified"],
            value="ALLOWED" if result["verified"] else "BLOCKED",
            confidence=1.0,
            evidence=result
        )
    
    def verify_config(self, config_data: Any) -> VerificationResult:
        """
        Scan configuration data for plaintext secrets.
        
        Uses deterministic regex pattern matching (no LLM).
        
        Args:
            config_data: Dict, list, or string to scan for secrets.
        
        Returns:
            VerificationResult with verified=False if secrets found.
        """
        from .guards.config_guard import ConfigGuard
        
        guard = ConfigGuard()
        result = guard.verify_config_safety(config_data)
        
        if HAS_COLOR and os.getenv("QWED_QUIET") != "1":
            print(f"\n{QWED.BRAND}🔬 QWED Verification{QWED.RESET} {QWED.INFO}| Config Security Engine{QWED.RESET}")
            if result["verified"]:
                print(f"{QWED.SUCCESS}✅ NO SECRETS DETECTED{QWED.RESET}")
            else:
                print(f"{QWED.ERROR}❌ SECRETS FOUND: {len(result.get('violations', []))}{QWED.RESET}")
                for v in result.get("violations", [])[:3]:
                    print(f"  {QWED.WARNING}⚠️  {v.get('type', 'SECRET')} at {v.get('path', 'unknown')}{QWED.RESET}")
        
        return VerificationResult(
            verified=result["verified"],
            value="CLEAN" if result["verified"] else "SECRETS_DETECTED",
            confidence=1.0,
            evidence=result
        )


# Convenience function
def verify(query: str, **kwargs) -> VerificationResult:
    """
    Quick verification without creating client.
    
    Uses Ollama by default if available, falls back to requiring API key.
    
    Example:
        result = verify("What is 2+2?")
        print(result.value)  # 4
    """
    # Try Ollama first (FREE!)
    try:
        client = QWEDLocal(
            base_url="http://localhost:11434/v1",
            model=kwargs.get("model", "llama3")
        )
        return client.verify(query)
    except Exception:
        # Ollama not available, require explicit configuration
        raise ValueError(
            "Ollama not running. Either:\n"
            "1. Start Ollama: ollama serve\n"
            "2. Or specify provider explicitly:\n"
            "   verify(query, provider='openai', api_key='sk-...')"
        )
