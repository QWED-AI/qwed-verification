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
                api_key=self.api_key or "dummy",  # Ollama doesn't need real key
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
                verified_result = eval(llm_expr.strip(), {"__builtins__": {}}, local_vars)
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
                        "method": "sympy_eval"
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
        
        Uses Z3 for SAT solving.
        """
        if not self.has_z3:
            return VerificationResult(
                verified=False,
                error="Z3 not installed. Run: pip install z3-solver"
            )
        
        # TODO: Implement Z3 verification
        return VerificationResult(
            verified=False,
            error="Logic verification not yet implemented"
        )
    
    def verify_code(self, code: str, language: str = "python") -> VerificationResult:
        """
        Verify code for security issues.
        
        Uses AST analysis.
        """
        # TODO: Implement AST-based code verification
        return VerificationResult(
            verified=False,
            error="Code verification not yet implemented"
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
