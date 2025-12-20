"""
Enterprise Reasoning Verification Engine.

Validates that LLMs correctly understand natural language queries.

Enhanced Features:
1. Multi-LLM cross-validation
2. Semantic fact extraction
3. Chain-of-thought verification
4. Formula caching
5. Provider flexibility
6. Confidence scoring
"""

import re
import json
import hashlib
from typing import Dict, Any, List, Tuple, Optional, Callable
from dataclasses import dataclass, field
from functools import lru_cache
import time


@dataclass
class ReasoningValidation:
    """Result of reasoning verification."""
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    reasoning_trace: List[str]
    issues: List[str]
    primary_formula: str
    alternative_formula: Optional[str] = None
    semantic_facts: Optional[Dict[str, Any]] = None
    cached: bool = False
    verification_time_ms: float = 0.0


@dataclass
class ChainOfThoughtStep:
    """A step in chain-of-thought reasoning."""
    step_number: int
    description: str
    operation: Optional[str] = None
    input_values: List[Any] = field(default_factory=list)
    output_value: Optional[Any] = None
    confidence: float = 1.0


class ReasoningVerifier:
    """
    Enterprise Reasoning Verification Engine (Engine 8).
    
    Uses multi-LLM cross-validation to catch "translation errors"
    where the LLM generates the wrong formula for a correctly-stated problem.
    
    Enhanced Features:
    - Multiple LLM providers
    - Result caching for identical queries
    - Chain-of-thought parsing and validation
    - Semantic consistency checking

    Attributes:
        provider_names (List[str]): List of configured provider names.
        enable_cache (bool): Whether results are cached.
        cache_ttl (int): Cache Time-To-Live in seconds.
    """
    
    # Operation keywords for extraction
    OPERATION_KEYWORDS = {
        "add": ["add", "plus", "sum", "total", "together", "combined", "more", "increase"],
        "subtract": ["subtract", "minus", "less", "remove", "eat", "lose", "decrease", "spent", "gave"],
        "multiply": ["multiply", "times", "of", "each", "per", "rate"],
        "divide": ["divide", "per", "split", "share", "ratio", "average"],
        "exponent": ["squared", "cubed", "power", "exponential", "^"],
        "percentage": ["percent", "%", "percentage", "rate"],
    }
    
    # Cache for semantic parsing (LRU cache)
    _cache: Dict[str, ReasoningValidation] = {}
    _cache_max_size: int = 1000
    
    def __init__(
        self, 
        providers: Optional[List[str]] = None,
        enable_cache: bool = True,
        cache_ttl_seconds: int = 3600
    ):
        """
        Initialize Reasoning Verifier.
        
        Args:
            providers: List of provider names ["anthropic", "azure", "openai"].
            enable_cache: Whether to cache results.
            cache_ttl_seconds: Cache time-to-live.

        Example:
            >>> verifier = ReasoningVerifier(providers=["openai"], enable_cache=True)
        """
        self.provider_names = providers or ["anthropic"]
        self.enable_cache = enable_cache
        self.cache_ttl = cache_ttl_seconds
        
        # Lazy-loaded providers
        self._providers: Dict[str, Any] = {}
        self._provider_loaders: Dict[str, Callable] = {
            "anthropic": self._load_anthropic,
            "azure": self._load_azure,
            "openai": self._load_openai,
        }
    
    # =========================================================================
    # Provider Loading
    # =========================================================================
    
    def _load_anthropic(self):
        """Load Anthropic provider."""
        try:
            from qwed_new.providers.anthropic import AnthropicProvider
            return AnthropicProvider()
        except ImportError:
            return None
    
    def _load_azure(self):
        """Load Azure OpenAI provider."""
        try:
            from qwed_new.providers.azure_openai import AzureOpenAIProvider
            return AzureOpenAIProvider()
        except (ImportError, Exception):
            return None
    
    def _load_openai(self):
        """Load OpenAI provider."""
        try:
            from qwed_new.providers.openai import OpenAIProvider
            return OpenAIProvider()
        except ImportError:
            return None
    
    def _get_provider(self, name: str):
        """Get or load a provider by name."""
        if name not in self._providers:
            loader = self._provider_loaders.get(name)
            if loader:
                self._providers[name] = loader()
        return self._providers.get(name)
    
    @property
    def primary_llm(self):
        """Get primary LLM provider."""
        for name in self.provider_names:
            provider = self._get_provider(name)
            if provider:
                return provider
        return None
    
    @property
    def secondary_llm(self):
        """Get secondary LLM provider (different from primary)."""
        primary = self.primary_llm
        for name in self.provider_names:
            provider = self._get_provider(name)
            if provider and provider != primary:
                return provider
        # If only one provider, return it anyway
        return primary
    
    # =========================================================================
    # Main Verification
    # =========================================================================
    
    def verify_understanding(
        self,
        query: str,
        primary_task: Any,  # MathVerificationTask or similar
        enable_cross_validation: bool = True
    ) -> ReasoningValidation:
        """
        Validate that the LLM correctly understood the query.
        
        Args:
            query: Original natural language query.
            primary_task: The task generated by the primary LLM.
            enable_cross_validation: Whether to use secondary LLM for comparison.
            
        Returns:
            ReasoningValidation with confidence and issues.

        Example:
            >>> result = verifier.verify_understanding("2+2", task_obj)
            >>> print(result.is_valid)
            True
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = self._get_cache_key(query, primary_task.expression)
        if self.enable_cache and cache_key in self._cache:
            cached = self._cache[cache_key]
            cached.cached = True
            return cached
        
        issues = []
        
        # 1. Extract semantic facts from query
        facts = self._extract_semantic_facts(query)
        
        # 2. Parse and validate chain-of-thought
        cot_steps = self._parse_chain_of_thought(query, primary_task)
        cot_issues = self._validate_chain_of_thought(cot_steps, facts)
        issues.extend(cot_issues)
        
        # 3. Generate reasoning trace from primary LLM
        reasoning_trace = self._generate_reasoning_trace(query, primary_task)
        
        # 4. Validate formula semantics
        formula_issues = self._validate_formula_semantics(facts, primary_task.expression)
        issues.extend(formula_issues)
        
        # 5. Cross-validate with secondary LLM
        alternative_formula = None
        if enable_cross_validation and self.secondary_llm:
            alt_result = self._cross_validate(query, primary_task.expression)
            alternative_formula = alt_result.get("formula")
            if alt_result.get("issues"):
                issues.extend(alt_result["issues"])
        
        # 6. Calculate confidence
        confidence = self._calculate_confidence(issues, facts, reasoning_trace, cot_steps)
        
        result = ReasoningValidation(
            is_valid=len(issues) == 0,
            confidence=confidence,
            reasoning_trace=reasoning_trace,
            issues=issues,
            primary_formula=primary_task.expression,
            alternative_formula=alternative_formula,
            semantic_facts=facts,
            cached=False,
            verification_time_ms=(time.time() - start_time) * 1000
        )
        
        # Cache result
        if self.enable_cache:
            self._cache_result(cache_key, result)
        
        return result
    
    # =========================================================================
    # Semantic Fact Extraction
    # =========================================================================
    
    def _extract_semantic_facts(self, query: str) -> Dict[str, Any]:
        """Extract entities, numbers, and operations from query."""
        facts = {
            "numbers": [],
            "entities": [],
            "operations": [],
            "keywords": [],
            "question_type": None,
            "unit": None
        }
        
        # Extract numbers (including decimals and percentages)
        number_pattern = r'\b\d+(?:\.\d+)?%?\b'
        numbers = re.findall(number_pattern, query)
        for n in numbers:
            if n.endswith('%'):
                facts["numbers"].append(float(n[:-1]) / 100)
                facts["operations"].append("percentage")
            else:
                facts["numbers"].append(float(n))
        
        # Extract operation keywords
        query_lower = query.lower()
        for op_type, keywords in self.OPERATION_KEYWORDS.items():
            for keyword in keywords:
                if keyword in query_lower:
                    if op_type not in facts["operations"]:
                        facts["operations"].append(op_type)
                    facts["keywords"].append(keyword)
        
        # Extract question type
        if "how many" in query_lower or "how much" in query_lower:
            facts["question_type"] = "quantity"
        elif "what is" in query_lower:
            facts["question_type"] = "calculation"
        elif "percent" in query_lower or "%" in query:
            facts["question_type"] = "percentage"
        
        # Extract units
        unit_patterns = [
            r'\$?\d+(?:\.\d+)?(?:\s*(dollars?|cents?|euros?|pounds?))?',
            r'\d+(?:\.\d+)?\s*(apples?|oranges?|items?|people?|days?|hours?)',
        ]
        for pattern in unit_patterns:
            matches = re.findall(pattern, query_lower)
            if matches:
                facts["unit"] = matches[0] if isinstance(matches[0], str) else matches[0][0]
                break
        
        # Extract named entities (capitalized words)
        words = query.split()
        for word in words:
            if word and word[0].isupper() and len(word) > 1 and word.isalpha():
                if word not in ["I", "A", "The", "What", "How", "If"]:
                    facts["entities"].append(word)
        
        return facts
    
    # =========================================================================
    # Chain-of-Thought Parsing
    # =========================================================================
    
    def _parse_chain_of_thought(self, query: str, task: Any) -> List[ChainOfThoughtStep]:
        """Parse the reasoning into chain-of-thought steps."""
        steps = []
        
        # If task has a reasoning attribute, parse it
        if hasattr(task, 'reasoning') and task.reasoning:
            lines = task.reasoning.split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                if line and (line[0].isdigit() or line.startswith('-')):
                    steps.append(ChainOfThoughtStep(
                        step_number=i + 1,
                        description=line
                    ))
        
        # If no explicit reasoning, try to infer from expression
        if not steps and hasattr(task, 'expression'):
            # Parse expression into steps
            expr = task.expression
            
            # Detect operations
            if '+' in expr:
                steps.append(ChainOfThoughtStep(
                    step_number=1,
                    description="Addition operation",
                    operation="add"
                ))
            if '-' in expr:
                steps.append(ChainOfThoughtStep(
                    step_number=len(steps) + 1,
                    description="Subtraction operation",
                    operation="subtract"
                ))
            if '*' in expr:
                steps.append(ChainOfThoughtStep(
                    step_number=len(steps) + 1,
                    description="Multiplication operation",
                    operation="multiply"
                ))
            if '/' in expr:
                steps.append(ChainOfThoughtStep(
                    step_number=len(steps) + 1,
                    description="Division operation",
                    operation="divide"
                ))
        
        return steps
    
    def _validate_chain_of_thought(
        self, 
        steps: List[ChainOfThoughtStep], 
        facts: Dict[str, Any]
    ) -> List[str]:
        """Validate that chain-of-thought steps are consistent with facts."""
        issues = []
        
        # Check if operations in CoT match expected operations
        cot_operations = {s.operation for s in steps if s.operation}
        expected_operations = set(facts["operations"])
        
        if expected_operations and cot_operations:
            missing = expected_operations - cot_operations
            if missing:
                issues.append(f"Expected operations not in reasoning: {missing}")
        
        # Check for coherent step sequence
        if len(steps) < 1 and facts["operations"]:
            issues.append("No reasoning steps found for complex operation")
        
        return issues
    
    # =========================================================================
    # Reasoning Trace Generation
    # =========================================================================
    
    def _generate_reasoning_trace(self, query: str, task: Any) -> List[str]:
        """Generate reasoning trace using LLM."""
        if not self.primary_llm:
            return ["No LLM provider available for reasoning trace"]
        
        prompt = f"""Given this problem:
"{query}"

You generated the formula: {task.expression}

Explain your reasoning step-by-step. For each step, state:
1. What information you extracted
2. What operation you performed
3. Why you chose that operation

Format as a numbered list."""
        
        try:
            # Try to use the LLM's complete method
            if hasattr(self.primary_llm, 'complete'):
                response = self.primary_llm.complete(prompt)
                trace_text = response if isinstance(response, str) else str(response)
            elif hasattr(self.primary_llm, 'client'):
                # Anthropic client
                response = self.primary_llm.client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}]
                )
                trace_text = response.content[0].text
            else:
                return ["Could not generate reasoning trace"]
            
            # Parse into list
            lines = trace_text.split('\n')
            trace = [line.strip() for line in lines if line.strip() and (line[0].isdigit() or line.startswith('-'))]
            
            return trace if trace else ["No structured reasoning trace generated"]
            
        except Exception as e:
            return [f"Failed to generate reasoning trace: {str(e)}"]
    
    # =========================================================================
    # Formula Validation
    # =========================================================================
    
    def _validate_formula_semantics(self, facts: Dict, formula: str) -> List[str]:
        """Check if the formula makes semantic sense given the facts."""
        issues = []
        
        # Check: Are all numbers from the query in the formula?
        formula_numbers = set(float(n) for n in re.findall(r'\b\d+\.?\d*\b', formula))
        query_numbers = set(facts["numbers"])
        
        # Allow for small differences (percentages converted)
        missing_numbers = []
        for qn in query_numbers:
            found = False
            for fn in formula_numbers:
                if abs(qn - fn) < 0.001 or abs(qn * 100 - fn) < 0.001:
                    found = True
                    break
            if not found:
                missing_numbers.append(qn)
        
        if missing_numbers:
            issues.append(f"Formula missing numbers from query: {missing_numbers}")
        
        # Check: Do operations match keywords?
        if "multiply" in facts["operations"] or "times" in facts["keywords"]:
            if "*" not in formula and "**" not in formula:
                issues.append("Query mentions multiplication but formula doesn't contain '*'")
        
        if "subtract" in facts["operations"] or any(k in facts["keywords"] for k in ["eat", "lose", "spent"]):
            if "-" not in formula:
                issues.append("Query mentions subtraction but formula doesn't contain '-'")
        
        if "divide" in facts["operations"] or "per" in facts["keywords"]:
            if "/" not in formula:
                issues.append("Query mentions division but formula doesn't contain '/'")
        
        return issues
    
    # =========================================================================
    # Cross-Validation
    # =========================================================================
    
    def _cross_validate(self, query: str, primary_formula: str) -> Dict[str, Any]:
        """Cross-validate with secondary LLM."""
        result = {"formula": None, "issues": []}
        
        if not self.secondary_llm:
            return result
        
        try:
            secondary_task = self.secondary_llm.translate(query)
            result["formula"] = secondary_task.expression
            
            # Compare formulas
            if not self._formulas_equivalent(primary_formula, secondary_task.expression):
                result["issues"].append(
                    f"LLM disagreement: Primary='{primary_formula}' vs Secondary='{secondary_task.expression}'"
                )
        except Exception as e:
            result["issues"].append(f"Cross-validation failed: {str(e)}")
        
        return result
    
    def _formulas_equivalent(self, formula1: str, formula2: str) -> bool:
        """Check if two formulas are semantically equivalent."""
        # Normalize
        f1 = formula1.replace(" ", "").lower()
        f2 = formula2.replace(" ", "").lower()
        
        if f1 == f2:
            return True
        
        # Try to evaluate both (if simple enough)
        try:
            # Only evaluate if they look safe
            if re.match(r'^[\d\+\-\*/\.\(\)]+$', f1) and re.match(r'^[\d\+\-\*/\.\(\)]+$', f2):
                v1 = eval(f1)
                v2 = eval(f2)
                return abs(v1 - v2) < 0.0001
        except:
            pass
        
        return False
    
    # =========================================================================
    # Confidence Calculation
    # =========================================================================
    
    def _calculate_confidence(
        self,
        issues: List[str],
        facts: Dict,
        reasoning_trace: List[str],
        cot_steps: List[ChainOfThoughtStep]
    ) -> float:
        """Calculate confidence score based on validation results."""
        if not issues:
            return 1.0
        
        confidence = 1.0
        
        for issue in issues:
            issue_lower = issue.lower()
            if "missing numbers" in issue_lower:
                confidence -= 0.4
            elif "disagreement" in issue_lower:
                confidence -= 0.5  # LLM disagreement is serious
            elif "operation" in issue_lower:
                confidence -= 0.3
            elif "formula" in issue_lower or "reasoning" in issue_lower:
                confidence -= 0.3
            else:
                confidence -= 0.15
        
        # Penalty for weak reasoning trace
        if len(reasoning_trace) < 2:
            confidence -= 0.2
        
        # Penalty for missing CoT steps
        if len(cot_steps) < 1 and facts["operations"]:
            confidence -= 0.1
        
        return max(confidence, 0.0)
    
    # =========================================================================
    # Caching
    # =========================================================================
    
    def _get_cache_key(self, query: str, formula: str) -> str:
        """Generate cache key for query + formula."""
        content = f"{query}||{formula}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _cache_result(self, key: str, result: ReasoningValidation):
        """Cache a result with size limit."""
        if len(self._cache) >= self._cache_max_size:
            # Remove oldest entries (simple FIFO)
            oldest_keys = list(self._cache.keys())[:100]
            for k in oldest_keys:
                del self._cache[k]
        
        self._cache[key] = result
    
    def clear_cache(self):
        """
        Clear the result cache.

        Example:
            >>> verifier.clear_cache()
        """
        self._cache.clear()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dict containing current size and max size.

        Example:
            >>> stats = verifier.get_cache_stats()
            >>> print(stats["size"])
        """
        return {
            "size": len(self._cache),
            "max_size": self._cache_max_size
        }
