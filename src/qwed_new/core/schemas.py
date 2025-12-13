"""
Structured Output Schemas for QWED

This module defines the Pydantic models that enforce structured outputs from LLMs.
By using these schemas with OpenAI's function calling (or equivalent), we force
the LLM to return clean JSON instead of messy natural language.

This is the CORE of solving the "messy output" problem.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, List


class MathVerificationTask(BaseModel):
    """
    The structured format that ALL LLMs must return when translating a math query.
    
    This schema is used with:
    - OpenAI: Function Calling
    - Anthropic: Tool Use
    - Open Source: Constrained Decoding (e.g., outlines library)
    
    Example:
        User Query: "What is 15% of 200?"
        LLM Returns: {
            "expression": "0.15 * 200",
            "claimed_answer": 30.0,
            "reasoning": "15% as decimal is 0.15, multiply by 200",
            "confidence": 0.95
        }
    """
    
    expression: str = Field(
        description=(
            "A pure mathematical expression that can be evaluated by SymPy. "
            "Use standard Python math syntax: +, -, *, /, **, sqrt(), sin(), etc. "
            "Do NOT include variable names unless they are mathematical constants (pi, e). "
            "Examples: '2 + 2', '1000 * (1 + 0.05)**2', 'sqrt(16)'"
        ),
        examples=["2 + 2", "1000 * (1 + 0.05)**2", "sqrt(16) + 3**2"]
    )
    
    claimed_answer: float = Field(
        description=(
            "The numerical result of evaluating the expression. "
            "This is what the LLM *thinks* the answer is. "
            "The verification engine will check if this is correct."
        ),
        examples=[4.0, 1102.5, 13.0]
    )
    
    reasoning: str = Field(
        description=(
            "A step-by-step explanation of how you derived the expression. "
            "This helps with debugging and provides transparency to users."
        ),
        examples=[
            "2 plus 2 equals 4",
            "Compound interest formula: P(1+r)^t where P=1000, r=0.05, t=2",
            "Square root of 16 is 4, 3 squared is 9, sum is 13"
        ]
    )
    
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence score from 0.0 to 1.0. "
            "1.0 means certain, 0.5 means unsure. "
            "This can be used to flag low-confidence translations for human review."
        )
    )
    
    @field_validator('expression')
    @classmethod
    def expression_not_empty(cls, v: str) -> str:
        """Ensure the expression is not empty or just whitespace."""
        if not v or not v.strip():
            raise ValueError("Expression cannot be empty")
        return v.strip()
    
    @field_validator('reasoning')
    @classmethod
    def reasoning_not_empty(cls, v: str) -> str:
        """Ensure reasoning is provided."""
        if not v or not v.strip():
            raise ValueError("Reasoning cannot be empty")
        return v.strip()


class VerificationResult(BaseModel):
    """
    The final result returned by QWED after verification.
    
    This combines the LLM's translation with the symbolic engine's verdict.
    """
    
    status: str = Field(
        description="VERIFIED, CORRECTED, or FAILED",
        examples=["VERIFIED", "CORRECTED", "FAILED"]
    )
    
    user_query: str = Field(
        description="The original user question"
    )
    
    translation: MathVerificationTask = Field(
        description="The LLM's structured translation"
    )
    
    validation: dict = Field(
        description="Results from semantic validation layer",
        examples=[{
            "is_valid": True,
            "checks_passed": ["syntax", "symbols", "evaluable"]
        }]
    )
    
    verification: dict = Field(
        description="Results from symbolic verification",
        examples=[{
            "calculated_value": 30.0,
            "is_correct": True,
            "diff": 0.0
        }]
    )
    
    final_answer: float = Field(
        description="The guaranteed correct answer (from SymPy)"
    )
    
    latency_ms: Optional[float] = Field(
        default=None,
        description="Total processing time in milliseconds"
    )

class LogicVerificationTask(BaseModel):
    """
    Structured format for Logic/Constraint problems (for Z3).
    
    Example: "Schedule A, B, C such that A != B"
    """
    variables: Dict[str, str] = Field(
        description="Map of variable names to types (Int, Bool, Real). Example: {'A': 'Int', 'B': 'Int'}",
        examples=[{"A": "Int", "B": "Int"}],
        default_factory=dict
    )
    
    constraints: List[str] = Field(
        description="List of constraints in Python/Z3 syntax. Example: ['A > 0', 'B > A', 'A + B == 10']",
        examples=[["A > 0", "B > A", "A + B == 10"]]
    )
    
    goal: str = Field(
        description="What to solve for? 'SATISFIABILITY' or a specific variable to maximize/minimize.",
        default="SATISFIABILITY"
    )

class LogicResult(BaseModel):
    """Result of a Z3 logic verification."""
    status: str = Field(description="SAT or UNSAT")
    model: Optional[Dict[str, str]] = Field(default=None, description="Values that satisfy the constraints")
    error: Optional[str] = None
