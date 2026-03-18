"""
OpenAI Direct Provider — Uses the official OpenAI Python SDK.

For direct OpenAI API access with sk-... keys.
NOT for Azure OpenAI (use azure_openai.py for that).
"""

import os
import json
import logging
from typing import Dict, Any, List

from openai import OpenAI
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class OpenAIDirectProvider(LLMProvider):
    """
    Provider for direct OpenAI API (gpt-4o, gpt-4o-mini, etc).
    Uses function calling (tools) for structured output.
    """

    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        if not self.api_key:
            raise ValueError(
                "OpenAI API key not found. "
                "Set OPENAI_API_KEY env var or run: qwed init"
            )

        self.client = OpenAI(api_key=self.api_key)

        # Tool schema for structured math output
        self.math_tool = {
            "type": "function",
            "function": {
                "name": "submit_math_expression",
                "description": "Submit a mathematical expression and its calculated result.",
                "parameters": MathVerificationTask.model_json_schema(),
            },
        }

    def _call_with_tool(self, system: str, user_msg: str, tool: dict, tool_name: str) -> dict:
        """Generic helper: call OpenAI with forced tool use."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            tools=[tool],
            tool_choice={"type": "function", "function": {"name": tool_name}},
            temperature=0.0,
        )
        tool_call = response.choices[0].message.tool_calls
        if not tool_call:
            raise ValueError("OpenAI did not use the required tool")
        return json.loads(tool_call[0].function.arguments)

    def _call_text(self, system: str, user_msg: str) -> str:
        """Generic helper: call OpenAI for plain text response."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,
        )
        return response.choices[0].message.content

    # ── LLMProvider Interface ──────────────────────────────────────

    def translate(self, user_query: str) -> MathVerificationTask:
        system = """You are a mathematical expression translator.
Convert natural language math questions into formal mathematical expressions.
Rules:
1. Use Python math syntax
2. Do NOT use variable names (except constants)
3. Convert percentages to decimals
4. Always calculate the numerical answer
You MUST use the submit_math_expression tool."""

        try:
            result = self._call_with_tool(system, user_query, self.math_tool, "submit_math_expression")
            return MathVerificationTask(**result)
        except Exception as e:
            logger.debug("OpenAI translation error: %s", e)
            raise ValueError("OpenAI translation failed.") from None

    def translate_logic(self, user_query: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask

        tool = {
            "type": "function",
            "function": {
                "name": "submit_z3_problem",
                "description": "Submit a logic or constraint satisfaction problem.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "variables": {
                            "type": "object",
                            "description": "Map of variable names to types (Int, Bool, Real)",
                            "additionalProperties": {"type": "string"},
                        },
                        "constraints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of constraints in Python syntax",
                        },
                        "goal": {"type": "string", "default": "SATISFIABILITY"},
                    },
                    "required": ["variables", "constraints"],
                },
            },
        }
        system = """You are a Logic Translator for the Z3 Theorem Prover.
Convert natural language logic puzzles into variables and constraints.
Use And(...), Or(...), Not(...) for logic. DO NOT use &, |, ~."""

        try:
            result = self._call_with_tool(system, user_query, tool, "submit_z3_problem")
            return LogicVerificationTask(**result)
        except Exception as e:
            logger.debug("OpenAI logic translation error: %s", e)
            raise ValueError("OpenAI logic translation failed.") from None

    def refine_logic(self, user_query: str, previous_error: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask

        tool = {
            "type": "function",
            "function": {
                "name": "submit_z3_problem",
                "description": "Submit a logic problem (refined based on error).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "variables": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                        },
                        "constraints": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "goal": {"type": "string", "default": "SATISFIABILITY"},
                    },
                    "required": ["variables", "constraints"],
                },
            },
        }
        system = f"""You are a Logic Translator. You previously made a mistake.
Fix based on this error: "{previous_error}"
Use And(...), Or(...), Not(...) for logic."""

        try:
            result = self._call_with_tool(system, user_query, tool, "submit_z3_problem")
            return LogicVerificationTask(**result)
        except Exception as e:
            logger.debug("OpenAI logic refinement error: %s", e)
            raise ValueError("OpenAI logic refinement failed.") from None

    def translate_stats(self, query: str, columns: List[str]) -> str:
        system = """You are a Python Data Science Expert.
Write Python code using Pandas to verify a claim about a dataset.
The dataset is loaded into `df`. Assign final result to `result`.
Output ONLY Python code. No markdown."""

        try:
            return self._call_text(system, f"Columns: {columns}\nQuery: {query}")
        except Exception as e:
            logger.debug("OpenAI stats translation error: %s", e)
            raise ValueError("OpenAI stats translation failed.") from None

    def verify_fact(self, claim: str, context: str) -> Dict[str, Any]:
        tool = {
            "type": "function",
            "function": {
                "name": "submit_fact_verification",
                "description": "Submit fact verification result.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "verdict": {"type": "string", "enum": ["SUPPORTED", "REFUTED", "NOT_ENOUGH_INFO"]},
                        "reasoning": {"type": "string"},
                        "citations": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["verdict", "reasoning", "citations"],
                },
            },
        }
        system = """You are a Fact Checking Engine. Verify the Claim against the Context.
Find EXACT QUOTES. Return SUPPORTED, REFUTED, or NOT_ENOUGH_INFO."""

        try:
            return self._call_with_tool(
                system, f"Context:\n{context}\n\nClaim:\n{claim}",
                tool, "submit_fact_verification"
            )
        except Exception as e:
            logger.debug("OpenAI fact verification error: %s", e)
            raise ValueError("OpenAI fact verification failed.") from None

    def verify_image(self, image_bytes: bytes, claim: str) -> Dict[str, Any]:
        import base64
        b64 = base64.b64encode(image_bytes).decode("utf-8")

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "Verify if the CLAIM is supported by the IMAGE. Return JSON: {verdict, reasoning, confidence}",
                    },
                    {
                        "role": "user",
                        "content": [
                            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}},
                            {"type": "text", "text": f"CLAIM: {claim}"},
                        ],
                    },
                ],
                temperature=0.0,
            )
            return json.loads(response.choices[0].message.content)
        except json.JSONDecodeError:
            return {"verdict": "ERROR", "reasoning": "Failed to parse response", "confidence": 0.0}
        except Exception:
            return {"verdict": "ERROR", "reasoning": "Image verification request failed", "confidence": 0.0}
