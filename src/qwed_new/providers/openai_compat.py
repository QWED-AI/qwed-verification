"""
OpenAI-Compatible Provider — Universal abstraction for any OpenAI-compatible API.

Central abstraction covering:
  - DigitalOcean GenAI
  - Groq
  - Together AI
  - LM Studio
  - Enterprise internal gateways
  - Any endpoint implementing the OpenAI chat/completions spec
"""

import os
import json
import logging
from typing import Dict, Any, List

from openai import OpenAI
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class OpenAICompatProvider(LLMProvider):
    """
    Generic provider for any OpenAI-compatible endpoint.

    Usage:
        provider = OpenAICompatProvider(
            base_url="https://inference.do-ai.run/v1",
            api_key="sk-do-...",
            model="openai-gpt-5.4"
        )
    """

    def __init__(
        self,
        base_url: str = None,
        api_key: str = None,
        model: str = None,
    ):
        self.base_url = base_url or os.getenv("CUSTOM_BASE_URL")
        self.api_key = api_key or os.getenv("CUSTOM_API_KEY")
        self.model = model or os.getenv("CUSTOM_MODEL", "gpt-4o-mini")

        if not self.base_url:
            raise ValueError(
                "Base URL not found. Set CUSTOM_BASE_URL env var or run: qwed init"
            )

        # Handle no-auth endpoints: use dummy key if None
        client_api_key = self.api_key if self.api_key else "dummy"

        self.client = OpenAI(
            base_url=self.base_url,
            api_key=client_api_key,
        )

    def _call_text(self, system: str, user_msg: str) -> str:
        """Call the endpoint for a plain text response."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,
        )
        return response.choices[0].message.content

    def _call_json(self, system: str, user_msg: str) -> dict:
        """
        Call the endpoint expecting a JSON response.

        Falls back to text extraction if the endpoint doesn't support
        response_format or function calling.
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system + "\n\nRespond ONLY with valid JSON."},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.0,
            )
            content = response.choices[0].message.content
            # Strip markdown code fences if present
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.debug("OpenAI-Compatible JSON parse error: %s", type(e).__name__)
            raise ValueError("Failed to parse JSON from endpoint.") from None

    # ── LLMProvider Interface ──────────────────────────────────────

    def translate(self, user_query: str) -> MathVerificationTask:
        system = """You are a mathematical expression translator.
Convert natural language math to formal expressions.
Respond with JSON: {"expression": "...", "claimed_answer": ..., "reasoning": "...", "confidence": 0.95}"""

        try:
            result = self._call_json(system, user_query)
            return MathVerificationTask(**result)
        except Exception as e:
            logger.debug("OpenAI-Compatible translation error: %s", type(e).__name__)
            raise ValueError("OpenAI-Compatible translation failed.") from None

    def translate_logic(self, user_query: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask

        system = """You are a Logic Translator for Z3. Convert to variables and constraints.
Respond with JSON: {"variables": {"x": "Int"}, "constraints": ["x > 0"], "goal": "SATISFIABILITY"}"""

        try:
            result = self._call_json(system, user_query)
            return LogicVerificationTask(**result)
        except Exception as e:
            logger.debug("OpenAI-Compatible logic translation error: %s", type(e).__name__)
            raise ValueError("OpenAI-Compatible logic translation failed.") from None

    def refine_logic(self, user_query: str, previous_error: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask

        system = f"""You are a Logic Translator. Fix based on error: "{previous_error}"
Respond with JSON: {{"variables": {{}}, "constraints": [], "goal": "SATISFIABILITY"}}"""

        try:
            result = self._call_json(system, user_query)
            return LogicVerificationTask(**result)
        except Exception as e:
            logger.debug("OpenAI-Compatible logic refinement error: %s", type(e).__name__)
            raise ValueError("OpenAI-Compatible logic refinement failed.") from None

    def translate_stats(self, query: str, columns: List[str]) -> str:
        system = """You are a Python Data Science Expert.
Write code using Pandas. Dataset is in `df`. Assign result to `result`.
Output ONLY Python code."""

        try:
            return self._call_text(system, f"Columns: {columns}\nQuery: {query}")
        except Exception as e:
            logger.debug("OpenAI-Compatible stats translation error: %s", type(e).__name__)
            raise ValueError("OpenAI-Compatible stats translation failed.") from None

    def verify_fact(self, claim: str, context: str) -> Dict[str, Any]:
        system = """Verify the Claim against the Context. Find EXACT QUOTES.
Respond with JSON: {"verdict": "SUPPORTED|REFUTED|NOT_ENOUGH_INFO", "reasoning": "...", "citations": [...]}"""

        try:
            return self._call_json(system, f"Context:\n{context}\n\nClaim:\n{claim}")
        except Exception as e:
            logger.debug("OpenAI-Compatible fact verification error: %s", type(e).__name__)
            raise ValueError("OpenAI-Compatible fact verification failed.") from None

    def verify_image(self, image_bytes: bytes, claim: str) -> Dict[str, Any]:
        # Most OpenAI-compat endpoints don't support vision — return graceful error
        return {
            "verdict": "INCONCLUSIVE",
            "reasoning": "Image verification not available on this endpoint.",
            "confidence": 0.0,
        }
