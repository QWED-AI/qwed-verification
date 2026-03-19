"""
Ollama Provider — Local LLM execution with zero network keys.

Auto-detects running Ollama instance at localhost:11434.
No API key required. Aligns with QWED sovereignty/offline philosophy.
"""

import os
import json
import logging
from typing import Dict, Any, List

from openai import OpenAI
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """
    Local LLM provider via Ollama.
    Uses OpenAI-compatible API at localhost:11434/v1.
    """

    def __init__(
        self,
        base_url: str = None,
        model: str = None,
    ):
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")

        # Ollama doesn't require auth — use env var or dummy token
        ollama_key = os.getenv("OLLAMA_API_KEY") or "not-needed"
        self.client = OpenAI(
            base_url=self.base_url,
            api_key=ollama_key,
        )

        logger.info("Ollama provider initialized for model '%s'", self.model)
        logger.debug("Ollama base_url: %s", self.base_url)

    def _call_text(self, system: str, user_msg: str) -> str:
        """Call Ollama for plain text response."""
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
        """Call Ollama expecting JSON response."""
        content = self._call_text(
            system + "\n\nYou MUST respond with ONLY valid JSON. No explanations.",
            user_msg,
        )
        # Strip markdown fences
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        return json.loads(content)

    # ── LLMProvider Interface ──────────────────────────────────────

    def translate(self, user_query: str) -> MathVerificationTask:
        system = """You are a mathematical expression translator.
Convert natural language math to formal expressions.
Respond with JSON: {"expression": "...", "claimed_answer": ..., "reasoning": "...", "confidence": 0.95}"""

        try:
            result = self._call_json(system, user_query)
            return MathVerificationTask(**result)
        except Exception as e:
            logger.debug("Ollama translation error: %s", type(e).__name__)
            raise ValueError("Ollama translation failed.") from None

    def translate_logic(self, user_query: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask

        system = """You are a Logic Translator for Z3.
Respond with JSON: {"variables": {"x": "Int"}, "constraints": ["x > 0"], "goal": "SATISFIABILITY"}"""

        try:
            result = self._call_json(system, user_query)
            return LogicVerificationTask(**result)
        except Exception as e:
            logger.debug("Ollama logic translation error: %s", type(e).__name__)
            raise ValueError("Ollama logic translation failed.") from None

    def refine_logic(self, user_query: str, previous_error: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask

        system = f"""You are a Logic Translator. Fix based on error: "{previous_error}"
Respond with JSON: {{"variables": {{}}, "constraints": [], "goal": "SATISFIABILITY"}}"""

        try:
            result = self._call_json(system, user_query)
            return LogicVerificationTask(**result)
        except Exception as e:
            logger.debug("Ollama logic refinement error: %s", type(e).__name__)
            raise ValueError("Ollama logic refinement failed.") from None

    def translate_stats(self, query: str, columns: List[str]) -> str:
        system = """You are a Python Data Science Expert.
Write code using Pandas. Dataset is in `df`. Assign result to `result`.
Output ONLY Python code."""

        return self._call_text(system, f"Columns: {columns}\nQuery: {query}")

    def verify_fact(self, claim: str, context: str) -> Dict[str, Any]:
        system = """Verify the Claim against the Context. Find EXACT QUOTES.
Respond with JSON: {"verdict": "SUPPORTED|REFUTED|NOT_ENOUGH_INFO", "reasoning": "...", "citations": [...]}"""

        try:
            return self._call_json(system, f"Context:\n{context}\n\nClaim:\n{claim}")
        except Exception as e:
            logger.debug("Ollama fact verification error: %s", type(e).__name__)
            raise ValueError("Ollama fact verification failed.") from None

    def verify_image(self, image_bytes: bytes, claim: str) -> Dict[str, Any]:
        # Most Ollama models don't support vision
        return {
            "verdict": "INCONCLUSIVE",
            "reasoning": "Image verification not available with this Ollama model.",
            "confidence": 0.0,
        }
