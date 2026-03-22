"""
Gemini Provider — Integration for Google Gemini via google-generativeai.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional

try:
    import google.generativeai as genai
except ImportError:
    genai = None

from qwed_new.core.schemas import MathVerificationTask, LogicVerificationTask
from qwed_new.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class GeminiProvider(LLMProvider):
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.model_name = model or os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

        if genai is not None:
            if not self.api_key:
                raise ValueError(
                    "Gemini API key not found. Set GOOGLE_API_KEY env var or run: qwed init"
                )
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
        else:
            self.model = None

    def _call_text(self, system: str, user_msg: str) -> str:
        if self.model is None or genai is None:
            raise ImportError("google-generativeai package required for Gemini integration.")
        prompt = f"{system}\n\n{user_msg}"
        response = self.model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(temperature=0.0)
        )
        return response.text

    def _call_json(self, system: str, user_msg: str) -> dict:
        if self.model is None or genai is None:
            raise ImportError("google-generativeai package required for Gemini integration.")
        prompt = f"{system}\n\nRespond ONLY with valid JSON.\n\n{user_msg}"
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.0,
                    response_mime_type="application/json"
                )
            )
            content = response.text
            # Strip markdown code fences if present
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.debug("Gemini JSON parse error: %s", type(e).__name__)
            raise ValueError("Failed to parse JSON from Gemini endpoint.") from e
        except Exception as e:
            logger.debug("Gemini generic error: %s", type(e).__name__)
            raise ValueError(f"Gemini call failed: {e}") from e

    def translate(self, user_query: str) -> MathVerificationTask:
        system = """You are a mathematical expression translator.
Convert natural language math to formal expressions.
Respond with JSON: {"expression": "...", "claimed_answer": ..., "reasoning": "...", "confidence": 0.95}"""
        try:
            result = self._call_json(system, user_query)
            return MathVerificationTask(**result)
        except Exception:
            raise ValueError("Gemini math translation failed.") from None

    def translate_logic(self, user_query: str) -> LogicVerificationTask:
        system = """You are a Logic Translator for Z3. Convert to variables and constraints.
Rules:
- Return constraints using Python comparison syntax (use ==, !=, >=, <=, >, <).
- Convert requirement phrases to explicit binary constraints:
  - "approval is required" -> "approval == 1"
  - "approval is not required" -> "approval == 0"
- Avoid natural-language constraints.
Respond with JSON: {"variables": {"x": "Int"}, "constraints": ["x > 0"], "goal": "SATISFIABILITY"}"""
        try:
            result = self._call_json(system, user_query)
            return LogicVerificationTask(**result)
        except Exception:
            raise ValueError("Gemini logic translation failed.") from None

    def refine_logic(self, user_query: str, previous_error: str) -> LogicVerificationTask:
        system = f"""You are a Logic Translator. Fix based on error: "{previous_error}"
Respond with JSON: {{"variables": {{}}, "constraints": [], "goal": "SATISFIABILITY"}}"""
        try:
            result = self._call_json(system, user_query)
            return LogicVerificationTask(**result)
        except Exception:
            raise ValueError("Gemini logic refinement failed.") from None

    def translate_stats(self, query: str, columns: List[str]) -> str:
        system = """You are a Python Data Science Expert. Write code using Pandas. Dataset is in `df`. Assign result to `result`. Output ONLY Python code."""
        try:
            return self._call_text(system, f"Columns: {columns}\nQuery: {query}")
        except Exception:
            raise ValueError("Gemini stats translation failed.") from None

    def verify_fact(self, claim: str, context: str) -> Dict[str, Any]:
        system = """Verify the Claim against the Context. Find EXACT QUOTES.
Respond with JSON: {"verdict": "SUPPORTED|REFUTED|NOT_ENOUGH_INFO", "reasoning": "...", "citations": [...]}"""
        try:
            prompt = f"Claim: {claim}\n\nContext:\n{context}"
            return self._call_json(system, prompt)
        except Exception:
            raise ValueError("Gemini fact verification failed.") from None

    def verify_image(self, image_bytes: bytes, claim: str) -> Dict[str, Any]:
        system = """Analyze the image and verify the claim.
Respond with JSON: {"verified": true, "reasoning": "...", "confidence": 0.95}"""
        try:
            prompt = f"{system}\n\nClaim: {claim}"
            response = self.model.generate_content(
                [
                    {"mime_type": "image/jpeg", "data": image_bytes},
                    prompt
                ],
                generation_config=genai.types.GenerationConfig(
                    temperature=0.0,
                    response_mime_type="application/json"
                )
            )
            content = response.text
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            return json.loads(content)
        except Exception:
            raise ValueError("Gemini image verification failed.") from None
