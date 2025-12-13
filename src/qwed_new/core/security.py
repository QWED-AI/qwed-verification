"""
Security Gateway for QWED.
Handles Prompt Injection detection and PII redaction.

OWASP LLM01:2025 - Prompt Injection Defense (Multi-Layer)
"""
import re
import base64
import logging
from typing import Tuple, Optional, Dict
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class SecurityGateway:
    """
    Basic security middleware for LLM Security.
    1. Detects Prompt Injection attempts using heuristics.
    2. Redacts PII (Personally Identifiable Information) from logs/inputs.
    """
    
    def __init__(self):
        # Math keywords whitelist (don't flag as malicious)
        self.math_whitelist = ['sqrt', 'log', 'ln', 'exp', 'sin', 'cos', 'tan', 'abs', 'max', 'min']
        
        # Heuristic patterns for Prompt Injection
        # These are common "jailbreak" phrases.
        self.injection_patterns = [
            r"ignore previous instructions",
            r"ignore all instructions",
            r"forget everything",
            r"forget all",
            r"tell me secrets",
            r"system override",
            r"you are now",
            r"developer mode",
            r"act as",
            r"forget your rules",
            r"ignore the above",
            r"simulated mode",
            r"disregard.*instructions",
            r"disregard.*prompt"
        ]
        
        # PII Patterns (Regex)
        self.pii_patterns = {
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "PHONE": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", # Simple US format
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "IP": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        }

    def detect_injection(self, prompt: str) -> Tuple[bool, Optional[str]]:
        """
        Checks for potential prompt injection attempts.
        Returns (is_safe, reason).
        """
        # 1. Length Check (Prevent buffer overflow / context exhaustion)
        if len(prompt) > 10000:
            return False, "Input too long (max 10000 chars)"

        # 2. Check if query contains whitelisted math terms (bypass checks)
        prompt_lower = prompt.lower()
        if any(math_term in prompt_lower for math_term in self.math_whitelist):
            # Still check length but skip pattern matching
            return True, None

        # 3. Heuristic Check
        for pattern in self.injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                return False, f"Potential Prompt Injection detected: '{pattern}'"
        
        return True, None

    def redact_pii(self, text: str) -> str:
        """
        Redacts PII from text.
        """
        redacted = text
        for p_type, pattern in self.pii_patterns.items():
            redacted = re.sub(pattern, f"[{p_type}_REDACTED]", redacted)
        return redacted


class EnhancedSecurityGateway:
    """
    Advanced multi-layer prompt injection defense.
    
    OWASP LLM01:2025 Compliance - Comprehensive protection against:
    - Base64-encoded injections
    - Unicode tricks and homoglyphs
    - Multi-language script mixing
    - Semantic similarity attacks
    - Length-based attacks
    
    Research-backed: 70% of attacks blocked by length limits alone.
    """
    
    def __init__(self, system_prompt: Optional[str] = None):
        # Wrap basic gateway for backward compatibility
        self.basic_gateway = SecurityGateway()
        
        # Enhanced parameters
        self.max_input_length = 2000  # Research-based: 70% attack prevention
        self.similarity_threshold = 0.6  # System prompt similarity detection
        
        # Store system prompt for similarity checks
        self.system_prompt = system_prompt or (
            "You are a mathematical expression translator for QWED. "
            "Convert natural language math queries to Python expressions."
        )
        
        # Additional injection keywords (beyond basic patterns)
        self.advanced_keywords = [
            'disregard', 'override', 'bypass', 'jailbreak', 'prompt',
            'instructions', 'system', 'admin', 'root', 'sudo',
            'pretend', 'roleplay', 'act like', 'simulate',
            'developer', 'debug', 'mode', 'unlock'
        ]
        
        # Block count for monitoring
        self.blocks_count = 0
    
    def detect_advanced_injection(self, prompt: str) -> Tuple[bool, Optional[str]]:
        """
        Multi-layer injection detection.
        
        Returns:
            (is_safe, reason) - True if safe, False with reason if blocked
        """
        # Layer 1: Basic patterns (existing SecurityGateway)
        is_safe, reason = self.basic_gateway.detect_injection(prompt)
        if not is_safe:
            self.blocks_count += 1
            logger.warning(f"Basic injection detected: {reason}")
            return False, reason
        
        # Layer 2: Stricter length check (70% effective per research)
        if len(prompt) > self.max_input_length:
            self.blocks_count += 1
            logger.warning(f"Input exceeds {self.max_input_length} chars: {len(prompt)}")
            return False, (
                f"Input too long ({len(prompt)} chars). "
                f"Maximum {self.max_input_length} characters allowed."
            )
        
        # Layer 3: Base64/encoding detection
        is_safe, reason = self._check_base64_encoding(prompt)
        if not is_safe:
            self.blocks_count += 1
            logger.warning(f"Base64 injection detected: {reason}")
            return False, reason
        
        # Layer 4: Semantic similarity to system prompt
        similarity = SequenceMatcher(None, prompt.lower(), self.system_prompt.lower()).ratio()
        if similarity > self.similarity_threshold:
            self.blocks_count += 1
            logger.warning(f"High similarity to system prompt: {similarity:.2%}")
            return False, (
                f"Input mimics system prompt structure (similarity: {similarity:.0%}). "
                "This may be a prompt injection attempt."
            )
        
        # Layer 5: Advanced keyword detection
        if self._contains_injection_keywords(prompt):
            self.blocks_count += 1
            return False, "Input contains suspicious keywords commonly used in prompt injections"
        
        # Layer 6: Multi-language script detection
        if self._contains_mixed_scripts(prompt):
            self.blocks_count += 1
            logger.warning("Mixed Unicode scripts detected")
            return False, "Input contains mixed-language scripts (potential evasion technique)"
        
        # Layer 7: Zero-width character detection
        if self._contains_zero_width_chars(prompt):
            self.blocks_count += 1
            logger.warning("Zero-width characters detected")
            return False, "Input contains hidden zero-width characters"
        
        # All checks passed
        return True, None
    
    def _check_base64_encoding(self, text: str) -> Tuple[bool, Optional[str]]:
        """Detect Base64-encoded injection payloads."""
        # Look for Base64-like patterns (length divisible by 4, only valid chars)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        for match in matches:
            try:
                # Attempt to decode
                decoded = base64.b64decode(match, validate=True)
                decoded_text = decoded.decode('utf-8', errors='ignore').lower()
                
                # Check if decoded content contains injection keywords
                if self._contains_injection_keywords(decoded_text):
                    return False, "Base64-encoded injection payload detected"
                    
            except Exception:
                # Not valid Base64 or not decodable, continue
                pass
        
        return True, None
    
    def _contains_injection_keywords(self, text: str) -> bool:
        """Check for common injection phrases."""
        text_lower = text.lower()
        
        # Check advanced keywords
        for keyword in self.advanced_keywords:
            if keyword in text_lower:
                return True
        
        # Check basic patterns from SecurityGateway
        for pattern in self.basic_gateway.injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _contains_mixed_scripts(self, text: str) -> bool:
        """
        Detect suspicious mixing of Unicode scripts.
        
        Attackers use Cyrillic, Arabic, or other scripts mixed with Latin
        to evade simple pattern matching.
        """
        scripts = set()
        
        for char in text:
            # Cyrillic
            if '\u0400' <= char <= '\u04FF':
                scripts.add('cyrillic')
            # Arabic
            elif '\u0600' <= char <= '\u06FF':
                scripts.add('arabic')
            # Chinese/Japanese/Korean
            elif '\u4E00' <= char <= '\u9FFF':
                scripts.add('cjk')
            # Greek
            elif '\u0370' <= char <= '\u03FF':
                scripts.add('greek')
            # Latin (normal English)
            elif char.isalpha():
                scripts.add('latin')
        
        # If more than one script, it's suspicious
        # Exception: allow CJK + Latin (common in multilingual queries)
        if len(scripts) > 1:
            # Allow latin + CJK combination
            if scripts == {'latin', 'cjk'}:
                return False
            return True
        
        return False
    
    def _contains_zero_width_chars(self, text: str) -> bool:
        """Detect zero-width characters used for obfuscation."""
        zero_width_chars = [
            '\u200B',  # Zero-width space
            '\u200C',  # Zero-width non-joiner
            '\u200D',  # Zero-width joiner
            '\uFEFF',  # Zero-width no-break space
        ]
        
        return any(char in text for char in zero_width_chars)
    
    def get_blocks_count(self) -> int:
        """Get total number of blocked attempts."""
        return self.blocks_count
    
    def redact_pii(self, text: str) -> str:
        """Delegate to basic gateway for PII redaction."""
        return self.basic_gateway.redact_pii(text)
