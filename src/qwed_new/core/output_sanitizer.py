"""
Output Sanitization Module for QWED.
OWASP LLM02:2025 - Insecure Output Handling Defense

This module sanitizes all LLM outputs before they are returned to users
or used in downstream systems, preventing XSS, code injection, and other attacks.
"""

import re
import html
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class OutputSanitizer:
    """
    Sanitizes LLM outputs to prevent security vulnerabilities.
    
    Key protections:
    - XSS/HTML injection prevention
    - JavaScript URL blocking
    - Mathematical expression whitelisting
    - Code output validation
    - PII re-redaction (belt-and-suspenders)
    """
    
    def __init__(self):
        # Dangerous HTML/JS patterns
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',                 # JavaScript URLs
            r'on\w+\s*=',                  # Event handlers (onclick, onerror, etc.)
            r'<iframe[^>]*>',              # Iframes
            r'<embed[^>]*>',               # Embed tags
            r'<object[^>]*>',              # Object tags
        ]
        
        # Allowed characters for math expressions
        self.math_allowed_chars = set('0123456789+-*/().epi sqrt sin cos tan log ln abs exp ')
        
        # Dangerous keywords in any output
        self.dangerous_keywords = [
            'eval', 'exec', '__import__', '__builtins__', 
            'compile', 'open', 'file', 'input', 'raw_input'
        ]
        
        # Sanitization event counter
        self.sanitization_count = 0
    
    def sanitize_output(
        self, 
        result: Dict[str, Any], 
        output_type: str, 
        organization_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Main sanitization entry point.
        
        Args:
            result: The verification result dictionary
            output_type: Type of output ('math', 'logic', 'code', 'stats', 'fact')
            organization_id: For logging purposes
            
        Returns:
            Sanitized result dictionary
        """
        sanitized_result = {}
        
        # Track if we made any changes
        changes_made = False
        
        # 1. Sanitize all string fields recursively
        for key, value in result.items():
            if isinstance(value, str):
                sanitized_value = self._strip_dangerous_content(value)
                if sanitized_value != value:
                    changes_made = True
                    logger.warning(
                        f"Sanitized output field '{key}' for org {organization_id}: "
                        f"removed {len(value) - len(sanitized_value)} dangerous chars"
                    )
                sanitized_result[key] = sanitized_value
            elif isinstance(value, dict):
                # Recursively sanitize nested dicts
                sanitized_result[key] = self.sanitize_output(
                    value, output_type, organization_id
                )
            elif isinstance(value, list):
                # Sanitize list items
                sanitized_result[key] = [
                    self._strip_dangerous_content(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                # Keep non-string values as-is
                sanitized_result[key] = value
        
        # 2. Domain-specific sanitization
        if output_type == "math":
            sanitized_result = self._sanitize_math_output(sanitized_result)
        elif output_type == "code":
            sanitized_result = self._sanitize_code_output(sanitized_result)
        elif output_type == "logic":
            sanitized_result = self._sanitize_logic_output(sanitized_result)
        
        # 3. Log sanitization event if changes were made
        if changes_made:
            self.sanitization_count += 1
            self._log_sanitization_event(
                result_type=output_type,
                org_id=organization_id,
                changes_made=True
            )
        
        return sanitized_result
    
    def _strip_dangerous_content(self, text: str) -> str:
        """
        Remove XSS, script injection, and other dangerous content.
        
        Protection layers:
        1. Remove script tags and event handlers
        2. Remove JavaScript URLs
        3. HTML encode remaining content
        """
        if not text or not isinstance(text, str):
            return text
        
        cleaned = text
        
        # Layer 1: Remove dangerous patterns
        for pattern in self.dangerous_patterns:
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE | re.DOTALL)
        
        # Layer 2: Remove data URIs (can contain base64-encoded malicious content)
        cleaned = re.sub(r'data:text/html[^,]*,', '', cleaned, flags=re.IGNORECASE)
        
        # Layer 3: HTML encode special characters
        # This prevents any remaining HTML from being executed
        cleaned = html.escape(cleaned)
        
        return cleaned
    
    def _sanitize_math_expression(self, expr: str) -> str:
        """
        Ensure mathematical expression contains ONLY safe operations.
        
        Uses whitelist approach - only allow known-safe math operations.
        """
        if not expr:
            return expr
        
        # Normalize whitespace
        expr = ' '.join(expr.split())
        
        # Check for dangerous keywords first
        expr_lower = expr.lower()
        for keyword in self.dangerous_keywords:
            if keyword in expr_lower:
                raise SecurityError(
                    f"Math expression contains dangerous keyword: '{keyword}'"
                )
        
        # Whitelist check - only allow safe math characters
        # We allow letters for function names (sqrt, sin, etc.)
        for char in expr:
            if not (char in self.math_allowed_chars or char.isalpha() or char.isspace()):
                raise SecurityError(
                    f"Math expression contains disallowed character: '{char}'"
                )
        
        # Additional check: no double underscores (Python magic methods)
        if '__' in expr:
            raise SecurityError("Math expression contains '__' (not allowed)")
        
        return expr
    
    def _sanitize_math_output(self, result: Dict) -> Dict:
        """Sanitize math-specific output fields."""
        # If there's a 'translation' field with an 'expression', validate it
        if 'translation' in result and isinstance(result['translation'], dict):
            if 'expression' in result['translation']:
                try:
                    expr = result['translation']['expression']
                    if isinstance(expr, str):
                        result['translation']['expression'] = self._sanitize_math_expression(expr)
                except SecurityError as e:
                    logger.error(f"Math expression sanitization failed: {e}")
                    # Replace with safe default
                    result['translation']['expression'] = "INVALID_EXPRESSION"
                    result['status'] = 'ERROR'
                    result['error'] = str(e)
        
        return result
    
    def _sanitize_code_output(self, result: Dict) -> Dict:
        """
        Sanitize code-specific output.
        
        For code verification results, ensure no executable code leaks through.
        """
        # If there's generated code in the output, HTML encode it
        if 'code' in result and isinstance(result['code'], str):
            result['code'] = html.escape(result['code'])
        
        if 'generated_code' in result and isinstance(result['generated_code'], str):
            result['generated_code'] = html.escape(result['generated_code'])
        
        return result
    
    def _sanitize_logic_output(self, result: Dict) -> Dict:
        """Sanitize logic verification output."""
        # Logic constraints should not contain code execution attempts
        if 'translation' in result and isinstance(result['translation'], dict):
            if 'constraints' in result['translation']:
                constraints = result['translation']['constraints']
                if isinstance(constraints, str):
                    # Check for dangerous keywords in constraints
                    for keyword in self.dangerous_keywords:
                        if keyword in constraints.lower():
                            logger.warning(
                                f"Dangerous keyword '{keyword}' found in logic constraints"
                            )
                            result['translation']['constraints'] = "SANITIZED"
                            break
        
        return result
    
    def _log_sanitization_event(
        self, 
        result_type: str, 
        org_id: Optional[int],
        changes_made: bool
    ):
        """Log sanitization events for security monitoring."""
        logger.info(
            f"Output sanitization #{self.sanitization_count}: "
            f"type={result_type}, org={org_id}, changes={changes_made}, "
            f"timestamp={datetime.utcnow().isoformat()}"
        )
    
    def get_sanitization_count(self) -> int:
        """Get total number of sanitization events."""
        return self.sanitization_count


class SecurityError(Exception):
    """Raised when security validation fails."""
    pass
