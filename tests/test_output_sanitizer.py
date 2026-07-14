"""
Test suite for OutputSanitizer module.
Tests XSS prevention, HTML encoding, and math expression whitelisting.
"""

import pytest
from qwed_new.core.output_sanitizer import OutputSanitizer, SecurityError


class TestOutputSanitizer:
    def setup_method(self):
        self.sanitizer = OutputSanitizer()
    
    def test_xss_script_removal(self):
        """Test that <script> tags are removed."""
        malicious = {"result": "<script>alert('XSS')</script>Hello"}
        clean = self.sanitizer.sanitize_output(malicious, "math", 1)
        assert "<script>" not in str(clean["result"])
        assert "alert" not in str(clean["result"])
    
    def test_javascript_url_blocking(self):
        """Test that javascript: URLs are blocked."""
        malicious = {"link": "javascript:void(0)"}
        clean = self.sanitizer.sanitize_output(malicious, "math", 1)
        assert "javascript:" not in str(clean["link"])
    
    def test_html_encoding(self):
        """Test that HTML entities are encoded."""
        data = {"text": "<div>Test</div>"}
        clean = self.sanitizer.sanitize_output(data, "math", 1)
        # HTML should be escaped
        result_str = str(clean["text"])
        assert "&lt;" in result_str or "<div>" not in result_str
    
    def test_safe_math_expression_allowed(self):
        """Test that legitimate math expressions pass."""
        safe_expr = "2 + 2 * sqrt(16)"
        result = self.sanitizer._sanitize_math_expression(safe_expr)
        assert result == safe_expr
    
    def test_dangerous_math_expression_blocked(self):
        """Test that eval/exec in expressions are blocked."""
        with pytest.raises(SecurityError):
            self.sanitizer._sanitize_math_expression("eval('2+2')")
    
    def test_import_in_expression_blocked(self):
        """Test that import statements are blocked."""
        with pytest.raises(SecurityError):
            self.sanitizer._sanitize_math_expression("__import__('os').system('ls')")
    
    def test_nested_objects_sanitized(self):
        """Test that nested dictionaries are sanitized."""
        nested = {
            "outer": {
                "inner": "<script>bad</script>"
            }
        }
        clean = self.sanitizer.sanitize_output(nested, "math", 1)
        assert "<script>" not in str(clean)
    
    def test_iframe_removal(self):
        """Test that iframe tags are removed."""
        malicious = {"content": "<iframe src='evil.com'></iframe>"}
        clean = self.sanitizer.sanitize_output(malicious, "math", 1)
        assert "<iframe" not in str(clean["content"])
    
    def test_event_handler_removal(self):
        """Test that event handlers are removed."""
        malicious = {"html": "<img src=x onerror=alert('XSS')>"}
        clean = self.sanitizer.sanitize_output(malicious, "math", 1)
        assert "onerror" not in str(clean["html"]).lower()
    
    def test_list_sanitization(self):
        """Test that lists of strings are sanitized."""
        data = {"items": ["<script>bad</script>", "safe text"]}
        clean = self.sanitizer.sanitize_output(data, "math", 1)
        assert "<script>" not in str(clean["items"])
    
    def test_math_output_sanitization(self):
        """Test domain-specific math output sanitization."""
        result = {
            "status": "VERIFIED",
            "translation": {
                "expression": "2 + 2",
                "reasoning": "Simple addition"
            }
        }
        clean = self.sanitizer.sanitize_output(result, "math", 1)
        assert clean["translation"]["expression"] == "2 + 2"
    
    def test_double_underscore_blocked(self):
        """Test that double underscores (Python magic) are blocked."""
        with pytest.raises(SecurityError):
            self.sanitizer._sanitize_math_expression("__builtins__['eval']")
    
    def test_sanitization_counter(self):
        """Test that sanitization events are counted."""
        initial_count = self.sanitizer.get_sanitization_count()
        malicious = {"result": "<script>bad</script>"}
        self.sanitizer.sanitize_output(malicious, "math", 1)
        assert self.sanitizer.get_sanitization_count() > initial_count
    
    # ----- data URI removal tests (Layer 2 coverage) -----
    
    def test_data_uri_removed(self):
        """Well-formed data:text/html URI is stripped."""
        cleaned = self.sanitizer._strip_dangerous_content(
            "before data:text/html,base64,content after"
        )
        assert cleaned == "before base64,content after"
    
    def test_data_uri_case_insensitive(self):
        """Case variants of data:text/html prefix are matched."""
        cleaned = self.sanitizer._strip_dangerous_content(
            "before DATA:TEXT/HTML,payload after"
        )
        assert cleaned == "before payload after"
    
    def test_data_uri_no_comma_preserved(self):
        """data:text/html without a comma is treated as plain text."""
        cleaned = self.sanitizer._strip_dangerous_content(
            "text data:text/html(nocomma) more"
        )
        assert cleaned == "text data:text/html(nocomma) more"
    
    def test_data_uri_malformed_then_valid(self):
        """Malformed URI (no comma) followed by valid URI — only valid is stripped."""
        cleaned = self.sanitizer._strip_dangerous_content(
            "prefix data:text/html(nocomma) and data:text/html,keep after"
        )
        assert cleaned == "prefix data:text/html(nocomma) and keep after"
    
    def test_data_uri_consecutive(self):
        """Two consecutive well-formed URIs are both stripped."""
        cleaned = self.sanitizer._strip_dangerous_content(
            "a data:text/html,first data:text/html,second z"
        )
        assert cleaned == "a first second z"
    
    def test_data_uri_unrelated_comma_inside(self):
        """First comma consumed (prefix+first comma stripped)."""
        cleaned = self.sanitizer._strip_dangerous_content(
            "data:text/html(text, with comma),rest"
        )
        assert cleaned == " with comma),rest"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
