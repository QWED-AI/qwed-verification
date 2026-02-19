
import unittest
from unittest.mock import MagicMock, patch
from qwed_sdk.qwed_local import QWEDLocal


class TestQWEDLocalCoverage(unittest.TestCase):
    """Targeted tests to improve coverage of qwed_local.py"""

    def test_init_openai_provider(self):
        """Test initialization with OpenAI provider."""
        with patch("qwed_sdk.qwed_local.OpenAI") as MockOpenAI:
            client = QWEDLocal(provider="openai", api_key="sk-test", cache=False)
            self.assertEqual(client.client_type, "openai")
            MockOpenAI.assert_called_with(api_key="sk-test")

    def test_init_anthropic_provider(self):
        """Test initialization with Anthropic provider."""
        with patch("qwed_sdk.qwed_local.Anthropic") as MockAnthropic:
            client = QWEDLocal(provider="anthropic", api_key="sk-ant", cache=False)
            self.assertEqual(client.client_type, "anthropic")
            MockAnthropic.assert_called_with(api_key="sk-ant")

    def test_init_gemini_provider(self):
        """Test initialization with Gemini provider."""
        with patch("qwed_sdk.qwed_local.genai") as MockGenAI:
            client = QWEDLocal(provider="gemini", api_key="AIza", cache=False)
            self.assertEqual(client.client_type, "gemini")
            MockGenAI.configure.assert_called_with(api_key="AIza")

    def test_init_custom_base_url(self):
        """Test initialization with custom base_url (Ollama style)."""
        with patch("qwed_sdk.qwed_local.OpenAI") as MockOpenAI:
            client = QWEDLocal(base_url="http://localhost:11434", cache=False)
            self.assertEqual(client.client_type, "openai")
            MockOpenAI.assert_called()

    def test_init_missing_deps(self):
        """Test import error when dependencies missing."""
        pass

    def test_verify_auto_detect(self):
        """Test verify() method defaults to verify_math."""
        client = QWEDLocal(base_url="http://mock", cache=False)
        client.verify_math = MagicMock(return_value="math_result")
        
        res = client.verify("2+2")
        self.assertEqual(res, "math_result")
        client.verify_math.assert_called_with("2+2")

    def test_verify_code_unsupported_lang(self):
        """Test verify_code with unsupported language."""
        client = QWEDLocal(base_url="http://mock", cache=False)
        res = client.verify_code("print('h')", language="java")
        self.assertFalse(res.verified)
        self.assertIn("Only Python supported", res.error)

    def test_cache_stats_none(self):
        """Test cache stats when cache disabled."""
        client = QWEDLocal(base_url="http://mock", cache=False)
        self.assertIsNone(client.cache_stats)
        # Should not crash
        client.print_cache_stats()

    def test_check_verifiers_missing(self):
        """Test _check_verifiers when deps are missing."""
        with patch("qwed_sdk.qwed_local.sympy", new=None), \
             patch("qwed_sdk.qwed_local.Solver", new=None):
            client = QWEDLocal(base_url="http://mock", cache=False)
            self.assertFalse(client.has_sympy)
            self.assertFalse(client.has_z3)

    def test_show_github_nudge(self):
        """Test the github nudge logic."""
        import qwed_sdk.qwed_local as mod
        
        # Reset counters
        mod._verification_count = 0
        mod._has_shown_nudge = False
        
        # 1st time - no show
        mod._show_github_nudge()
        self.assertFalse(mod._has_shown_nudge)
        
        # 2nd time - no show
        mod._show_github_nudge()
        
        # 3rd time - SHOW
        mod._show_github_nudge()
        self.assertTrue(mod._has_shown_nudge)
        
        # 10th time - SHOW again
        mod._verification_count = 9
        mod._show_github_nudge()

    def test_show_github_nudge_no_color(self):
        """Test nudge without color (non-colored fallback path)."""
        import qwed_sdk.qwed_local as mod
        
        old_count = mod._verification_count
        old_shown = mod._has_shown_nudge
        old_has_color = mod.HAS_COLOR
        
        try:
            # Directly set the module-level variable
            mod.HAS_COLOR = False
            mod._verification_count = 2
            mod._has_shown_nudge = False
            
            with patch('builtins.print') as mock_print:
                mod._show_github_nudge()
                
                self.assertTrue(mod._has_shown_nudge)
                
                # Verify print was called with non-colored separator
                args, _ = mock_print.call_args_list[0]
                self.assertIn("─" * 60, args[0])
        finally:
            mod._verification_count = old_count
            mod._has_shown_nudge = old_shown
            mod.HAS_COLOR = old_has_color

    def test_cache_hit_printing_logic(self):
        """Test cache hit printing paths."""
        import qwed_sdk.qwed_local as mod
        
        client = QWEDLocal(base_url="http://mock", cache=True)
        # Mock the cache to return a valid VerificationResult-compatible dict
        mock_cache = MagicMock()
        mock_cache.get.return_value = {"verified": True, "value": 42, "confidence": 1.0}
        # Make cache truthy
        mock_cache.__bool__ = MagicMock(return_value=True)
        client._cache = mock_cache
        
        old_has_color = mod.HAS_COLOR
        
        try:
            # 1. Test WITH Color
            mod.HAS_COLOR = True
            with patch("os.getenv", return_value="0"), \
                 patch('builtins.print') as mock_print:
                client.verify("q")
                mock_print.assert_called()
                # Find the "Cache HIT" print call
                found_cache_hit = any(
                    "Cache HIT" in str(call)
                    for call in mock_print.call_args_list
                )
                self.assertTrue(found_cache_hit, "Expected 'Cache HIT' print")

            # 2. Test WITHOUT Color
            mod.HAS_COLOR = False
            with patch('builtins.print') as mock_print:
                client.verify("q")
                # Without HAS_COLOR, no cache HIT print
                found_cache_hit = any(
                    "Cache HIT" in str(call)
                    for call in mock_print.call_args_list
                )
                self.assertFalse(found_cache_hit, "Should NOT print 'Cache HIT' without color")
        finally:
            mod.HAS_COLOR = old_has_color

    def test_is_safe_sympy_expr_complex(self):
        """Test safe sympy validator with various node types."""
        import qwed_sdk.qwed_local as mod
        
        # Valid cases - bare expressions and safe builtins
        self.assertTrue(mod._is_safe_sympy_expr("1 + 2"))
        self.assertTrue(mod._is_safe_sympy_expr("abs(x)"))
        self.assertTrue(mod._is_safe_sympy_expr("int(1.5)"))
        # Attribute-style calls (e.g., sympy.sin) ARE allowed
        self.assertTrue(mod._is_safe_sympy_expr("sympy.sin(x)"))
        self.assertTrue(mod._is_safe_sympy_expr("sympy.simplify(x**2 + 2*x + 1)"))
        
        # Invalid cases - bare function calls NOT in safe_funcs
        # Security design: only abs/int allowed as bare calls.
        # sin(x), simplify(x) etc are rejected (must use sympy.sin(x))
        self.assertFalse(mod._is_safe_sympy_expr("sin(x)"))
        self.assertFalse(mod._is_safe_sympy_expr("simplify(x**2)"))
        
        # Import/exec-style attacks
        self.assertFalse(mod._is_safe_sympy_expr("import os"))
        self.assertFalse(mod._is_safe_sympy_expr("open('file')"))
        self.assertFalse(mod._is_safe_sympy_expr("print('hi')"))
        
        # String arg injection (sympy.simplify internally calls eval on strings)
        self.assertFalse(mod._is_safe_sympy_expr("sympy.simplify('rm -rf')"))
        self.assertFalse(mod._is_safe_sympy_expr("sympy.simplify(x, nice='rm -rf')"))
        
        # float/complex removed from whitelist
        self.assertFalse(mod._is_safe_sympy_expr("float(1.0)"))
        
    def test_call_llm_routes(self):
        """Test _call_llm routing to different clients."""
        client = QWEDLocal(base_url="http://mock", cache=False)
        
        # 1. OpenAI
        client.client_type = "openai"
        client.llm_client = MagicMock()
        client.llm_client.chat.completions.create.return_value.choices[0].message.content = "openai_resp"
        self.assertEqual(client._call_llm("prompt"), "openai_resp")
        
        # 2. Anthropic
        client.client_type = "anthropic"
        client.llm_client = MagicMock()
        client.llm_client.messages.create.return_value.content[0].text = "anthropic_resp"
        self.assertEqual(client._call_llm("prompt"), "anthropic_resp")
        
        # 3. Gemini
        client.client_type = "gemini"
        client.llm_client = MagicMock()
        client.llm_client.generate_content.return_value.text = "gemini_resp"
        self.assertEqual(client._call_llm("prompt"), "gemini_resp")
        
        # 4. Unknown
        client.client_type = "mysterious_ai"
        with self.assertRaises(NotImplementedError):
            client._call_llm("prompt")

    def test_pii_masking_active(self):
        """Test PII masking path."""
        # PIIDetector is imported inside __init__ from qwed_sdk.pii_detector
        with patch("qwed_sdk.qwed_local.QWEDLocal.__init__", return_value=None):
            client = QWEDLocal.__new__(QWEDLocal)
            # Manually set attributes that __init__ would set
            client.mask_pii = True
            client._pii_detector = MagicMock()
            client._pii_detector.detect_and_mask.return_value = (
                "masked prompt",
                {"pii_detected": 5, "types": ["EMAIL"]}
            )
            client.client_type = "openai"
            client.model = "gpt-4"
            client.llm_client = MagicMock()
            client.llm_client.chat.completions.create.return_value.choices[0].message.content = '{"answer": 4}'
            client._cache = None
            
            with patch('builtins.print'):
                client._call_llm("my email is test@test.com")
            
            # Verify detect_and_mask was called
            client._pii_detector.detect_and_mask.assert_called_with("my email is test@test.com")


if __name__ == '__main__':
    unittest.main()
