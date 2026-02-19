
import unittest
import sys
import os

# Adjust path to allow imports from qwed_sdk if not installed as package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from qwed_sdk.qwed_local import _is_safe_sympy_expr, _is_safe_z3_expr, QWEDLocal
from unittest.mock import MagicMock, patch

def _has_attestation_deps():
    try:
        from src.qwed_new.core.attestation import AttestationService, HAS_CRYPTO
        return HAS_CRYPTO
    except ImportError:
        return False

class TestSecurityFixes(unittest.TestCase):
    
    def test_base64_padding_correctness(self):
        """Test that our new padding logic works for all modulo cases."""
        # Case 0: Needs 0 padding
        s = "aaaa" # len 4
        padding = '=' * (-len(s) % 4)
        self.assertEqual(len(padding), 0)
        
        # Case 1: Needs 3 padding? No, base64 blocks are 4 chars.
        # Valid base64 strings length % 4 is 0, 2, or 3. (1 is impossible)
        
        # Payload '{"a":1}' -> eyJhIjoxfQ (len 10) -> 10 % 4 = 2. Needs 2 '='.
        s = "eyJhIjoxfQ"
        padding = '=' * (-len(s) % 4)
        # -10 % 4 = 2 (because -10 = -3*4 + 2)
        self.assertEqual(len(padding), 2)
        self.assertEqual(padding, "==")
        
        # Payload '{"sub":"1"}' -> eyJzdWIiOiIxIn0 (len 15) -> 15 % 4 = 3. Needs 1 '='.
        s = "eyJzdWIiOiIxIn0" 
        padding = '=' * (-len(s) % 4)
        # -15 % 4 = 1
        self.assertEqual(len(padding), 1)
        self.assertEqual(padding, "=")


    @unittest.skipUnless(_has_attestation_deps(), "Attestation dependencies not installed")
    def test_attestation_integration(self):
        """Test the full attestation creation and verification flow."""
        from src.qwed_new.core.attestation import AttestationService, VerificationResult
        
        # Use a dummy DID for testing self-issued check
        # Inject deterministic key suffix to avoid datetime usage in __init__
        service = AttestationService(issuer_did="did:web:qwed.ai", key_suffix="test")
        
        result = VerificationResult(
            status="VERIFIED",
            verified=True, 
            engine="qwed-test-engine",
            confidence=1.0
        )
        
        # 1. Create Attestation
        attestation = service.create_attestation(result, "What is 2+2?")
        self.assertIsNotNone(attestation.jwt_token)
        
        # 2. Verify Attestation
        # The verify_attestation method might fail if public keys aren't set up,
        # but we want to ensure it doesn't crash with AttributeError (the fix we made).
        # We catch the "Untrusted issuer" or "External issuer key resolution" error, which is expected.
        is_valid, _claims, error = service.verify_attestation(attestation.jwt_token)
        
        # Self-issued attestation should verify successfully
        self.assertTrue(is_valid, f"Self-issued attestation should be valid, got error: {error}")
        self.assertIsNone(error)
        self.assertIsNotNone(_claims)

    def test_safe_sympy_validator(self):
        """Test the AST validator for SymPy expressions using REAL implementation."""
        
        # Safe expressions
        self.assertTrue(_is_safe_sympy_expr("sympy.diff(x**2, x)"))
        self.assertTrue(_is_safe_sympy_expr("sympy.sin(x) + 1"))
        self.assertTrue(_is_safe_sympy_expr("x + 2"))
        
        # Unsafe expressions
        self.assertFalse(_is_safe_sympy_expr("import os"))
        self.assertFalse(_is_safe_sympy_expr("__import__('os')"))
        self.assertFalse(_is_safe_sympy_expr("eval('print(1)')"))
        self.assertFalse(_is_safe_sympy_expr("exec('print(1)')"))
        self.assertFalse(_is_safe_sympy_expr("open('/etc/passwd')"))
        
        # Adversarial cases (bypass attempts)
        self.assertFalse(_is_safe_sympy_expr("sympy.sympify('__import__(\"os\")')"))
        self.assertFalse(_is_safe_sympy_expr("sympy.os.system('id')"))
        
        # String args to whitelisted functions — sympify is called internally
        self.assertFalse(_is_safe_sympy_expr("sympy.simplify('__import__(\"os\")')"))
        self.assertFalse(_is_safe_sympy_expr("sympy.solve('__import__(\"os\")')"))

    def test_safe_z3_validator(self):
        """Test the AST validator for Z3 expressions."""
        # Safe expressions
        self.assertTrue(_is_safe_z3_expr("And(Bool('p'), Bool('q'))"))
        self.assertTrue(_is_safe_z3_expr("Not(Bool('p'))"))
        self.assertTrue(_is_safe_z3_expr("Implies(Bool('a'), Bool('b'))"))
        self.assertTrue(_is_safe_z3_expr("True"))
        self.assertTrue(_is_safe_z3_expr("False"))

        # Unsafe expressions
        self.assertFalse(_is_safe_z3_expr("__import__('os')"))
        self.assertFalse(_is_safe_z3_expr("eval('1+1')"))
        self.assertFalse(_is_safe_z3_expr("os.system('id')"))
        self.assertFalse(_is_safe_z3_expr("Int('x') + Int('y')")) # Int not in allowed_names

    def test_log_sanitization(self):
        """Test that newlines are stripped from log messages."""
        from src.qwed_new.core.secure_code_executor import _sanitize_log_msg
        
        raw_error = "Error occurred\nwith malicious\rnewline injection"
        sanitized = _sanitize_log_msg(raw_error)
        
        self.assertNotIn('\n', sanitized)
        self.assertNotIn('\r', sanitized)
        self.assertEqual(sanitized, "Error occurred with malicious newline injection")

    def test_secure_executor_logging_fix(self):
        """Test that logging exception in SecureCodeExecutor does not duplicate message."""
        from src.qwed_new.core.secure_code_executor import SecureCodeExecutor
        import tempfile
        
        # Mock logger
        with patch('src.qwed_new.core.secure_code_executor.logger') as mock_logger:
            executor = SecureCodeExecutor()
            # Force docker_available to True so we don't return early
            executor.docker_available = True
            
            # Mock tempfile.TemporaryDirectory to raise OSError
            with patch('tempfile.TemporaryDirectory', side_effect=OSError("Permission denied")):
                # execute() -> tries to create temp dir -> raises OSError
                success, error, _ = executor.execute("print('hi')", {})
                
                self.assertFalse(success)
                self.assertIn("Setup error", error)
                # Verify logger.exception was called with static message
                mock_logger.exception.assert_called_with("Failed to create temporary directory")



class TestQWEDLocalExecution(unittest.TestCase):
    """Test the actual execution flow of QWEDLocal, including eval() safety."""
    
    def setUp(self):
        self.client = QWEDLocal(base_url="http://mock-url", model="mock-model")
        # Mock the LLM call to return safe expressions
        self.client._call_llm = MagicMock()

    def test_verify_math_safe_eval(self):
        """Test that verify_math correctly evaluates safe expressions."""
        # 1. Mock LLM to return "4" then "2 + 2"
        # Note: We cannot use sympy.simplify("2+2") because string args are now banned!
        self.client._call_llm.side_effect = ["4", "2 + 2"]
        
        # 2. Call verify_math
        result = self.client.verify_math("What is 2+2?")
        
        # 3. Assertions
        self.assertTrue(result.verified)
        self.assertEqual(result.value, "4")
        self.assertIn("2 + 2", result.evidence["sympy_expr"])

    def test_verify_math_unsafe_eval(self):
        """Test that verify_math blocks unsafe expressions before eval."""
        # 1. Mock LLM to return "import os"
        self.client._call_llm.side_effect = ["pwned", "import os"]
        
        # 2. Call verify_math
        # It should catch ValueError from _is_safe_sympy_expr and return verified=False
        result = self.client.verify_math("Hack me")
        
        # 3. Assertions
        self.assertFalse(result.verified)
        # "import os" is a statement — triggers InvalidExpressionSyntaxError.
        # verify_math catches it and sets result.error with the prefix below.
        self.assertIsNotNone(result.error)
        self.assertIn("SymPy verification failed", result.error)

    def test_verify_logic_safe_eval(self):
        """Test that verify_logic correctly evaluates safe Z3 expressions."""
        # Check if Z3 is installed
        if not self.client.has_z3:
            self.skipTest("Z3 not installed")
            
        # 1. Mock LLM to return "TRUE" then "And(True, True)"
        # Note: We use capitalized True/False because strict Z3 validator might require specific form,
        # but here we rely on what _is_safe_z3_expr allows.
        # Actually, _is_safe_z3_expr allows And, Or, Not.
        # Let's use a valid Z3 expression that works with the validator.
        self.client._call_llm.side_effect = ["TRUE", "And(True, True)"] # safe Z3 expr
        
        # 2. Call verify_logic
        result = self.client.verify_logic("Is true true?")
        
        # 3. Assertions
        self.assertTrue(result.verified)
        self.assertEqual(result.value, "TRUE")


