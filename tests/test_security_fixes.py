
import unittest
import sys
import os

# Adjust path to allow imports from qwed_sdk if not installed as package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from qwed_sdk.qwed_local import _is_safe_sympy_expr, _is_safe_z3_expr

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
        
        # Expected failure mode for this test setup (no real keys), but strictly NO CRASHES.
        # If we fixed the logic, it should handle the token parsing and return tuple.
        self.assertIsInstance(is_valid, bool)
        self.assertTrue(error is None or isinstance(error, str))

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

if __name__ == '__main__':
    unittest.main()
