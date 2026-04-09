import unittest
import os
import importlib
import sys
from uuid import uuid4
from unittest.mock import patch
from fastapi.testclient import TestClient


def _build_test_env():
    return {
        "API_KEY_SECRET": f"unit-test-api-{uuid4().hex}",
        "QWED_JWT_SECRET_KEY": f"unit-test-jwt-{uuid4().hex}",
        "QWED_CORS_ORIGINS": "http://localhost:3000",
    }


TEST_ENV = _build_test_env()

# IMPORTANT: we must mock environment variables before importing modules that fail immediately
@patch.dict(os.environ, TEST_ENV)
class TestCoverageGap(unittest.TestCase):
    
    def test_auth_security(self):
        from src.qwed_new.auth import security
        # Test hash/verify password
        test_credential = os.environ.get("TEST_AUTH_CREDENTIAL", "unit_test_credential")
        hashed = security.hash_password(test_credential)
        self.assertTrue(security.verify_password(test_credential, hashed))
        self.assertFalse(security.verify_password("wrong", hashed))
        
        # Test token creation/decode
        token = security.create_access_token({"sub": "user1"})
        decoded = security.decode_access_token(token)
        self.assertEqual(decoded["sub"], "user1")
        
        # Invalid token
        self.assertIsNone(security.decode_access_token("invalid"))
        
        # With explicit timedelta
        from datetime import timedelta
        token2 = security.create_access_token({"sub": "user2"}, expires_delta=timedelta(minutes=10))
        self.assertEqual(security.decode_access_token(token2)["sub"], "user2")

        # Mask api key
        self.assertEqual(security.mask_api_key("short"), "****")
        self.assertEqual(security.mask_api_key("qwed_live_verylongkeyjusttotestmasking"), "qwed_live_****king")
        
        # Generate API key
        raw_key, hashed_key = security.generate_api_key()
        self.assertTrue(raw_key.startswith("qwed_live_"))
        self.assertEqual(security.hash_api_key(raw_key), hashed_key)

    def test_rate_limiter(self):
        from src.qwed_new.core.rate_limiter import RateLimiter
        import time
        
        # Override global limit using patch
        with patch.dict(os.environ, {"QWED_RATE_LIMIT_GLOBAL": "2"}):
            limiter = RateLimiter()
            
            # Test global limit
            self.assertTrue(limiter.check_global_limit())
            self.assertTrue(limiter.check_global_limit())
            self.assertFalse(limiter.check_global_limit())
        
        # Reset time
        reset_time = limiter.get_reset_time()
        self.assertGreaterEqual(reset_time, 0)
        
        # API key limits (enforcement path)
        with patch.dict(os.environ, {"QWED_RATE_LIMIT_PER_KEY": "1", "QWED_RATE_LIMIT_GLOBAL": "10"}):
            limiter = RateLimiter()
            api_key = "test_key"
            self.assertTrue(limiter.check_api_key_limit(api_key))
            self.assertFalse(limiter.check_api_key_limit(api_key))
            reset_time_api = limiter.get_reset_time(api_key)
            self.assertGreaterEqual(reset_time_api, 0)

    def test_config_missing_api_key(self):
        config_module_name = "src.qwed_new.config"
        cached_module = sys.modules.pop(config_module_name, None)

        try:
            with patch.dict(os.environ, {"QWED_CORS_ORIGINS": "http://localhost:3000"}):
                os.environ.pop("API_KEY_SECRET", None)
                with patch("dotenv.load_dotenv", return_value=False):
                    with self.assertRaises(RuntimeError) as cm:
                        importlib.import_module(config_module_name)
            self.assertIn("API_KEY_SECRET", str(cm.exception))
        finally:
            sys.modules.pop(config_module_name, None)
            if cached_module is not None:
                sys.modules[config_module_name] = cached_module

    def test_main_enforce_integrity(self):
        from src.qwed_new.api.main import _enforce_environment_integrity
        # Test bypass
        with patch.dict(os.environ, {"QWED_SKIP_ENV_INTEGRITY_CHECK": "true"}):
            try:
                _enforce_environment_integrity()
            except Exception as e:
                self.fail(f"Bypass unexpectedly raised {e}")
                
        # Test failure
        from qwed_sdk.guards.environment_guard import StartupHookGuard
        with patch.dict(os.environ, {"QWED_SKIP_ENV_INTEGRITY_CHECK": "false"}):
            with patch.object(StartupHookGuard, 'verify_environment_integrity', return_value={"verified": False, "risk": "critical"}):
                with self.assertRaises(RuntimeError) as cm:
                    _enforce_environment_integrity()
                self.assertIn("verification failed", str(cm.exception))

    def test_main_import_requires_cors_origins(self):
        main_module_name = "src.qwed_new.api.main"
        cached_module = sys.modules.pop(main_module_name, None)

        try:
            with patch.dict(os.environ, {"API_KEY_SECRET": TEST_ENV["API_KEY_SECRET"]}):
                os.environ.pop("QWED_CORS_ORIGINS", None)
                with self.assertRaises(RuntimeError) as cm:
                    importlib.import_module(main_module_name)
            self.assertIn("QWED_CORS_ORIGINS", str(cm.exception))
        finally:
            sys.modules.pop(main_module_name, None)
            if cached_module is not None:
                sys.modules[main_module_name] = cached_module

    def test_config_and_main(self):
        from src.qwed_new.config import ensure_jwt_secret
        from src.qwed_new.api.main import app
        from src.qwed_new.api import main as main_module
        
        # Test jwt secret generation logic
        with patch.dict(os.environ, clear=True):
            s1 = ensure_jwt_secret()
            self.assertGreater(len(s1), 0)
            self.assertEqual(os.environ["QWED_JWT_SECRET_KEY"], s1)
            # Second call should return existing
            s2 = ensure_jwt_secret()
            self.assertEqual(s1, s2)
        
        # Testing main.py app initialized correctly
        # We need to make sure auth passes Rate limit
        from fastapi import HTTPException
        from src.qwed_new.core.rate_limiter import check_rate_limit, rate_limiter
        
        # Reset limiter explicitly
        with rate_limiter._lock:
            orig_global_limit = rate_limiter.GLOBAL_LIMIT
            orig_per_key_limit = rate_limiter.PER_KEY_LIMIT
            orig_global_requests = list(rate_limiter.global_requests)
            orig_api_key_requests = {k: list(v) for k, v in rate_limiter.api_key_requests.items()}
            rate_limiter.api_key_requests.clear()
            rate_limiter.global_requests.clear()

        try:
            rate_limiter.GLOBAL_LIMIT = 0
            with self.assertRaises(HTTPException):
                check_rate_limit()
                
            rate_limiter.GLOBAL_LIMIT = 100
            rate_limiter.PER_KEY_LIMIT = 0
            with self.assertRaises(HTTPException):
                check_rate_limit(api_key="test")
            
            rate_limiter.PER_KEY_LIMIT = 100
            check_rate_limit(api_key="good")
        finally:
            with rate_limiter._lock:
                rate_limiter.GLOBAL_LIMIT = orig_global_limit
                rate_limiter.PER_KEY_LIMIT = orig_per_key_limit
                rate_limiter.global_requests = orig_global_requests
                rate_limiter.api_key_requests.clear()
                rate_limiter.api_key_requests.update(orig_api_key_requests)
        self.assertIsNotNone(app)

        client = TestClient(app)
        root_response = client.get("/")
        self.assertEqual(root_response.status_code, 200)
        self.assertEqual(root_response.json()["version"], main_module.APP_VERSION)

        health_response = client.get("/health")
        self.assertEqual(health_response.status_code, 200)
        self.assertEqual(health_response.json()["version"], main_module.APP_VERSION)
        self.assertTrue(health_response.json()["timestamp"])
