"""Tests for key_rotation.py — Key lifecycle management (Issue #224)."""

from unittest.mock import patch, MagicMock
from qwed_new.core.key_rotation import KeyManager


class TestKeyManager:
    """KeyManager.create_key must use hash_api_key (PBKDF2, not raw SHA-256)."""

    @patch("qwed_new.core.key_rotation.Session")
    @patch("qwed_new.core.key_rotation.hash_api_key")
    def test_create_key_uses_hash_api_key(self, mock_hash, mock_session):
        mock_session.return_value.__enter__.return_value = MagicMock()
        mock_hash.return_value = "ab" * 32  # 64-char hex

        key_manager = KeyManager()
        api_key, raw = key_manager.create_key(organization_id=1)

        mock_hash.assert_called_once()
        assert mock_hash.call_args[0][0].startswith("qwed_live_")
        assert api_key.key_hash == "ab" * 32
