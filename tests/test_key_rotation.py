"""Tests for key_rotation.py — Key lifecycle management (Issue #224)."""

from unittest.mock import MagicMock, patch

from qwed_new.core.key_rotation import KeyManager


class TestKeyManager:
    """KeyManager.create_key must store the HMAC hash from the centralized
    generator (issue #366), never a raw token or a re-derived local hash."""

    @patch("qwed_new.core.key_rotation.Session")
    @patch("qwed_new.core.key_rotation.generate_api_key")
    def test_create_key_uses_centralized_generator(self, mock_gen, mock_session):
        mock_session.return_value.__enter__.return_value = MagicMock()
        # The centralized generator returns (plaintext, hmac_hash); the manager
        # must persist the hash it is handed rather than hashing on its own.
        mock_gen.return_value = ("qwed_live_" + "a" * 36, "ab" * 32)

        key_manager = KeyManager()
        api_key, raw = key_manager.create_key(organization_id=1)

        mock_gen.assert_called_once()
        assert raw.startswith("qwed_live_")
        assert api_key.key_hash == "ab" * 32
        assert api_key.key_preview  # masked preview is populated
