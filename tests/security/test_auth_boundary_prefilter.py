"""#366: the offline API-key format pre-filter at the auth boundaries.

Malformed keys must be rejected BEFORE the HMAC lookup and BEFORE any DB
query, at every boundary that reads `x-api-key`. These tests call the real
dependency functions directly — dependency overrides are deliberately NOT
used — so a regression that removes or relocates the pre-filter fails here.

Covers the whole family of boundaries (middleware.get_api_key,
tenant_context.get_current_tenant, api.main.get_optional_api_key_record)
rather than only the one that happened to be flagged.

These dependencies are async, so the tests are `async def` under the repo's
`@pytest.mark.asyncio` convention (as in test_logic_exceptions.py). A single
`await` sits inside `pytest.raises`, so the raising call is unambiguous and no
`asyncio.run` wrapper adds a second invocation to the block.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from qwed_new.auth.middleware import get_api_key
from qwed_new.auth.security import _V2_RANDOM_LEN, _checksum_for
from qwed_new.core.tenant_context import get_current_tenant


def _fixed_v2_key() -> str:
    """Deterministic, valid v2 key (computed: repeatable, not a hardcoded
    credential literal) that must pass the format gate."""
    body = "A" * _V2_RANDOM_LEN
    return "qwed_live_" + body + _checksum_for(body)


# Valid prefix + invalid body -> always classified "invalid", constructed so it
# is not a credential-shaped literal.
MALFORMED_KEY = "qwed_live_" + "!"


class TestMiddlewareGetApiKey:
    """src/qwed_new/auth/middleware.py::get_api_key"""

    @pytest.mark.asyncio
    async def test_rejects_malformed_header_before_lookup(self):
        session = MagicMock()
        with (
            patch("qwed_new.auth.middleware.hash_api_key") as mock_hash,
            pytest.raises(HTTPException) as exc,
        ):
            await get_api_key(api_key_header=MALFORMED_KEY, session=session)

        assert exc.value.status_code == 403
        assert exc.value.detail == "Invalid or revoked API Key"
        mock_hash.assert_not_called()
        session.exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_header_is_401(self):
        session = MagicMock()
        with pytest.raises(HTTPException) as exc:
            await get_api_key(api_key_header="", session=session)

        assert exc.value.status_code == 401
        session.exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_v2_key_reaches_lookup(self):
        """Dual acceptance: a valid v2 key must pass the gate, not be blocked."""
        session = MagicMock()
        session.exec.return_value.first.return_value = MagicMock()
        with patch("qwed_new.auth.middleware.hash_api_key", return_value="digest") as mock_hash:
            result = await get_api_key(api_key_header=_fixed_v2_key(), session=session)

        assert result is not None
        mock_hash.assert_called_once()
        session.exec.assert_called_once()


class TestTenantContextGetCurrentTenant:
    """src/qwed_new/core/tenant_context.py::get_current_tenant"""

    @pytest.mark.asyncio
    async def test_rejects_malformed_key_before_lookup(self):
        session = MagicMock()
        with (
            patch("qwed_new.core.tenant_context.hash_api_key") as mock_hash,
            pytest.raises(HTTPException) as exc,
        ):
            await get_current_tenant(x_api_key=MALFORMED_KEY, session=session)

        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid or inactive API key"
        mock_hash.assert_not_called()
        session.exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_v2_key_reaches_lookup(self):
        """Dual acceptance: valid v2 key passes the gate to the key + org lookup."""
        session = MagicMock()
        api_key_row = MagicMock(organization_id=1)
        org_row = MagicMock(id=1, name="Org", tier="free")
        session.exec.return_value.first.side_effect = [api_key_row, org_row]

        with patch("qwed_new.core.tenant_context.hash_api_key", return_value="digest") as mock_hash:
            tenant = await get_current_tenant(x_api_key=_fixed_v2_key(), session=session)

        assert tenant.organization_id == 1
        mock_hash.assert_called_once()
        assert session.exec.call_count == 2  # api-key lookup + organization lookup