"""#450 review: check_expiring_keys subtracts key.expires_at from a tz-aware
now(). Older SQLModel/SQLite can read expires_at back naive, so the value must be
normalised to UTC first or the subtraction raises TypeError and the expiry
warning loop stops."""
from datetime import datetime, timedelta, timezone

from qwed_new.core.key_rotation import _as_utc


def test_naive_timestamp_is_normalised_to_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)  # no tzinfo, as an old DB row reads back
    normalised = _as_utc(naive)
    assert normalised.tzinfo is timezone.utc
    assert normalised == naive.replace(tzinfo=timezone.utc)


def test_aware_timestamp_is_unchanged():
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert _as_utc(aware) is aware


def test_subtracting_a_naive_expiry_from_now_does_not_raise():
    naive_expiry = datetime.utcnow() + timedelta(days=3)  # naive, like an old row
    # This is exactly the days_remaining computation in check_expiring_keys.
    days = (_as_utc(naive_expiry) - datetime.now(timezone.utc)).days
    assert days in (2, 3)  # ~3 days out, allowing for the clock between the two calls
