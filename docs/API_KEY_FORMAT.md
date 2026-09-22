# QWED API-Key Format Specification

Canonical patterns for QWED API keys, for scanner authors, leak detectors,
integrators, and SDK implementers. Machine-readable copy:
[`spec/api-key-format.json`](../spec/api-key-format.json). Test vectors:
[`spec/api-key-test-vectors.json`](../spec/api-key-test-vectors.json)
(synthetic, non-functional — see the notice at the top of that file).

## Versions

### v2 (current, checksummed)

Pattern: `qwed_live_[A-Za-z0-9]{36}`

The 36 characters after the prefix are strictly alphanumeric (Base62 —
digits, uppercase, lowercase; no `-`, no `_`, no padding):

- First 30: random Base62 (~178.6 bits of entropy).
- Last 6: checksum authenticating the shape (never authorization — access
  still requires the server-side HMAC lookup).

### v1 (legacy, still accepted)

Pattern: `qwed_live_[A-Za-z0-9_-]{43}`

The body is exactly 43 base64url characters (32 random bytes, padding
stripped; 256 bits of entropy). Existing v1 keys keep working and are never
force-rotated. No checksum — enforce the exact shape only.

### Test prefix (never production)

`qwed_test_` marks non-production keys. Scanners must exclude this prefix
from high-confidence production-secret matching; the revocation pipeline
never acts on it.

## Checksum algorithm (v2)

CRC32 (IEEE, as in `zlib`) over the ASCII encoding of the first 30 body
characters, Base62-encoded with leading-zero padding to a fixed width of 6,
using the alphabet
`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`.

To validate offline: split the body into the first 30 characters and the
trailing 6, recompute, and accept only on exact match. This collapses random
false-positive matches to ~2^-32 while staying pure math (no database).

Masked previews in documentation and examples show the prefix, asterisks,
and only the last 4 characters — never a full body.

## Scanning guidance

Anchor both patterns with word boundaries (`\b…\b`, published as
`anchored_pattern` in the machine-readable spec). Unanchored, a valid
shape matches as a prefix inside a longer token, and scanners report
fragments of larger credentials as complete keys.

## Validator

`validate_api_key_format()` in `src/qwed_new/auth/security.py` classifies a
key as `"v2"`, `"v1"`, or `"invalid"`; `is_valid_key_checksum()` is the pure
offline v2 shape check. `tests/security/test_api_key_vectors.py` runs every
vector in `spec/api-key-test-vectors.json` against the validator.

## Ops checklist (external scanning/notification consumers)

- Notification endpoint: fixed path `/webhooks/secret-scanning` on the
  public host. Public host: **TBD** (left blank on the partnership form,
  which permits it).
- Registered pattern names: `QWED_LIVE_API_KEY` (`qwed_live_api_key`) and
  `QWED_LIVE_API_KEY_V1` (`qwed_live_api_key_v1`).
- Sample credentials for partners: **TBD** — confirm how samples are
  provisioned.
- `qwed_test_` exclusion: confirmed — test prefix never alerts, never acts.
