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
from high-confidence production-secret matching. Because the registered
production patterns match only `qwed_live_`, test keys are never reported
to QWED; the revocation sink itself applies no separate prefix filter.

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

Boundaries are charset complements, not word boundaries (`\b…\b`,
published as `anchored_pattern` in the machine-readable spec). A trailing
`\b` is wrong here in both directions: it misses a v1 body ending in `-`
followed by whitespace or punctuation (both non-word characters, so no
boundary exists), and the same gap applies anywhere a body edge meets a
delimiter outside `\w`. The lookarounds exclude the body alphabet of each version
(`(?<![A-Za-z0-9_-])…(?![A-Za-z0-9_-])` for v1,
`(?<![A-Za-z0-9])…(?![A-Za-z0-9])` for v2, per
`anchored_pattern` in the machine-readable spec) and match exactly when no
body-alphabet character continues on either side.
Scanners on engines without lookarounds (e.g. RE2) should use an explicit
delimiter class instead, with the key wrapped in capture group 1:

```text
# v2 (current)
(?:^|[^A-Za-z0-9])(qwed_live_[A-Za-z0-9]{36})(?:[^A-Za-z0-9]|$)

# v1 (legacy)
(?:^|[^A-Za-z0-9_-])(qwed_live_[A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)
```

Always read the match's group 1 as the token, never the whole match: the
surrounding `(?:^|[^…])` and `(?:[^…]|$)` parts consume characters that
are not part of the key, so the whole match carries one or two extra
characters that break checksum validation and the revocation lookup. A
global scan must also resume after the end of group 1, not the end of the
whole match — a match that consumes the single delimiter separating two
back-to-back keys would otherwise make the scanner miss the second one.

Precision note: `secrets.token_urlsafe(32)` output always ends in one of
`A`, `Q`, `g`, `w` (the 43rd base64 character carries 2 zero padding bits),
so generator-issued v1 keys never end in `-` — but the pattern still accepts
it, and scanner guidance must handle dash endings correctly regardless of
what the generator emits.

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
  provisioned. `spec/api-key-test-vectors.json` holds synthetic,
  never-issued keys that can serve as samples.
- `qwed_test_` exclusion: confirmed — no registered production pattern
  matches the test prefix, so it never alerts. The revocation sink applies
  no separate prefix filter; it simply never receives test keys.
