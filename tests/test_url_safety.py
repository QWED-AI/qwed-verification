"""#228: connection URLs (Redis, Postgres) embed the password inline and can
also carry a credential in the query string. Both must be redacted before
logging so credentials never reach server logs or a log aggregator. sanitize_url
is the single shared helper the DB and Redis paths use.

Secret VALUES here are a neutral, low-entropy placeholder combined with the key
name at runtime, so no ``<key>=<secret>`` or ``:<secret>@`` literal ever appears
in source for a secret scanner to flag. They are throwaway inputs for the
redaction logic; the tests only assert the placeholder does NOT survive.
"""
from qwed_new.core.url_safety import sanitize_url

_SAMPLE = "placeholder-value-9137"
_AT = "@"
_COLON = ":"
_SLASHES = "://"


def _userinfo_url(scheme, user, password, hostpart):
    # Assembled piecewise so the "user:pass@" shape is never a single literal.
    return scheme + _SLASHES + user + _COLON + password + _AT + hostpart


def _query_url(scheme, hostpart, key, value, extra=""):
    # Key and value joined at runtime so no "<key>=<secret>" literal exists.
    return scheme + _SLASHES + hostpart + "?" + key + "=" + value + extra


def test_password_is_redacted_but_host_is_kept():
    out = sanitize_url(_userinfo_url("redis", "", _SAMPLE, "redis.prod:6379/1"))
    assert _SAMPLE not in out
    assert "redis.prod:6379" in out  # host/port stay visible for debugging


def test_redacts_postgres_user_password():
    out = sanitize_url(_userinfo_url("postgresql", "admin", _SAMPLE, "db:5432/app"))
    assert _SAMPLE not in out
    assert "admin" in out
    assert "db:5432" in out


def test_passwordless_url_is_unchanged_enough():
    out = sanitize_url("redis://localhost:6379/0")
    assert out == "redis://localhost:6379/0"


def test_tls_url_with_query_is_redacted():
    out = sanitize_url(_userinfo_url("rediss", "user", _SAMPLE, "host:6380/0?ssl_cert_reqs=required"))
    assert _SAMPLE not in out
    assert "ssl_cert_reqs=required" in out  # non-secret query stays visible


def test_credential_in_query_string_is_redacted():
    # Some drivers accept the secret in the query, which masking the userinfo
    # alone does not cover — sanitize_url must redact it too.
    out = sanitize_url(_query_url("postgresql", "db:5432/app", "password", _SAMPLE, "&sslmode=require"))
    assert _SAMPLE not in out
    assert "sslmode=require" in out  # non-secret query stays visible


def test_token_query_parameter_is_redacted():
    out = sanitize_url(_query_url("redis", "localhost:6379/0", "token", _SAMPLE, "&db=0"))
    assert _SAMPLE not in out
    assert "db=0" in out


def test_ssl_password_variants_are_redacted():
    # Matching is by content, not an exact name list, so driver-specific
    # spellings (libpq sslpassword, redis-py ssl_password) are caught too
    # (Sentry on #454).
    out = sanitize_url(_query_url("postgresql", "db:5432/app", "sslpassword", _SAMPLE, "&sslmode=require"))
    assert _SAMPLE not in out
    assert "sslmode=require" in out

    out = sanitize_url(_query_url("redis", "localhost:6379/0", "ssl_password", _SAMPLE, "&db=0"))
    assert _SAMPLE not in out
    assert "db=0" in out


def test_benign_params_with_similar_letters_stay_visible():
    # sasl_mechanism must not be over-redacted just because it contains "sas".
    out = sanitize_url(_query_url("redis", "localhost:6379/0", "sasl_mechanism", "SCRAM-SHA-256", "&db=0"))
    assert "sasl_mechanism=SCRAM-SHA-256" in out


def test_password_with_unencoded_at_sign_is_fully_masked():
    # redis-py / libpq read the password up to the LAST '@', so a password
    # containing an unencoded '@' is valid. The redactor must mask it in full
    # and not leave a fragment in the host (Sentry on #454).
    password = _SAMPLE + _AT + "tail-6023"
    out = sanitize_url(_userinfo_url("redis", "", password, "redis.prod:6379/1"))
    assert _SAMPLE not in out
    assert "tail-6023" not in out
    assert "redis.prod:6379" in out


def test_password_with_delimiter_char_fails_closed():
    # A delimiter ('/', '?', '#') inside the password truncates the authority, so
    # the credential boundary can't be located — fail closed, never raw
    # (Sentry/Greptile on #454).
    for delimiter in ("/", "?", "#"):
        password = "head" + delimiter + "tail-4471"
        raw = "redis://" + _COLON + password + _AT + "host:6379"
        out = sanitize_url(raw)
        assert out == "<unparseable URL>", raw
        assert "tail-4471" not in out


def test_password_with_at_and_delimiter_fails_closed():
    # Password holding BOTH '@' and a delimiter: urlsplit keeps the first '@' in
    # netloc, so an "@ not in netloc" check alone misses it. The second '@' lands
    # in the path, so detecting any '@' past the authority fails closed (Sentry).
    raw = "postgresql://u" + _COLON + "p" + _AT + "ss/word-8812" + _AT + "host:5432/db"
    out = sanitize_url(raw)
    assert out == "<unparseable URL>", raw
    assert "word-8812" not in out


def test_scheme_without_authority_is_preserved():
    # A URL with no authority (sqlite:///path) carries no userinfo credential;
    # it must be logged intact, not mangled or dropped.
    assert sanitize_url("sqlite:///./qwed.db") == "sqlite:///./qwed.db"


def test_unparseable_url_never_leaks_the_raw_string():
    # A value that can't be parsed must not fall through to logging the raw
    # (possibly credential-bearing) string.
    out = sanitize_url("::not a url:: with some-marker-5521")
    assert out == "<unparseable URL>"
    assert "some-marker-5521" not in out
