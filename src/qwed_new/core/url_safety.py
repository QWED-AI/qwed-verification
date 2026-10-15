"""Shared helper for logging connection URLs without leaking credentials.

Connection URLs for Redis, Postgres and friends embed the password inline
(``redis://:pw@host``, ``postgresql://user:pw@host``) and can also carry a
credential in the query string (``?password=...``, ``?token=...``). Logging the
raw string puts that secret into server logs and every downstream log-aggregation
system (#228). Route every connection URL through :func:`sanitize_url` before it
reaches a log line.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_UNPARSEABLE = "<unparseable URL>"
_REDACTED = "***"

#: A query parameter carries a credential when its value must be masked. Some
#: drivers accept the secret in the query string rather than the userinfo
#: (libpq ``sslpassword``, redis-py ``ssl_password``, Azure SAS ``sig``), and
#: masking the userinfo alone does not cover those. Matching is by content, not
#: an exact name list, so spelling/prefix variants (sslpassword, ssl_password,
#: access_token, …) can't slip past a hardcoded set (Sentry on #454).
#:
#: Long, unambiguous tokens match anywhere in the (separator-stripped) key name.
_SENSITIVE_QUERY_SUBSTRINGS = (
    "password", "passwd", "passphrase",
    "secret", "token", "credential", "apikey",
)
#: Short/ambiguous names match only exactly, so benign params that merely
#: contain these letters (sasl_mechanism, sslkey file paths, …) stay visible.
_SENSITIVE_QUERY_EXACT = frozenset(
    {"pwd", "pass", "key", "auth", "authorization", "sig", "sas"}
)


def _is_sensitive_query_key(name: str) -> bool:
    normalized = name.lower().replace("_", "").replace("-", "")
    if normalized in _SENSITIVE_QUERY_EXACT:
        return True
    return any(token in normalized for token in _SENSITIVE_QUERY_SUBSTRINGS)


def sanitize_url(url: str) -> str:
    """Render a connection URL with every credential redacted, for safe logging.

    Keeps the scheme, host, port, path and non-secret query values visible (they
    are useful for debugging) and redacts the userinfo password plus the values
    of any credential-bearing query parameter.

    The userinfo is split from the host on the LAST ``@`` (via ``rpartition``),
    matching how redis-py and libpq read passwords, so a password containing an
    unencoded ``@`` is masked in full rather than leaving a fragment in the host
    (SQLAlchemy's make_url splits on the first ``@`` and leaked such a fragment —
    Sentry on #454). If the value has no scheme, or cannot be parsed, a constant
    placeholder is returned rather than the raw string, so logging never raises
    and never falls back to emitting the secret.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return _UNPARSEABLE

    # A connection URL always has a scheme; without one there is nothing we can
    # confidently redact, so refuse to echo the raw value.
    if not parts.scheme:
        return _UNPARSEABLE

    netloc = parts.netloc
    # A connection URL's userinfo '@' always sits in the authority. An '@' left
    # in the path, query or fragment means a delimiter ('/', '?', '#') inside the
    # password truncated the authority early (urlsplit ends netloc at the first
    # such char) — including when the password holds BOTH '@' and a delimiter, in
    # which case netloc keeps the first '@' and the rest spills past it. The
    # credential boundary then can't be located, so fail closed rather than risk
    # logging a password fragment (Sentry/Greptile on #454).
    if "@" in parts.path or "@" in parts.query or "@" in parts.fragment:
        return _UNPARSEABLE

    userinfo, at, hostport = netloc.rpartition("@")
    redacted = False
    if at and ":" in userinfo:
        # Split userinfo on the first ':' so everything after it (the password,
        # including any ':' or '@' it contains) is redacted.
        user, _, _password = userinfo.partition(":")
        netloc = f"{user}:{_REDACTED}@{hostport}"
        redacted = True

    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        if any(_is_sensitive_query_key(key) for key, _ in pairs):
            query = urlencode(
                [
                    (key, _REDACTED if _is_sensitive_query_key(key) else value)
                    for key, value in pairs
                ]
            )
            redacted = True

    # Only rebuild when something was actually redacted. urlunsplit drops the
    # authority marker for a URL with an empty netloc (sqlite:///path), so
    # returning the original string keeps such URLs — which carry no userinfo
    # credential anyway — intact.
    if not redacted:
        return url
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
