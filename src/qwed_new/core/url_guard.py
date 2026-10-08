"""SSRF guard for operator-supplied fetch URLs (issue #423).

Both call sites are operator-controlled today (local CLI provider import,
operator-configured Slack webhook), so this is defense-in-depth: cheap
checks that stay correct if either path is ever exposed to untrusted input.

Design notes (read before weakening anything here):
- No DNS resolution, ever. Resolving hostnames would make offline and
  mocked use hang or fail, and cannot stop DNS-rebinding anyway. Only
  *literal* IP hosts are inspected; DNS names pass through (documented
  residual — see below).
- Redirect targets are re-validated per hop, which closes the classic
  "clean initial URL, dirty redirect" bypass for literal-IP targets.
- Residual risks, accepted for operator-only callers: DNS names are not
  resolved (rebinding possible if a path ever takes untrusted input), and
  non-IP allow decisions rely on scheme + redirect caps only.
"""

import contextlib
import ipaddress
import urllib.error
import urllib.parse
import urllib.request


#: Maximum redirects followed per fetch. urllib sets no bound itself, so an
#: adversarial redirect loop would otherwise recurse until RecursionError
#: (or stall per-hop timeouts indefinitely).
MAX_REDIRECTS = 5

#: Cloud metadata endpoints: never fetchable, even with allow_local.
_ALWAYS_BLOCKED_IPS = (
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
)

#: Ranges rejected unless allow_local=True (loopback, link-local, private,
#: unspecified). Local-dev profiles that genuinely fetch from these ranges
#: must opt in explicitly per call site.
_LOCAL_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
)


def _literal_ip(host: str):
    """Parsed IP for literal-IP hosts, else None (no DNS is performed)."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    # Unwrap v4-mapped IPv6 so ::ffff:169.254.169.254 is judged as IPv4.
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def validate_fetch_url(url: str, *, allow_local: bool = False) -> str:
    """Reject fetch URLs that must never be retrieved. Returns url unchanged.

    Raises:
        ValueError: non-http(s) scheme, or a literal-IP host in a blocked
            range (metadata endpoints always; loopback/link-local/private
            unless allow_local=True).
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only http/https allowed."
        )
    host = (parsed.hostname or "").strip("[]")
    addr = _literal_ip(host) if host else None
    if addr is None:
        return url
    if addr in _ALWAYS_BLOCKED_IPS:
        raise ValueError(f"Refusing to fetch cloud metadata address '{host}'.")
    if not allow_local and any(addr in net for net in _LOCAL_NETWORKS):
        raise ValueError(f"Refusing to fetch non-public address '{host}'.")
    return url


class _RedirectLimitHandler(urllib.request.HTTPRedirectHandler):
    """HTTPRedirectHandler with a hop bound and per-hop revalidation."""

    max_redirects = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        count = getattr(req, "_qwed_redirects", 0) + 1
        if count > self.max_redirects:
            raise urllib.error.HTTPError(
                newurl, code, "Too many redirects (QWED cap)", headers, fp
            )
        # Re-validate every hop: a clean start URL must not launder a
        # blocked literal-IP target through a redirect.
        validate_fetch_url(newurl)
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None:
            new_req._qwed_redirects = count
        return new_req


@contextlib.contextmanager
def limited_redirects():
    """Activate the redirect-limiting opener for one fetch only.

    Installs a process-global opener around the call and restores the
    previous one afterwards, so the standard
    ``urllib.request.urlopen(...)`` call path — and the test mocks that
    patch it — keeps working unchanged. Single-threaded CLI use only.
    """
    opener = urllib.request.build_opener(_RedirectLimitHandler())
    previous = urllib.request._opener
    urllib.request.install_opener(opener)
    try:
        yield
    finally:
        urllib.request.install_opener(previous)
