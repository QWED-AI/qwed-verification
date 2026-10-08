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
#: (Suppression rationale for the hardcoded-address rule below: these are
#: IETF/cloud-reserved endpoints, not deployment config.)
_ALWAYS_BLOCKED_IPS = (
    ipaddress.ip_address("169.254.169.254"),  # NOSONAR
    ipaddress.ip_address("100.100.100.200"),  # NOSONAR
    ipaddress.ip_address("fd00:ec2::254"),  # NOSONAR AWS IPv6 metadata
)

#: Ranges rejected unless allow_local=True (loopback, link-local, private,
#: unspecified). Local-dev profiles that genuinely fetch from these ranges
#: must opt in explicitly per call site.
#: (Suppression rationale as above: IETF-reserved ranges per RFC
#: 1122/3927/1918/6598; allow_local is the intentional override.)
_LOCAL_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),  # NOSONAR
    ipaddress.ip_network("10.0.0.0/8"),  # NOSONAR
    ipaddress.ip_network("172.16.0.0/12"),  # NOSONAR
    ipaddress.ip_network("192.168.0.0/16"),  # NOSONAR
    ipaddress.ip_network("100.64.0.0/10"),  # NOSONAR shared (CGNAT), not globally reachable
    ipaddress.ip_network("169.254.0.0/16"),  # NOSONAR
    ipaddress.ip_network("0.0.0.0/8"),  # NOSONAR
    ipaddress.ip_network("::1/128"),  # NOSONAR
    ipaddress.ip_network("fe80::/10"),  # NOSONAR
    ipaddress.ip_network("::/128"),  # NOSONAR
    ipaddress.ip_network("fc00::/7"),  # NOSONAR
)


def _literal_ip(host: str):
    """Parsed IP for literal-IP hosts, else None (no DNS is performed).

    Beyond dotted quads, resolvers accept decimal ("2852039166"),
    hexadecimal ("0xa9fea9fe"), octal ("0251.0376.0251.0376"), and
    shortened ("127.1", "169.254.43518") IPv4 forms — all of which must
    be judged, or a blocked address slips through in disguise. Parsed
    manually (not via socket.inet_aton, whose accepted forms vary by
    platform) so the guard behaves identically everywhere.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = _alt_ipv4_literal(host)
    if addr is None:
        return None
    # Unwrap v4-mapped IPv6 so ::ffff:169.254.169.254 is judged as IPv4.
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def _alt_ipv4_literal(host: str):
    """Resolver-style IPv4 for disguise forms, else None.

    One to four dot-separated parts; each part decimal, 0x-hex, or
    0-octal; the last part fills all remaining bytes with C-style range
    checks per part count. Anything else (including invalid octal like
    "09" or out-of-range parts) is not a numeric literal — resolvers
    send it to DNS, and so do we.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    nums = []
    for part in parts:
        low = part.lower()
        try:
            if low.startswith("0x"):
                nums.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                nums.append(int(part, 8))
            elif part.isdigit():
                nums.append(int(part))
            else:
                return None
        except ValueError:
            return None
    limits = {
        1: (0xFFFFFFFF,),
        2: (0xFF, 0xFFFFFF),
        3: (0xFF, 0xFF, 0xFFFF),
        4: (0xFF, 0xFF, 0xFF, 0xFF),
    }[len(nums)]
    if any(n < 0 or n > lim for n, lim in zip(nums, limits)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value |= n << (8 * (3 - i))
    return ipaddress.IPv4Address(value)


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

    def __init__(self, allow_local: bool = False):
        self.allow_local = allow_local

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        count = getattr(req, "_qwed_redirects", 0) + 1
        if count > self.max_redirects:
            raise urllib.error.HTTPError(
                newurl, code, "Too many redirects (QWED cap)", headers, fp
            )
        # Re-validate every hop with the caller's local policy: a clean
        # start URL must not launder a blocked literal-IP target through
        # a redirect.
        validate_fetch_url(newurl, allow_local=self.allow_local)
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None:
            new_req._qwed_redirects = count
        return new_req


@contextlib.contextmanager
def limited_redirects(allow_local: bool = False):
    """Activate the redirect-limiting opener for one fetch only.

    Installs a process-global opener around the call and restores the
    previous one afterwards, so the standard
    ``urllib.request.urlopen(...)`` call path — and the test mocks that
    patch it — keeps working unchanged. Single-threaded CLI use only.
    """
    opener = urllib.request.build_opener(_RedirectLimitHandler(allow_local))
    previous = urllib.request._opener
    urllib.request.install_opener(opener)
    try:
        yield
    finally:
        urllib.request.install_opener(previous)
