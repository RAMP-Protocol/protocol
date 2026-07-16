"""Reserved-address classification for the WBA SSRF guard.

Port of the Go oracle's ``ssrfBlocked`` / ``ssrfBlockedPrefixes``
(sdk/go/helpers/wbakeyresolver.go). The WBA directory host is derived from a
caller-supplied Signature-Agent header and fetched BEFORE the ed25519 signature
check, so an unguarded default transport is a pre-auth SSRF lever against
internal networks. This module is the classifier the guarded default transport
consults against ALREADY-RESOLVED peer addresses.

Parity note: :mod:`ipaddress` alone (``is_private`` / ``is_reserved`` /
``is_link_local`` / ``is_loopback`` / ``is_multicast``) covers much of the set,
but its verdicts differ from the Go oracle on a few ranges (e.g. 100.64.0.0/10
CGNAT, 0.0.0.0/8, 240.0.0.0/4, the NAT64 forms). The EXPLICIT prefix table below
plus the v4-mapped / NAT64 unwrapping mirror the Go set byte-for-byte so the
three SDKs classify identically.
"""

from __future__ import annotations

import ipaddress


class SsrfError(OSError):
    """Raised when the guarded transport refuses to dial a non-public target.

    Subclasses :class:`OSError` so it flows through the transport-failure arms of
    :func:`ramp_sdk.resolvers._http.fetch_strict` / ``fetch_soft`` exactly like
    any other dial failure (mapping to ``DirectoryUnavailableError`` / a dropped
    best-effort refresh) rather than surfacing as an uncaught exception.
    """


# The shared redirect-depth cap. Deny-by-default and IDENTICAL across the three
# SDKs (Go maxWBARedirects / undici maxRedirections): the guarded client follows
# at most this many redirect hops and refuses the next, so no SDK inherits its
# HTTP library's looser default (httpx's default is 20). httpx enforces it via the
# guarded client's ``max_redirects`` kwarg; the corpus pins the predicate below.
MAX_REDIRECTS = 5


def redirect_chain_refused(hops: int) -> bool:
    """Report whether a chain of ``hops`` redirects must be refused.

    The shared redirect-depth policy: a chain is refused iff it EXCEEDS
    :data:`MAX_REDIRECTS`. Corpus-tested identically against the Go oracle's
    ``redirectChainRefused`` so the three SDKs agree on the boundary; the real
    httpx client is configured to the same cap (``max_redirects=MAX_REDIRECTS``).
    """
    return hops > MAX_REDIRECTS


def refusal(host: str) -> SsrfError:
    """Build the GENERIC dial-refusal error the guard raises for EVERY refuse
    reason — an unresolvable host, an empty resolution, or a resolved-reserved
    address all yield the SAME message. It names only the caller-supplied host
    (already known to the caller), never the resolved IP, and does not distinguish
    an NXDOMAIN from a resolved-private answer, so it cannot serve as a pre-auth
    DNS oracle against internal networks. Identical wording across the three SDKs.
    """
    return SsrfError(f"refusing to dial {host!r} (SSRF guard)")


# The reserved / non-public address set the WBA SSRF guard rejects. Mirrors the
# Go oracle's ssrfBlockedPrefixes EXACTLY (order irrelevant — membership is a
# per-prefix containment test). IPv4-mapped and NAT64 forms are unwrapped in
# blocked_address() so an IPv6 literal cannot smuggle a private v4 past a
# v6-form-only check.
_BLOCKED_PREFIXES: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        # IPv4
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        # IPv6
        "::/128",
        "::1/128",
        "100::/64",
        "2001:db8::/32",
        "2001::/23",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        # 6to4 (RFC 3056): 2002:V4ADDR::/48 tunnels an embedded v4; block the
        # whole 2002::/16 wholesale (any embedded v4, private or not).
        "2002::/16",
        # IPv4-compatible (deprecated ::a.b.c.d): the trailing v4 sits in ::/96,
        # so ::a00:1 (== ::10.0.0.1) must not slip past a v6-only test.
        "::/96",
        # NAT64 (the embedded v4 is also re-checked in blocked_address)
        "64:ff9b::/96",
        "64:ff9b:1::/48",
    )
)

# The well-known NAT64 prefix (RFC 6052). Only the /96 well-known prefix carries
# an embedded v4 that must be re-checked; the /48 local-use prefix is caught
# directly by the prefix table.
_NAT64_WELLKNOWN = ipaddress.ip_network("64:ff9b::/96")


def _nat64_embedded_v4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return the trailing 32 bits of a 64:ff9b::/96 address as an IPv4 address.

    RFC 6052 NAT64 embeds the target v4 in the low 32 bits; extracting it lets
    the guard re-check the embedded address's reserved-ness. Returns None when
    ``addr`` is not in the well-known NAT64 prefix.
    """
    if addr not in _NAT64_WELLKNOWN:
        return None
    return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)


def blocked_address(ip: str | ipaddress._BaseAddress) -> bool:
    """Report whether ``ip`` is a reserved / non-public address the guard rejects.

    Mirrors the Go oracle's ``ssrfBlocked``: it first unwraps v4-mapped
    (``::ffff:a.b.c.d``) and NAT64 (``64:ff9b::a.b.c.d``) forms and re-checks the
    embedded v4, so an IPv6 literal embedding a private v4 cannot slip past a
    v6-only test, then tests the (unwrapped) address against the explicit prefix
    table.

    ``ip`` may be a string literal or an ``ipaddress`` address object.
    """
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address
    if isinstance(ip, str):
        # Strip any IPv6 zone id (everything from '%' onward) before parsing:
        # a zoned literal like fe80::1%eth0 is not a member of any prefix, so a
        # zone would otherwise skip every containment test — a guard bypass.
        # Mirrors the Go oracle's addr.WithZone("").
        zone = ip.find("%")
        if zone != -1:
            ip = ip[:zone]
        addr = ipaddress.ip_address(ip)
    elif isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        addr = ip
    else:  # pragma: no cover - defensive: _BaseAddress has only these two leaves
        raise TypeError(f"unsupported address type: {type(ip)!r}")

    # Unwrap a v4-mapped ::ffff:a.b.c.d to its embedded a.b.c.d before testing.
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            addr = mapped

    # NAT64: re-check the embedded v4 (only meaningful for a still-v6 address).
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = _nat64_embedded_v4(addr)
        if embedded is not None and blocked_address(embedded):
            return True

    return any(addr in prefix for prefix in _BLOCKED_PREFIXES)


def allowed_scheme(scheme: str) -> bool:
    """Report whether ``scheme`` may be dialed by the guarded transport.

    Deny-by-default allowlist: only http/https, enforced on the initial request
    AND every redirect target. A scheme denylist is unwinnable (ftp, ftps,
    telnet, gopher, file, data, dict, …), so the policy is an allowlist.
    Case-insensitive per RFC 3986. Mirrors the Go oracle's ``allowedScheme`` and
    is corpus-tested identically across the three SDKs.
    """
    return scheme.lower() in ("http", "https")
