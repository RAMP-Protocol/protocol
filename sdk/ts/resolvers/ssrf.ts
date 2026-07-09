// The SSRF address guard for the fetching resolvers' DEFAULT transport. Ports
// sdk/go/helpers/wbakeyresolver.go (ssrfBlockedPrefixes / ssrfBlocked) 1:1.
//
// A WBA/well-known resolver fetches a directory from a caller-supplied
// Signature-Agent host BEFORE the ed25519 signature check, so an unguarded
// default is a pre-auth SSRF lever against internal networks. blockedAddress is
// the reserved / non-public address predicate the guarded default transport
// applies to EVERY resolved address before connecting. It replaces the
// IsPrivate/IsLinkLocal heuristic, which misses CGNAT (100.64.0.0/10),
// 0.0.0.0/8, the TEST-NETs, benchmarking, protocol-assignment, and other
// reserved ranges. IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d)
// forms are unwrapped and their embedded v4 re-checked, so an IPv6 literal
// cannot smuggle a private v4 past a v6-form-only test.

/** The scheme allowlist the SSRF guard enforces: deny-by-default, only http and
 * https may be dialed (mirrors the Go oracle's allowedScheme). Blocks
 * file/data/gopher/dict/ftp/ldap and every other exotic scheme that would let a
 * caller-supplied URL reach the local filesystem or unintended protocols. The
 * comparison is case-insensitive (HTTPS ≡ https). */
export function allowedScheme(scheme: string): boolean {
  const s = scheme.toLowerCase();
  return s === "http" || s === "https";
}

/** A parsed CIDR: the network bytes (4 or 16) and the prefix length in bits. */
interface Cidr {
  bytes: Uint8Array;
  bits: number;
}

// The reserved / non-public prefix set the guard rejects — the EXACT set the Go
// oracle rejects (ssrfBlockedPrefixes), split v4 / v6.
const BLOCKED_CIDRS: readonly string[] = [
  // IPv4
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
  // IPv6
  "::/128",
  "::1/128",
  // IPv4-compatible IPv6 (::a.b.c.d) — deprecated; block the whole ::/96 so an
  // embedded v4 cannot smuggle a reserved address through a v6 literal.
  "::/96",
  "100::/64",
  "2001:db8::/32",
  "2001::/23",
  // 6to4 (RFC 3056) — block wholesale; a 2002:V4ADDR:: literal embeds an
  // arbitrary v4 in bits 16..48 and must never be dialed.
  "2002::/16",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
  // NAT64 (the /96 well-known prefix's embedded v4 is also re-checked below)
  "64:ff9b::/96",
  "64:ff9b:1::/48",
];

// The well-known NAT64 prefix (RFC 6052). An address inside it embeds an IPv4
// in its trailing 32 bits, which must be re-checked for reserved-ness.
const NAT64_WELL_KNOWN = parseCidr("64:ff9b::/96");

const BLOCKED_PARSED: readonly Cidr[] = BLOCKED_CIDRS.map(parseCidr);

/** Reports whether `ip` (a numeric IPv4 or IPv6 literal — never a hostname) is
 * a reserved / non-public address the SSRF guard must refuse to dial. It first
 * unwraps v4-mapped and NAT64 forms and re-checks the embedded v4, so an IPv6
 * literal embedding a private v4 cannot slip past a v6-only test. An
 * unparseable input is treated as blocked (fail-closed: never dial what we
 * cannot classify). */
export function blockedAddress(ip: string): boolean {
  const addr = parseAddr(ip);
  if (!addr) return true;
  return blockedBytes(addr);
}

function blockedBytes(addr: Uint8Array): boolean {
  // Unwrap an IPv4-mapped IPv6 (::ffff:a.b.c.d) to its 4-byte form so the v4
  // prefix table applies. Then, for any remaining 16-byte address, re-check a
  // NAT64-embedded v4 before the prefix scan.
  const unmapped = unmapV4(addr);
  if (unmapped.length === 16) {
    const embedded = nat64EmbeddedV4(unmapped);
    if (embedded && blockedBytes(embedded)) return true;
  }
  for (const cidr of BLOCKED_PARSED) {
    if (cidr.bytes.length === unmapped.length && contains(cidr, unmapped)) return true;
  }
  return false;
}

/** Extract the trailing 32 bits of a 64:ff9b::/96 address as a 4-byte v4, or
 * `undefined` when `addr` is not in the well-known NAT64 prefix. */
function nat64EmbeddedV4(addr: Uint8Array): Uint8Array | undefined {
  if (!contains(NAT64_WELL_KNOWN, addr)) return undefined;
  return addr.slice(12, 16);
}

/** Unwrap an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its 4-byte v4 form;
 * pass any other address through unchanged. */
function unmapV4(addr: Uint8Array): Uint8Array {
  if (addr.length !== 16) return addr;
  for (let i = 0; i < 10; i++) if (addr[i] !== 0) return addr;
  if (addr[10] !== 0xff || addr[11] !== 0xff) return addr;
  return addr.slice(12, 16);
}

/** Whether `addr` (same byte-length as the CIDR) falls inside `cidr` — a masked
 * byte comparison over the prefix length. */
function contains(cidr: Cidr, addr: Uint8Array): boolean {
  if (addr.length !== cidr.bytes.length) return false;
  let bits = cidr.bits;
  for (let i = 0; i < cidr.bytes.length; i++) {
    if (bits <= 0) break;
    const take = bits >= 8 ? 8 : bits;
    const mask = take === 8 ? 0xff : (0xff << (8 - take)) & 0xff;
    if (((addr[i] as number) & mask) !== ((cidr.bytes[i] as number) & mask)) return false;
    bits -= 8;
  }
  return true;
}

function parseCidr(cidr: string): Cidr {
  const slash = cidr.lastIndexOf("/");
  const addrPart = cidr.slice(0, slash);
  const bits = Number(cidr.slice(slash + 1));
  const bytes = parseAddr(addrPart);
  if (!bytes) throw new Error(`ssrf: unparseable CIDR ${cidr}`);
  return { bytes, bits };
}

/** Parse an IPv4 or IPv6 literal into its network-order bytes (4 or 16), or
 * `undefined` when it is not a bare numeric address. */
export function parseAddr(ip: string): Uint8Array | undefined {
  if (ip.includes(":")) return parseV6(ip);
  return parseV4(ip);
}

function parseV4(ip: string): Uint8Array | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) return undefined;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i] as string;
    if (!/^\d{1,3}$/.test(p)) return undefined;
    const n = Number(p);
    if (n > 255) return undefined;
    out[i] = n;
  }
  return out;
}

function parseV6(ip: string): Uint8Array | undefined {
  // Strip a zone id (fe80::1%eth0) — irrelevant to the prefix check.
  const zone = ip.indexOf("%");
  if (zone >= 0) ip = ip.slice(0, zone);

  const halves = ip.split("::");
  if (halves.length > 2) return undefined;

  const head = halves[0] === "" ? [] : (halves[0] as string).split(":");
  const tailStr = halves.length === 2 ? halves[1] : undefined;
  const tail = tailStr === undefined || tailStr === "" ? [] : tailStr.split(":");

  const out = new Uint8Array(16);
  let idx = 0;

  const writeGroups = (groups: string[], start: number): boolean => {
    let pos = start;
    for (let g = 0; g < groups.length; g++) {
      const grp = groups[g] as string;
      // A trailing IPv4 in the last group (e.g. ::ffff:1.2.3.4 or 64:ff9b::a.b.c.d).
      if (grp.includes(".")) {
        if (g !== groups.length - 1) return false;
        const v4 = parseV4(grp);
        if (!v4) return false;
        if (pos + 4 > 16) return false;
        out.set(v4, pos);
        pos += 4;
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(grp)) return false;
      if (pos + 2 > 16) return false;
      const val = parseInt(grp, 16);
      out[pos] = (val >> 8) & 0xff;
      out[pos + 1] = val & 0xff;
      pos += 2;
    }
    return true;
  };

  // Count the bytes each side occupies (an embedded v4 counts as 4, not 2).
  const byteLen = (groups: string[]): number =>
    groups.reduce((n, g) => n + (g.includes(".") ? 4 : 2), 0);

  if (halves.length === 1) {
    // No "::" — must be a full address.
    if (byteLen(head) !== 16) return undefined;
    return writeGroups(head, 0) ? out : undefined;
  }

  const headBytes = byteLen(head);
  const tailBytes = byteLen(tail);
  if (headBytes + tailBytes > 16) return undefined;
  if (!writeGroups(head, 0)) return undefined;
  idx = 16 - tailBytes;
  if (!writeGroups(tail, idx)) return undefined;
  return out;
}
