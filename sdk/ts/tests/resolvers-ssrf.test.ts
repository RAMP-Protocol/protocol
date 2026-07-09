// Unit + integration coverage for the SSRF address guard on the resolvers'
// DEFAULT transport — parity with sdk/go/helpers/wbakeyresolver.go (ssrfBlocked /
// newGuardedWBAClient). A WBA/well-known resolver fetches a directory from a
// caller-supplied Signature-Agent host BEFORE the ed25519 signature check, so an
// unguarded default is a pre-auth SSRF lever. blockedAddress is the reserved /
// non-public predicate; the guarded default transport refuses to dial a blocked
// target (loopback proven end-to-end below).

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";

import { blockedAddress } from "../resolvers/ssrf.ts";
import { guardedFetch, SsrfBlockedError } from "../resolvers/http.ts";

// The FULL reserved set the Go oracle rejects (ssrfBlockedPrefixes) — one
// representative address per prefix, INCLUDING the ranges an IsPrivate/
// IsLinkLocal heuristic misses (100.64/10 CGNAT, 0.0.0.0/8, the TEST-NETs,
// benchmarking, protocol-assignment) and the v4-mapped / NAT64 embedding forms.
const BLOCKED: ReadonlyArray<[string, string]> = [
  ["0.0.0.0/8", "0.1.2.3"],
  ["10.0.0.0/8", "10.1.2.3"],
  ["100.64.0.0/10 CGNAT", "100.64.0.1"], // previously-missed by IsPrivate
  ["100.64.0.0/10 CGNAT top", "100.127.255.255"],
  ["127.0.0.0/8 loopback", "127.0.0.1"],
  ["169.254.0.0/16 link-local", "169.254.169.254"], // cloud metadata endpoint
  ["172.16.0.0/12", "172.16.5.5"],
  ["172.16.0.0/12 top", "172.31.255.255"],
  ["192.0.0.0/24", "192.0.0.8"],
  ["192.0.2.0/24 TEST-NET-1", "192.0.2.1"],
  ["192.88.99.0/24 6to4-relay", "192.88.99.1"],
  ["192.168.0.0/16", "192.168.1.1"],
  ["198.18.0.0/15 benchmark", "198.18.0.1"],
  ["198.51.100.0/24 TEST-NET-2", "198.51.100.1"],
  ["203.0.113.0/24 TEST-NET-3", "203.0.113.1"],
  ["224.0.0.0/4 multicast", "224.0.0.1"],
  ["240.0.0.0/4 reserved", "240.0.0.1"],
  ["255.255.255.255/32 broadcast", "255.255.255.255"],
  // IPv6
  ["::/128 unspecified", "::"],
  ["::1/128 loopback", "::1"],
  ["100::/64 discard", "100::1"],
  ["2001:db8::/32 doc", "2001:db8::1"],
  ["2001::/23 teredo/etc", "2001:0:1::1"],
  ["fc00::/7 ULA", "fc00::1"],
  ["fe80::/10 link-local", "fe80::1"],
  ["ff00::/8 multicast", "ff02::1"],
  // v4-mapped forms must unwrap and re-check the embedded v4.
  ["::ffff:169.254.x mapped link-local", "::ffff:169.254.169.254"],
  ["::ffff:127.0.0.1 mapped loopback", "::ffff:127.0.0.1"],
  ["::ffff:10.x mapped private", "::ffff:10.0.0.1"],
  // NAT64: the well-known 64:ff9b::/96 prefix is blocked WHOLESALE (matching the
  // Go oracle's prefix table), and the embedded-v4 re-check independently catches
  // a private v4 smuggled in the trailing 32 bits.
  ["64:ff9b::a9fe:a9fe NAT64 link-local", "64:ff9b::a9fe:a9fe"],
  ["64:ff9b::169.254.169.254 NAT64 dotted", "64:ff9b::169.254.169.254"],
  ["64:ff9b:1::/48 local-use NAT64", "64:ff9b:1::1"],
];

// Public addresses the guard must ALLOW — the guard is a denylist over reserved
// ranges, so a routable v4/v6 (and a NAT64-embedded PUBLIC v4) passes.
const ALLOWED: ReadonlyArray<[string, string]> = [
  ["Google DNS", "8.8.8.8"],
  ["Cloudflare DNS", "1.1.1.1"],
  ["a routable v4", "93.184.216.34"],
  ["Cloudflare v6", "2606:4700::1"],
  ["a routable v6", "2001:4860:4860::8888"],
];

describe("blockedAddress", () => {
  for (const [label, ip] of BLOCKED) {
    it(`blocks ${label} (${ip})`, () => {
      expect(blockedAddress(ip)).toBe(true);
    });
  }

  for (const [label, ip] of ALLOWED) {
    it(`allows ${label} (${ip})`, () => {
      expect(blockedAddress(ip)).toBe(false);
    });
  }

  it("fails closed on an unparseable input (never dials what it cannot classify)", () => {
    expect(blockedAddress("not-an-ip")).toBe(true);
    expect(blockedAddress("999.1.2.3")).toBe(true);
    expect(blockedAddress("")).toBe(true);
  });
});

describe("guardedFetch (default transport)", () => {
  it("refuses to dial a loopback (127.0.0.1) origin with an SSRF error", async () => {
    // A REAL loopback origin: the guard must refuse to CONNECT to it, proving the
    // default transport closes the pre-auth SSRF lever even against a live server.
    const server: Server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    try {
      await expect(guardedFetch(`http://127.0.0.1:${port}/.well-known/x`)).rejects.toBeInstanceOf(
        SsrfBlockedError,
      );
      await expect(guardedFetch(`http://127.0.0.1:${port}/.well-known/x`)).rejects.toThrow(/SSRF/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("refuses an IPv6 loopback ([::1]) target", async () => {
    await expect(guardedFetch("http://[::1]:80/x")).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});
