// SSRF guard parity (TypeScript side) — the shared adversarial corpora are the
// oracle: sdk/go emits them, every SDK consumes them, and this guard MUST fail
// if a prefix, an IPv6 zone strip, or a v4-mapped/NAT64 unwrap is missing.
//
//   sdk/go/resolvers/testdata/ssrf-address-vectors.json  {vectors:[{name,addr,blocked}]}
//     hostile/benign resolved addresses and whether blockedAddress MUST refuse
//     each (zoned IPv6, v4-mapped, NAT64, 6to4, IPv4-compatible, CGNAT, TEST-NETs).
//   sdk/go/resolvers/testdata/ssrf-scheme-vectors.json   {vectors:[{name,scheme,allowed}]}
//     deny-by-default scheme allowlist — only http/https may be dialed.
//
// Both corpora are read-only; do NOT edit them here. This file is the parity
// guard that keeps blockedAddress/allowedScheme in lockstep with the Go oracle.

import { describe, expect, it } from "vitest";

import { allowedScheme, blockedAddress } from "../resolvers/ssrf.ts";
import addressVectorsFile from "../../go/resolvers/testdata/ssrf-address-vectors.json";
import schemeVectorsFile from "../../go/resolvers/testdata/ssrf-scheme-vectors.json";

type AddressVector = { name: string; addr: string; blocked: boolean };
type AddressVectorsFile = { vectors: AddressVector[] };
type SchemeVector = { name: string; scheme: string; allowed: boolean };
type SchemeVectorsFile = { vectors: SchemeVector[] };

const addressVectors = (addressVectorsFile as AddressVectorsFile).vectors;
const schemeVectors = (schemeVectorsFile as SchemeVectorsFile).vectors;

describe("blockedAddress matches the sdk/go ssrf-address-vectors oracle", () => {
  it("address vector set is non-empty (guard against vacuous parity)", () => {
    expect(addressVectors.length).toBeGreaterThan(0);
  });

  for (const v of addressVectors) {
    it(`${v.name} (${v.addr}) blocked === ${v.blocked}`, () => {
      expect(blockedAddress(v.addr)).toBe(v.blocked);
    });
  }
});

describe("allowedScheme matches the sdk/go ssrf-scheme-vectors oracle", () => {
  it("scheme vector set is non-empty (guard against vacuous parity)", () => {
    expect(schemeVectors.length).toBeGreaterThan(0);
  });

  for (const v of schemeVectors) {
    it(`${v.name} (${v.scheme}) allowed === ${v.allowed}`, () => {
      expect(allowedScheme(v.scheme)).toBe(v.allowed);
    });
  }
});
