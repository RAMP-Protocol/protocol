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
import addressVectorsFile from "../../go/resolvers/testdata/ssrf-address-vectors.json";
import hostsetVectorsFile from "../../go/resolvers/testdata/ssrf-hostset-vectors.json";
import redirectVectorsFile from "../../go/resolvers/testdata/ssrf-redirect-vectors.json";
import schemeVectorsFile from "../../go/resolvers/testdata/ssrf-scheme-vectors.json";
import {
	allowedScheme,
	blockedAddress,
	redirectChainRefused,
} from "../resolvers/ssrf.ts";

type AddressVector = { name: string; addr: string; blocked: boolean };
type AddressVectorsFile = { vectors: AddressVector[] };
type SchemeVector = { name: string; scheme: string; allowed: boolean };
type SchemeVectorsFile = { vectors: SchemeVector[] };
type RedirectVector = { name: string; hops: number; refused: boolean };
type RedirectVectorsFile = { vectors: RedirectVector[] };
type HostsetVector = { name: string; addrs: string[]; blocked: boolean };
type HostsetVectorsFile = { vectors: HostsetVector[] };

const addressVectors = (addressVectorsFile as AddressVectorsFile).vectors;
const schemeVectors = (schemeVectorsFile as SchemeVectorsFile).vectors;
const redirectVectors = (redirectVectorsFile as RedirectVectorsFile).vectors;
const hostsetVectors = (hostsetVectorsFile as HostsetVectorsFile).vectors;

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

describe("redirectChainRefused matches the sdk/go ssrf-redirect-vectors oracle", () => {
	it("redirect vector set is non-empty (guard against vacuous parity)", () => {
		expect(redirectVectors.length).toBeGreaterThan(0);
	});

	for (const v of redirectVectors) {
		it(`${v.name} (hops=${v.hops}) refused === ${v.refused}`, () => {
			expect(redirectChainRefused(v.hops)).toBe(v.refused);
		});
	}
});

describe("the multi-address any-reserved rule matches the sdk/go ssrf-hostset-vectors oracle", () => {
	it("host-set vector set is non-empty (guard against vacuous parity)", () => {
		expect(hostsetVectors.length).toBeGreaterThan(0);
	});

	for (const v of hostsetVectors) {
		it(`${v.name} (${v.addrs.join(",")}) blocked === ${v.blocked}`, () => {
			// Fail closed if ANY resolved address is reserved — the whole-set verdict the
			// guarded connector applies before pinning.
			expect(v.addrs.some((a) => blockedAddress(a))).toBe(v.blocked);
		});
	}
});
