// Shared served-directory harness for the resolver integration suites
// (resolvers-wellknown.integration.test.ts + resolvers-wba.integration.test.ts).
//
// Per the RAMP testing doctrine these resolvers are IO-BOUND, so the suites
// exercise them against a REAL in-process node:http server on 127.0.0.1:0 — never
// a mocked fetch. The resolvers use their default global-fetch transport; only
// the clock (and the poll timer/seams) are injected for determinism. This module
// stands up that real origin and mints real Ed25519 keys; it imports ONLY the
// existing byte-parity-pinned SDK primitives (thumbprint, base64url), never the
// not-yet-existing resolver faces — so a RED run points at the missing faces, not
// at this fixture.

import { generateKeyPairSync } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import { decodeBase64Url } from "../src/base64url.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { WellKnownManifestVersion } from "../src/wire.ts";

// Well-known paths the origin serves. The WBA directory path is the fixed Web
// Bot Auth path; the JWKS key doc and the endpoint manifest sit on distinct
// paths so the key face (fixed URL) and endpoint face (host-keyed ramp.json)
// never collide.
export const WBA_DIR_PATH = "/.well-known/http-message-signatures-directory";
export const REVOCATION_PATH = "/.well-known/ramp-key-revocations.json";
export const MANIFEST_PATH = "/.well-known/ramp.json";
export const JWKS_PATH = "/keys.json";

/** A real Ed25519 key: raw 32-byte public key, its base64url `x`, and its RFC
 * 7638 thumbprint (the WBA keyid). Produced through the SDK's own thumbprint
 * primitive so lookups match the port byte-for-byte. */
export interface TestKey {
	rawPub: Uint8Array;
	x: string;
	tp: string;
}

/** Mint a fresh Ed25519 key via node:crypto and derive its SDK thumbprint. */
export async function makeKey(): Promise<TestKey> {
	const { publicKey } = generateKeyPairSync("ed25519");
	const jwk = publicKey.export({ format: "jwk" }) as { x: string };
	const raw = decodeBase64Url(jwk.x);
	if (!raw) throw new Error("harness: could not decode generated JWK x");
	return { rawPub: raw, x: jwk.x, tp: await thumbprint(raw) };
}

/** One JWK member of a WBA directory, snake_case exactly as the Go oracle emits
 * it via protojson (UseProtoNames). */
export function wbaJwk(
	x: string,
	notBefore: string,
	notAfter: string,
): Record<string, unknown> {
	return {
		kty: "OKP",
		crv: "Ed25519",
		use: "sig",
		alg: "EdDSA",
		x,
		not_before: notBefore,
		not_after: notAfter,
	};
}

/** Serialize a WBAFile carrying keys (and optionally a revocation_url). */
export function wbaFileJson(
	keys: Record<string, unknown>[],
	revocationUrl?: string,
): string {
	const doc: Record<string, unknown> = { keys };
	if (revocationUrl !== undefined) doc.revocation_url = revocationUrl;
	return JSON.stringify(doc);
}

/** Serialize a KeyRevocationList snapshot (as_of RFC3339-Z + revoked thumbprints). */
export function revocationJson(asOf: string, revoked: string[]): string {
	return JSON.stringify({ as_of: asOf, revoked });
}

/** Serialize the ad-hoc kid-carrying JWKS key doc (shape:
 * `{keys:[{kid,kty,crv,x}]}`) the WellKnownKeyResolver reads. */
export function jwksKeyDocJson(entries: Record<string, unknown>[]): string {
	return JSON.stringify({ keys: entries });
}

/** A valid Ed25519 JWKS entry keyed by kid. */
export function jwksEntry(kid: string, x: string): Record<string, unknown> {
	return { kid, kty: "OKP", crv: "Ed25519", x };
}

/** Serialize a WellKnownManifest projection ({ver, role, endpoint}); omit
 * endpoint to model a valid-but-inert manifest, and pass `ver: null` to omit the
 * version member and model a manifest with no version at all. */
export function manifestJson(endpoint?: string, ver: string | null = WellKnownManifestVersion): string {
	const doc: Record<string, unknown> = { role: "ROLE_EXCHANGE" };
	if (ver !== null) doc.ver = ver;
	if (endpoint !== undefined) doc.endpoint = endpoint;
	return JSON.stringify(doc);
}

interface OriginState {
	wba?: string;
	wbaStatus: number;
	wbaHits: number;
	rev?: string;
	jwks?: string;
	jwksStatus: number;
	jwksHits: number;
	manifest?: string;
	manifestStatus: number;
	manifestHits: number;
}

/** A real in-process origin serving the WBA directory, revocation snapshot,
 * JWKS key doc, and ramp.json manifest. Each doc is independently settable so a
 * test can rotate keys, publish a new revocation snapshot, or force a 500. */
export interface Origin {
	url: string;
	host: string;
	setWBA(body: string): void;
	setWBAStatus(code: number): void;
	wbaHits(): number;
	setRevocation(body: string): void;
	setJwks(body: string): void;
	setJwksStatus(code: number): void;
	jwksHits(): number;
	setManifest(body: string): void;
	setManifestStatus(code: number): void;
	manifestHits(): number;
	revocationURL(): string;
	close(): Promise<void>;
}

function route(
	state: OriginState,
	path: string,
): { code: number; body: string } | undefined {
	if (path === WBA_DIR_PATH) {
		state.wbaHits += 1;
		if (state.wbaStatus !== 0) return { code: state.wbaStatus, body: "" };
		if (state.wba === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.wba };
	}
	if (path === REVOCATION_PATH) {
		if (state.rev === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.rev };
	}
	if (path === JWKS_PATH) {
		state.jwksHits += 1;
		if (state.jwksStatus !== 0) return { code: state.jwksStatus, body: "" };
		if (state.jwks === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.jwks };
	}
	if (path === MANIFEST_PATH) {
		state.manifestHits += 1;
		if (state.manifestStatus !== 0)
			return { code: state.manifestStatus, body: "" };
		if (state.manifest === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.manifest };
	}
	return undefined;
}

/** Start a real origin on 127.0.0.1:0. */
export async function startOrigin(): Promise<Origin> {
	const state: OriginState = {
		wbaStatus: 0,
		wbaHits: 0,
		jwksStatus: 0,
		jwksHits: 0,
		manifestStatus: 0,
		manifestHits: 0,
	};
	const server: Server = createServer((req, res) => {
		const path = (req.url ?? "").split("?")[0] ?? "";
		const hit = route(state, path);
		if (hit === undefined) {
			res.writeHead(404);
			res.end();
			return;
		}
		res.writeHead(hit.code, { "content-type": "application/json" });
		res.end(hit.body);
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const addr = server.address() as AddressInfo;
	const host = `127.0.0.1:${addr.port}`;
	const url = `http://${host}`;
	return {
		url,
		host,
		setWBA: (b) => {
			state.wba = b;
		},
		setWBAStatus: (c) => {
			state.wbaStatus = c;
		},
		wbaHits: () => state.wbaHits,
		setRevocation: (b) => {
			state.rev = b;
		},
		setJwks: (b) => {
			state.jwks = b;
		},
		setJwksStatus: (c) => {
			state.jwksStatus = c;
		},
		jwksHits: () => state.jwksHits,
		setManifest: (b) => {
			state.manifest = b;
		},
		setManifestStatus: (c) => {
			state.manifestStatus = c;
		},
		manifestHits: () => state.manifestHits,
		revocationURL: () => url + REVOCATION_PATH,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
}

// Time constants shared by the suites. The anchor sits well inside the validity
// windows the active-key builders emit.
export const HOUR_MS = 3_600_000;
export const ANCHOR_MS = Date.UTC(2026, 4, 1, 12, 0, 0); // 2026-05-01T12:00:00Z

/** RFC3339-Z rendering of an epoch-ms instant. */
export function iso(ms: number): string {
	return new Date(ms).toISOString();
}

/** The unguarded transport the integration suites inject to reach the in-process
 * 127.0.0.1 origin. The SDK's DEFAULT transport is now SSRF-guarded (it refuses
 * loopback / private targets — see resolvers/ssrf.ts), which is exactly the
 * pre-auth SSRF lever these faces close. A test origin is loopback, so — like
 * the Go oracle's tests, which inject an httptest client — the suites inject
 * this bare global-fetch transport as the escape hatch, keeping the guard on the
 * production default while still exercising the resolver logic against a real
 * server. It is a REAL fetch, never a mock; only the clock/poll seams are stubbed. */
export const loopbackFetch = (
	url: string,
): Promise<{ status: number; text(): Promise<string> }> =>
	fetch(url) as unknown as Promise<{ status: number; text(): Promise<string> }>;

// Parsed-WBAFile builders. These mirror the inline helpers the active-key
// behavior suite uses, hoisted here so the offer-key-cache suite consumes a
// PARSED WBAFile (the shape the cache's injected OfferDirectoryFetch seam
// returns) without re-deriving window arithmetic. `WBAFileSchema` is a generated
// schema (always present), so importing it here does NOT couple the harness to
// the not-yet-existing offer-key-cache face — a RED run still points at that
// missing module, not at this fixture.
export type WBAFile = ReturnType<typeof WBAFileSchema.parse>;

/** Parse raw JWK member objects into a WBAFile, exactly as an injected
 * directory-fetch seam would hand one to the cache. */
export function directory(keys: Record<string, unknown>[]): WBAFile {
	return WBAFileSchema.parse({ keys });
}

/** A window-active JWK member: validity window straddles ANCHOR
 * ([ANCHOR-1h, ANCHOR+1h]), so its `not_after` is ANCHOR+1h — the bound the
 * cache clamps its TTL against. */
export function activeJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + HOUR_MS));
}

/** A retired JWK member: validity window sits entirely before ANCHOR, so it is
 * never window-active at ANCHOR. */
export function expiredJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - 2 * HOUR_MS), iso(ANCHOR_MS - HOUR_MS));
}
