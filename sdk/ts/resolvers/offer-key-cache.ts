// CachedOfferKeyResolver — the domain-keyed offer-signing-key cache that
// consolidates the Broker's offerkeys.Resolver and the MCP shim's
// ExchangeOfferKeyCache into the SDK. It resolves an exchange DOMAIN
// (Offer.exchange) to that exchange's active Ed25519 offer-signing key, caching
// per domain with a TTL whose expiry is CLAMPED to the key's not_after, folding
// revocation screening into selection, and coalescing concurrent resolves for a
// domain into a single directory fetch. It IMPLEMENTS core/verifier.ts
// OfferKeyResolver (resolve(exchange) → Promise<key | undefined>), so
// NewVerifier({ resolve }) injects it directly.
//
// It ASSEMBLES existing SDK primitives rather than reinventing them:
//   - activeEd25519KeyWithExpiryScreened (wba.ts) — the revocation-aware
//     document-order active-key selector with the not_after to clamp against.
//   - the host-keyed TTL-cache + per-host single-flight shape mirrored from
//     EndpointResolverImpl (wellknown.ts).
//   - the SSRF-guarded fetch seam (http.ts) for the default directory fetcher.
//
// CORE INVARIANT (fail-closed): core.Verifier awaits resolve() with NO try/catch
// (verifier.ts check()), so a throw would fail-CRASH the whole verification batch
// instead of fail-closed-REJECTING the one offer. resolve() therefore NEVER
// throws: every fallible step — the injected fetch, the async selector (its
// thumbprint screening), and the caller-supplied revoked() callback — is wrapped
// so any throw or absence becomes `undefined`. Only a successful selection caches
// and returns a key. TS is fail-closed by ABSENCE (undefined), matching Python's
// absence-from-map — NOT Go's error return. The one exception is a MISSING fetch
// seam, which is a programmer error surfaced at CONSTRUCTION (TypeError), never a
// per-resolve absence — mirroring Go's PanicsWithoutFetch.

import { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import type { OfferKeyResolver } from "../core/verifier.ts";
import { type FetchLike, fetchStrict, guardedFetchFromEnv } from "./http.ts";
import { activeEd25519KeyWithExpiryScreened } from "./wba.ts";

/** A parsed WBA identity directory — the shape the injected fetch seam returns. */
type WBAFile = ReturnType<typeof WBAFileSchema.parse>;

/** The fixed Web Bot Auth directory path the default fetcher GETs. */
export const WBA_OFFER_DIRECTORY_PATH =
	"/.well-known/http-message-signatures-directory";

/** Default per-domain cache TTL (5 min), matching the Go/Python resolver. */
const DEFAULT_TTL_MS = 300_000;

/**
 * OfferDirectoryFetch resolves one exchange domain to its WBA directory, or
 * `undefined` when the directory is unresolvable (unreachable, malformed, blocked).
 * The injected IO seam of the cache: a test injects a directory table with no
 * network, an app wraps its shared well-known fetch. The seam SHOULD contain its
 * own failures as `undefined` rather than throw — but resolve() defends against a
 * throwing seam anyway (Core Invariant), so a hand-rolled fetcher that raises still
 * fails closed. Mirrors Python's `DirectoryFetch` None-absence contract.
 */
export type OfferDirectoryFetch = (
	domain: string,
) => Promise<WBAFile | undefined>;

/** Wires a {@link newCachedOfferKeyResolver}. `fetch` is REQUIRED. */
export interface CachedOfferKeyResolverOptions {
	/** Resolves a domain to its WBA directory. REQUIRED — the factory throws a
	 * TypeError at construction when it is missing (a resolver with no directory
	 * source can never resolve anything). */
	fetch: OfferDirectoryFetch;
	/** Per-domain cache TTL in ms; ≤0/undefined → {@link DEFAULT_TTL_MS}. The stored
	 * entry's expiry is clamped to min(now+ttlMs, not_after). */
	ttlMs?: number;
	/** The cache-freshness + selection clock; undefined → Date.now. Tests inject. */
	now?: () => number;
	/** Screens a candidate key by its RFC 7638 thumbprint — a revoked key is skipped
	 * during selection so a window-active-but-revoked key is never served. undefined
	 * screens nothing; inject a revoked-set predicate on any verification path. A
	 * throwing predicate fails closed (resolve → undefined), never propagates. */
	revoked?: (thumbprint: string) => boolean;
}

/** The public face: the OfferKeyResolver core.Verifier resolves offer keys through. */
export type CachedOfferKeyResolver = OfferKeyResolver;

interface OfferKeyEntry {
	key: Uint8Array<ArrayBuffer>;
	exp: number;
}

/**
 * clampOfferKeyExpiry bounds a cache entry's expiry to the key's validity window:
 * the entry expires at min(nowMs+ttlMs, notAfterMs), so a key is never served past
 * its not_after even within the TTL. A pure helper (all epoch-ms) so the
 * tri-language clamp corpus replays the SAME arithmetic the resolver runs, not a
 * re-inlined copy that could silently drift.
 */
export function clampOfferKeyExpiry(
	nowMs: number,
	ttlMs: number,
	notAfterMs: number,
): number {
	return Math.min(nowMs + ttlMs, notAfterMs);
}

class CachedOfferKeyResolverImpl implements OfferKeyResolver {
	private readonly fetchFn: OfferDirectoryFetch;
	private readonly ttlMs: number;
	private readonly now: () => number;
	private readonly revoked: (thumbprint: string) => boolean;
	private readonly cache = new Map<string, OfferKeyEntry>();
	private readonly flight = new Map<
		string,
		Promise<Uint8Array<ArrayBuffer> | undefined>
	>();

	constructor(opts: CachedOfferKeyResolverOptions) {
		// A missing fetch seam is a programmer error, surfaced at CONSTRUCTION — never
		// a per-resolve fail-closed absence (mirrors Go PanicsWithoutFetch).
		if (typeof opts.fetch !== "function") {
			throw new TypeError(
				"CachedOfferKeyResolver requires a fetch directory seam",
			);
		}
		this.fetchFn = opts.fetch;
		this.ttlMs = opts.ttlMs && opts.ttlMs > 0 ? opts.ttlMs : DEFAULT_TTL_MS;
		this.now = opts.now ?? Date.now;
		this.revoked = opts.revoked ?? (() => false);
	}

	async resolve(
		exchange: string,
	): Promise<Uint8Array<ArrayBuffer> | undefined> {
		const hit = this.cached(exchange);
		if (hit !== undefined) return hit;
		let flight = this.flight.get(exchange);
		if (!flight) {
			flight = this.fetchAndSelect(exchange);
			this.flight.set(exchange, flight);
		}
		try {
			// fetchAndSelect is total (all failures → undefined), so awaiting the flight
			// cannot throw — resolve() upholds the never-throw Core Invariant.
			return await flight;
		} finally {
			this.flight.delete(exchange);
		}
	}

	private cached(exchange: string): Uint8Array<ArrayBuffer> | undefined {
		const entry = this.cache.get(exchange);
		// Miss at or past the (clamped) expiry — hit strictly before it, so a key whose
		// clamped entry expires exactly at not_after is refetched at not_after (and then
		// fails closed, since it is no longer window-active). Matches the Go read check.
		if (!entry || this.now() >= entry.exp) return undefined;
		return entry.key;
	}

	private async fetchAndSelect(
		exchange: string,
	): Promise<Uint8Array<ArrayBuffer> | undefined> {
		try {
			const hit = this.cached(exchange);
			if (hit !== undefined) return hit; // filled while we queued behind the flight
			const dir = await this.fetchFn(exchange);
			if (dir === undefined) return undefined; // unresolvable directory → fail closed
			const nowMs = this.now();
			const selected = await activeEd25519KeyWithExpiryScreened(
				dir,
				nowMs,
				this.revoked,
			);
			if (selected === null) return undefined; // no active, non-revoked key
			// The decoded key bytes are ArrayBuffer-backed at runtime; the selector widens
			// them to ArrayBufferLike, so pin the generic (base64url.ts convention) to
			// satisfy OfferKeyResolver's Uint8Array<ArrayBuffer> contract under tsc --strict.
			const key = selected.key as Uint8Array<ArrayBuffer>;
			const exp = clampOfferKeyExpiry(nowMs, this.ttlMs, selected.notAfter);
			this.cache.set(exchange, { key, exp });
			return key;
		} catch {
			// Core Invariant: ANY throw (fetch seam, async thumbprint screening, or the
			// caller-supplied revoked() callback) fails closed to undefined — never
			// propagates, since core.Verifier awaits resolve() with no try/catch.
			return undefined;
		}
	}
}

/**
 * newCachedOfferKeyResolver builds a domain-keyed offer-key cache implementing
 * OfferKeyResolver. `newX` for family consistency with the sibling resolver
 * factories (newWBAKeyResolver, newWellKnownKeyResolver, …). Throws TypeError when
 * opts.fetch is missing; every other failure fails closed at resolve() time.
 */
export function newCachedOfferKeyResolver(
	opts: CachedOfferKeyResolverOptions,
): CachedOfferKeyResolver {
	return new CachedOfferKeyResolverImpl(opts);
}

/**
 * newWBAOfferDirectoryFetch returns the default {@link OfferDirectoryFetch}: it
 * GETs {scheme}://{domain}[:{port}]{WBA_OFFER_DIRECTORY_PATH} and parses the body
 * as a WBAFile, returning `undefined` on ANY transport/status/decode failure so
 * the default fetcher itself upholds the undefined-not-throw seam contract.
 *
 * The default transport is SSRF-guarded (guardedFetchFromEnv): the exchange domain
 * is signature-covered but attacker-influenceable and the fetch runs before the
 * offer signature is checked, so an unguarded default would be a pre-auth SSRF
 * lever (mirrors Go NewWBADirectoryFetcher). Tests inject a loopback fetch; apps
 * may inject a fetch wrapping their shared well-known client.
 */
export function newWBAOfferDirectoryFetch(
	opts: { fetch?: FetchLike; scheme?: string; port?: string } = {},
): OfferDirectoryFetch {
	const fetchFn = opts.fetch ?? guardedFetchFromEnv();
	const scheme = opts.scheme && opts.scheme !== "" ? opts.scheme : "https";
	const port = opts.port ?? "";
	return async (domain: string) => {
		try {
			const host = port !== "" ? `${domain}:${port}` : domain;
			const body = await fetchStrict(
				fetchFn,
				`${scheme}://${host}${WBA_OFFER_DIRECTORY_PATH}`,
			);
			return WBAFileSchema.parse(JSON.parse(body));
		} catch {
			return undefined;
		}
	};
}
