// sdk/ts/core — the transport-neutral L2 core (Verifier + {verified, rejected} +
// the unforgeable VerifiedOffer). Mirror of sdk/go/core, translated to idiomatic
// TS. It imposes NOTHING beyond the WHATWG Fetch/WebCrypto web standard — no Hono,
// no Connect-ES. Framework bindings (sdk/ts/hono) depend one-directionally on this
// core, never the reverse.
//
// The Verifier splits received offers into {verified, rejected} by ed25519-
// verifying the canonical offer signature. Per the JCS switch (ADR-020 §4), the
// signed payload is RFC 8785 JCS over the canonical proto-JSON of the offer with
// signature/signature_algorithm cleared:
//
//     signed_payload = JCS(protojson(offer with sig+alg cleared))
//
// so the core reproduces the exact signed bytes without a protobuf binary codec.
//
// VerifiedOffer is a BRANDED/opaque type: it carries a module-private Symbol tag
// that only this core's verify path (or RejectedOffer.unsafe()) can stamp, so an
// application cannot forge one with an object literal and slip it into
// execute(offer: VerifiedOffer). That is the TS analogue of the Go compile guard
// (unexported field + no exported constructor).

import canonicalize from "canonicalize";

import { utf8Bytes } from "../src/base64url.ts";

// OFFER_SIGNATURE_ALGORITHM is the JOSE/JWA algorithm identifier advertised on
// signed offers. Always
// EdDSA for Ed25519 (mirror helpers.OfferSignatureAlgorithm).
export const OFFER_SIGNATURE_ALGORITHM = "EdDSA";

// Mode selects offer-verification strictness. "strict" (the default) is
// fail-closed: an offer that does not verify against the exchange's offer-signing
// key lands in rejected and cannot reach execute. "off" is the single, loud,
// named opt-out — it surfaces every offer as verified WITHOUT checking a signature.
export type Mode = "strict" | "off";

/**
 * OfferKeyResolver resolves an exchange identity to its raw 32-byte Ed25519
 * offer-signing public key. Injected — the core owns no key state. Returns
 * undefined when no key is known for the exchange (→ fail-closed reject under
 * strict).
 */
export interface OfferKeyResolver {
	resolve(exchange: string): Promise<Uint8Array<ArrayBuffer> | undefined>;
}

/**
 * Ed25519 verify primitive: (publicKey, signature, message) -> valid?. Injected
 * so a non-WebCrypto runtime can supply its own without changing the byte
 * contract. Defaults to WebCrypto crypto.subtle. Byte params are
 * `Uint8Array<ArrayBuffer>` (never SharedArrayBuffer-backed) so the default can
 * hand them to WebCrypto's BufferSource without casts.
 */
export type Ed25519Verify = (
	publicKey: Uint8Array<ArrayBuffer>,
	signature: Uint8Array<ArrayBuffer>,
	message: Uint8Array<ArrayBuffer>,
) => Promise<boolean>;

// The module-private brand. Only code in this module can read/stamp it, so a
// VerifiedOffer cannot be fabricated outside the core's verify path.
const VERIFIED_BRAND: unique symbol = Symbol("ramp.core.VerifiedOffer");

/**
 * VerifiedOffer wraps an offer that passed the core's fail-closed verification
 * (genuine exchange signature, not expired) — OR was surfaced under mode "off" /
 * RejectedOffer.unsafe(). The brand is module-private, so `execute(offer:
 * VerifiedOffer)` accepts only offers the core minted: an app cannot construct one
 * with an object literal (tsc rejects the missing brand). Reading the wrapped
 * offer is fine; only MINTING one is gated.
 */
export interface VerifiedOffer {
	readonly [VERIFIED_BRAND]: true;
	readonly offer: unknown;
}

/**
 * RejectedOffer is an offer the Verifier could NOT accept: the wrapped offer plus
 * the reason it failed. It is VISIBLE (the app learns which offers failed and why)
 * but not directly executable — acting on it requires the explicit .unsafe()
 * escape.
 */
export interface RejectedOffer {
	readonly offer: unknown;
	readonly reason: string;
	/** The single, audit-visible escape hatch: mint an executable VerifiedOffer. */
	unsafe(): VerifiedOffer;
}

/**
 * Result is the fail-closed {verified, rejected} contract every discover/resolve
 * call returns. Neither list is silently dropped. Canonical cross-language shape
 * (mirror sdk/go core.Result).
 */
export interface Result {
	verified: VerifiedOffer[];
	rejected: RejectedOffer[];
}

// The shape both discovery verbs return.
//
// A discovery call is per-URI: an agent asks about several resources at once and the
// answer comes back grouped, one group per requested URI, each either carrying offers or
// carrying a typed reason it carries none. A flat list cannot express that. It has
// nowhere to put the reason, and a refused URI vanishes entirely — its group holds no
// offer, so nothing survives to say which resource was refused or why.
//
// That distinction is the point of the vocabulary: "not in the catalogue" means give up,
// "scope insufficient" means acquire an entitlement and retry, and "content blocked"
// means never retry. Flattened, all three read as "found nothing".
//
// The fail-closed {verified, rejected} split is preserved inside each group, through the
// same Verifier — not a second verification path.

/**
 * OfferGroupResult is one requested URI's answer (mirror sdk/go core.OfferGroupResult).
 *
 * `absenceReason` is undefined when the responder stated no reason — a legitimate
 * answer, not an omission: where the existence of a resource must itself stay hidden, a
 * responder MAY withhold the reason rather than confirm the resource exists. The Go
 * oracle keeps a pointer to tell that apart from the unspecified enum value; here the
 * generated enums carry no `*_UNSPECIFIED` member at all, so a present value is always a
 * real reason and undefined is the only way to say nothing.
 */
export interface OfferGroupResult {
	readonly uri: string;
	readonly result: Result;
	readonly absenceReason?: string;
	readonly discoveryMethod?: string;
	/**
	 * The restriction axes that drove a convenience pre-filter, when the absence reason
	 * is a restriction filter. Advisory diagnostics, not an enforcement verdict — but
	 * they tell an agent which axis to vary on a retry.
	 */
	readonly restrictionFilters: string[];
}

/** DiscoveryResult is what discover and resolve return (mirror sdk/go core.DiscoveryResult). */
export interface DiscoveryResult {
	/** One entry per requested URI, in the order the responder returned. */
	readonly groups: OfferGroupResult[];
	/**
	 * Why the CALL as a whole yielded nothing. Set only on that path — when any group
	 * carries offers it stays undefined, and the per-URI causes ride on each group
	 * instead. Only a Broker resolve can set it: an Exchange's own discovery response has
	 * no whole-call reason field.
	 */
	readonly absenceReason?: string;
	/**
	 * Canonical domain of the responding Exchange. Empty from a Broker resolve, whose
	 * response names no single Exchange — each offer carries its own issuing domain.
	 */
	readonly exchange: string;
	/**
	 * The caller's rate-limit standing, when the responder reported it, so an agent can
	 * throttle before a fan-out meets a hard limit. Undefined from a Broker resolve.
	 */
	readonly rateLimit?: Record<string, unknown>;
}

/**
 * Every verified offer across all groups, for a caller that does not care which URI an
 * offer answers.
 *
 * A free function rather than a method, unlike the Go and Python faces: DiscoveryResult
 * here is a plain record — what the client hands back after parsing — and putting
 * methods on the interface would force every hand-built literal to supply them. Same
 * contract, spelled the way this language spells it.
 *
 * A convenience over `groups`, never a substitute. A URI that was REFUSED contributes
 * nothing here — it has no offer to contribute — so a caller reading only this cannot
 * tell a refusal from a resource it never asked about. That is exactly the information
 * `groups` exists to keep.
 */
export function verifiedOffers(result: DiscoveryResult): VerifiedOffer[] {
	return result.groups.flatMap((g) => g.result.verified);
}

/**
 * Every rejected offer across all groups, with the reason each failed. The same caveat as
 * {@link verifiedOffers} applies: a URI that yielded no offers at all is not a rejection
 * and appears only in `groups`.
 */
export function rejectedOffers(result: DiscoveryResult): RejectedOffer[] {
	return result.groups.flatMap((g) => g.result.rejected);
}

// mintVerified is the SOLE constructor of a branded VerifiedOffer, module-private.
function mintVerified(offer: unknown): VerifiedOffer {
	return { [VERIFIED_BRAND]: true, offer };
}

function makeRejected(offer: unknown, reason: string): RejectedOffer {
	return { offer, reason, unsafe: () => mintVerified(offer) };
}

/** Runtime brand check — a plain object cannot carry the module-private Symbol. */
export function isVerifiedOffer(value: unknown): value is VerifiedOffer {
	return (
		typeof value === "object" &&
		value !== null &&
		(value as Record<PropertyKey, unknown>)[VERIFIED_BRAND] === true
	);
}

const defaultVerifyEd25519: Ed25519Verify = async (pubkey, sig, message) => {
	try {
		const key = await crypto.subtle.importKey(
			"raw",
			pubkey,
			{ name: "Ed25519" },
			false,
			["verify"],
		);
		return await crypto.subtle.verify("Ed25519", key, sig, message);
	} catch {
		return false;
	}
};

// stringOr returns a wire string, or the fallback. A responder that sent the wrong JSON
// type for an enum or a URI has said nothing usable, and reading it as its own text
// would put an unvalidated value where a typed reason belongs.
function stringOr<T extends string | undefined>(
	value: unknown,
	fallback: T,
): string | T {
	return typeof value === "string" ? value : fallback;
}

// stringList returns the string members of a wire array; anything else contributes
// nothing.
function stringList(value: unknown): string[] {
	return Array.isArray(value)
		? value.filter((v): v is string => typeof v === "string")
		: [];
}

// hexToBytes decodes a hex string (the Offer.signature encoding) to bytes.
//
// Strict about what a hex digit is. Number.parseInt accepts a sign, leading whitespace and
// a trailing tail — "-1", "+f" and " a" all produce a number — so a signature carrying any
// of them would decode to bytes rather than being refused, where Go's hex.DecodeString and
// Python's bytes.fromhex refuse it. The value comes from a peer, so the three languages
// have to agree on what is a signature and what is garbage.
const HEX_PAIR = /^[0-9a-fA-F]{2}$/;

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> | undefined {
	if (hex.length % 2 !== 0) return undefined;
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i += 1) {
		const pair = hex.slice(i * 2, i * 2 + 2);
		if (!HEX_PAIR.test(pair)) return undefined;
		out[i] = Number.parseInt(pair, 16);
	}
	return out;
}

/**
 * canonicalOfferPayload reproduces the signed bytes: clear signature +
 * signature_algorithm from the offer's canonical proto-JSON, then apply RFC 8785
 * JCS. MUST stay byte-identical to the Go oracle (helpers.CanonicalOfferBytes).
 * The offer is already canonical proto-JSON (snake_case, enums-as-names,
 * omit-unpopulated) — the core only clears the two signature fields and re-JCS-es.
 */
export function canonicalOfferPayload(
	offer: Record<string, unknown>,
): Uint8Array<ArrayBuffer> {
	const stripped: Record<string, unknown> = { ...offer };
	delete stripped.signature;
	delete stripped.signature_algorithm;
	const jcs = canonicalize(stripped);
	if (jcs === undefined)
		throw new Error("ramp/core: offer is not JSON-serializable");
	return utf8Bytes(jcs);
}

/**
 * Verifier runs the per-offer authenticity + freshness check, keyed through the
 * injected KeyResolver. It is PURE apart from the resolver IO — no state, no clock
 * beyond the injected now. Transport-neutral: any Fetch/WebCrypto consumer composes
 * it directly, without any framework binding.
 */
export class Verifier {
	constructor(
		private readonly mode: Mode,
		private readonly resolver: OfferKeyResolver,
		private readonly now: () => number,
		private readonly verifyEd25519: Ed25519Verify,
	) {}

	/**
	 * sort splits offers into verified and rejected per the configured mode. Under
	 * "off" every offer is surfaced verified with no check. Under "strict" each offer
	 * is verified against its resolved exchange key and its expiry — a failure of
	 * either lands it in rejected with the reason.
	 */
	async sort(offers: unknown[]): Promise<Result> {
		const result: Result = { verified: [], rejected: [] };
		for (const offer of offers) {
			if (this.mode === "off") {
				result.verified.push(mintVerified(offer));
				continue;
			}
			const reason = await this.check(offer);
			if (reason === undefined) {
				result.verified.push(mintVerified(offer));
			} else {
				result.rejected.push(makeRejected(offer, reason));
			}
		}
		return result;
	}

	/**
	 * sortGroups verifies every group's offers through THIS Verifier and returns the
	 * per-URI results, preserving each group's URI and its typed reasons (mirror sdk/go
	 * `Verifier.SortGroups`).
	 *
	 * One Verifier sorts every group deliberately: it is stateless apart from the
	 * injected resolver and clock, so a fresh one per group would mean N resolver caches
	 * and N clock readings for a single logical answer.
	 *
	 * A non-object element is SKIPPED rather than surfaced as an empty URI: it is not a
	 * group with no offers, it is nothing at all, and inventing an answer the responder
	 * never gave is worse than dropping a malformed one.
	 */
	async sortGroups(groups: readonly unknown[]): Promise<OfferGroupResult[]> {
		const out: OfferGroupResult[] = [];
		for (const group of groups) {
			if (typeof group !== "object" || group === null || Array.isArray(group)) {
				continue;
			}
			const rec = group as Record<string, unknown>;
			const offers = rec["offers"];
			// The two optional reasons are OMITTED when the responder gave none, rather
			// than set to undefined: under exactOptionalPropertyTypes those are different
			// facts, and "the responder said nothing" is the one being preserved.
			const absenceReason = stringOr(rec["absence_reason"], undefined);
			const discoveryMethod = stringOr(rec["discovery_method"], undefined);
			out.push({
				uri: stringOr(rec["uri"], ""),
				result: await this.sort(Array.isArray(offers) ? offers : []),
				...(absenceReason !== undefined ? { absenceReason } : {}),
				...(discoveryMethod !== undefined ? { discoveryMethod } : {}),
				restrictionFilters: stringList(rec["restriction_filters"]),
			});
		}
		return out;
	}

	// check verifies a single offer: resolve the exchange offer-signing key, verify
	// the JCS signature, and enforce the not-in-the-past expiry. Any step failing
	// rejects the offer (fail-closed) — including an unresolvable key.
	private async check(offer: unknown): Promise<string | undefined> {
		if (typeof offer !== "object" || offer === null)
			return "offer is not an object";
		const rec = offer as Record<string, unknown>;
		const exchange = typeof rec.exchange === "string" ? rec.exchange : "";
		// A resolver that THROWS rejects this offer and nothing else. The shipped
		// resolvers raise on a network failure, and on a Broker fan-out the exchange comes
		// off a relayed offer — so one Exchange whose key endpoint hangs would otherwise
		// deny the agent every offer in the response, as an untyped exception out of a
		// call that promises a typed one. Go returns the resolver's error as this offer's
		// rejection reason and moves on.
		let pub: Uint8Array<ArrayBuffer> | undefined;
		try {
			pub = await this.resolver.resolve(exchange);
		} catch (cause) {
			return `no offer-signing key for exchange ${JSON.stringify(exchange)}: ${
				cause instanceof Error ? cause.message : String(cause)
			}`;
		}
		if (!pub)
			return `no offer-signing key for exchange ${JSON.stringify(exchange)}`;

		const sigHex = typeof rec.signature === "string" ? rec.signature : "";
		const sig = hexToBytes(sigHex);
		if (!sig) return "offer signature is not valid hex";

		const payload = canonicalOfferPayload(rec);
		const valid = await this.verifyEd25519(pub, sig, payload);
		if (!valid) return "offer signature invalid";

		if (this.expired(rec)) return "offer expires_at is in the past";
		return undefined;
	}

	// expired mirrors the Go oracle (core.Verifier.expired), fail-closed: an offer
	// with no expires_at, or one whose expires_at cannot be parsed, is treated as
	// EXPIRED — RAMP offers are minted now+TTL, so a missing/broken bound is
	// malformed bearer state, never an eternal grant. A present bound is inclusive
	// at now (strictly-before is expired). The wire form is UTC, so an offset-less
	// instant is read as UTC, not host-local.
	private expired(rec: Record<string, unknown>): boolean {
		const expiresAt = rec.expires_at;
		if (typeof expiresAt !== "string") return true;
		const ms = parseUtcMillis(expiresAt);
		if (Number.isNaN(ms)) return true;
		return ms < this.now();
	}
}

// parseUtcMillis parses an RFC 3339 instant as UTC epoch-millis. An instant with
// no timezone designator (no trailing Z / ±hh:mm) is read as UTC — the protobuf
// Timestamp wire form is always UTC — rather than host-local, which is what
// Date.parse would silently assume and which diverges from Go/Python.
function parseUtcMillis(s: string): number {
	const hasTz = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(s);
	return Date.parse(hasTz ? s : `${s}Z`);
}

/** Options for createVerifier (all injected — the core owns no state). */
export interface VerifierOptions {
	resolve: (exchange: string) => Promise<Uint8Array<ArrayBuffer> | undefined>;
	now: () => number;
	verifyEd25519?: Ed25519Verify;
}

/**
 * createVerifier is the transport-neutral constructor. Mirror of sdk/go
 * core.NewVerifier: the verification mode, offer KeyResolver, and clock are all
 * injected; the Ed25519 primitive defaults to WebCrypto.
 */
export function createVerifier(mode: Mode, opts: VerifierOptions): Verifier {
	const resolver: OfferKeyResolver = { resolve: opts.resolve };
	return new Verifier(
		mode,
		resolver,
		opts.now,
		opts.verifyEd25519 ?? defaultVerifyEd25519,
	);
}
