// sdk/ts framework-agnostic RFC 9421 single-signature SERVER-verify face — the
// verify sibling of core/sign-request.ts and the TS port of sdk/go/connectserver's
// single-sig verify path (verify.go / classify.go over helpers/verify.go +
// sigbase.go). Where hono/middleware.ts::rampVerify is the edge-GET-PoP path
// (2-component, self-verifying, no resolver) and core/verifier.ts is OFFER verify
// (JCS), this is the request-verify a Broker/Exchange built in TS wires behind its
// framework: it parses the inbound Signature-Input/Signature, enforces the RAMP
// required-5 covered set + content-digest + created/expires window, resolves the
// keyid through an INJECTED KeyResolver (the SDK owns no keys), runs the two-phase
// replay check over an INJECTED store (the SDK owns no replay state), reads time
// through an INJECTED clock (the SDK owns no wall clock), and returns a VERDICT
// carrying the reject reason mirroring the Go taxonomy — never throws.
//
// SINGLE-SIG scope only:
// multisig forwarding-chain verify (hop budget, broken_chain) is owned by the
// core/verify-multisig-request.ts sibling.
// The reject reasons this face emits are exactly the two the single-sig surface
// produces (connectserver classify.go RejectReason.String()): "signature" (bad
// sig / expiry / future-created / wrong-or-unresolvable key / tampered covered
// field / missing component — the default) and "replay".

import { decodeBase64Url, utf8Bytes } from "../src/base64url.ts";
import { stdBase64 } from "./sign.ts";
import {
	buildRequestSignatureBase,
	type ChainLink,
	COVERED_COMPONENTS,
	contentDigest,
} from "./sign-request.ts";

/**
 * The classified reject reason (connectserver classify.go RejectReason.String()).
 * SINGLE-SIG surface: "signature" (the default — authenticity/freshness/key/
 * covered-set failures) and "replay". The multisig tokens broken_chain /
 * hop_budget are out of scope here.
 */
export type RejectReason = "signature" | "replay";

/**
 * The injected keyid-keyed verifying-key resolver (ADR-020 §4). Distinct from
 * core/verifier.ts::OfferKeyResolver which is EXCHANGE-keyed for offer verify: a
 * request-verify resolver is keyed by the Signature-Input keyid. Returns the raw
 * 32-byte Ed25519 public key, or undefined when the key is unknown.
 */
export interface RequestKeyResolver {
	resolve(keyid: string | null): Uint8Array<ArrayBuffer> | undefined;
}

/**
 * The injected replay-nonce store (mirrors Go core.ReplayStore). The SDK ships NO
 * default — replay state lives entirely in the injected implementation.
 * `seenNonce` is the read-only first phase; `seenOrAdd` is the commit phase
 * (resolves true if the nonce was already present).
 */
export interface ReplayStore {
	seenNonce(nonce: string): Promise<boolean>;
	seenOrAdd(nonce: string): Promise<boolean>;
}

/** The lowercased request headers a server-verify reads. */
export interface VerifyRequestHeaders {
	"content-digest": string;
	"signature-input": string;
	signature: string;
	/**
	 * The two covered headers whose value may legitimately be EMPTY. Optional so an
	 * ABSENT one is distinguishable from an empty one, which is the whole reason an
	 * empty one is put on the wire: the base is rebuilt from the request that ARRIVED,
	 * so a name the signature covers and the request does not carry cannot be
	 * reconstructed, and defaulting it to "" would invent a value the signer may never
	 * have bound. The oracle draws the same line by reading these with Values rather
	 * than Get. See docs/design-history.md, "A covered header the peer never receives
	 * is not bound".
	 */
	authorization?: string;
	"signature-agent"?: string;
	/**
	 * The entitlement-token header (mirrors Go entitlementHeaderLower). When
	 * present, the covered set MUST commit to it (enforceEntitlementCoverage);
	 * omit/empty when the request carries no entitlement. Format-neutral —
	 * JWT/opaque token; coverage is enforced, contents are not.
	 */
	"x-entitlement-token"?: string;
}

/** Inputs for verifyRequestServer — the request material plus the injected boundary. */
export interface VerifyRequestServerInput {
	method: string;
	url: string;
	body: Uint8Array<ArrayBuffer>;
	headers: VerifyRequestHeaders;
	resolve: RequestKeyResolver;
	/** Omit to disable replay detection (verify-only), matching Go WithReplayStore-absent. */
	replayStore?: ReplayStore;
	/** Injected clock returning unix seconds — verify reads time ONLY through this. */
	now: () => number;
	/**
	 * The per-hop signature-lifetime clamp in SECONDS (mirrors Go
	 * VerifyOptions.MaxSignatureAge). When > 0, a signature whose declared window
	 * (expires − created) EXCEEDS this is rejected as "signature"; the bound is
	 * inclusive (a window exactly equal to it is accepted). 0/undefined = unbounded.
	 */
	maxSignatureAge?: number;
}

/** The returned verdict: valid, or invalid with the classified reason. */
export interface VerifyVerdict {
	valid: boolean;
	reason?: RejectReason;
}

// A created timestamp may not lead the verifier clock by more than this
// (mirrors Go helpers.defaultMaxFutureSkew = 300s).
const MAX_FUTURE_SKEW_SEC = 300;

// The RAMP required covered set, lowercased (mirrors Go requiredCoveredComponents).
const REQUIRED_COVERED: ReadonlySet<string> = new Set(COVERED_COMPONENTS);

// The entitlement-token header in covered-component (lowercased) form
// (mirrors Go entitlementHeaderLower). When the request carries this header the
// signature's covered set MUST commit to it; absent → no constraint.
const ENTITLEMENT_COVERED = "x-entitlement-token";

const REASON_SIGNATURE: RejectReason = "signature";
const REASON_REPLAY: RejectReason = "replay";

const reject = (reason: RejectReason): VerifyVerdict => ({
	valid: false,
	reason,
});
const accept: VerifyVerdict = { valid: true };

interface ParsedInput {
	/** Verbatim inner-list + params tail after `label=` — the base @signature-params value. */
	rawParams: string;
	covered: Set<string>;
	keyid: string | null;
	alg: string | null;
	created?: number;
	expires?: number;
}

/**
 * Parse `label=("c1" "c2" ...);keyid="..";alg="..";created=..;expires=..` — a
 * minimal RFC 8941-shaped parser for the SINGLE-SIG surface (one label, the RAMP
 * covered set, string-valued keyid/alg). It keeps the VERBATIM params tail so the
 * verify base terminates with the signer's exact @signature-params bytes (Go
 * RawInner), never a re-rendering.
 */
function parseSignatureInput(raw: string): ParsedInput | undefined {
	const eq = raw.indexOf("=");
	if (eq < 0) return undefined;
	const rawParams = raw.slice(eq + 1).trim();
	const open = rawParams.indexOf("(");
	const close = rawParams.indexOf(")");
	if (open !== 0 || close < 0) return undefined;
	const inner = rawParams.slice(open + 1, close);
	const covered = new Set(
		[...inner.matchAll(/"([^"]*)"/g)].map((m) => (m[1] ?? "").toLowerCase()),
	);
	const tail = rawParams.slice(close + 1);
	const keyid = matchQuoted(tail, /;keyid="([^"]*)"/);
	const alg = matchQuoted(tail, /;alg="([^"]*)"/);
	const created = matchInt(tail, /;created=(\d+)/);
	const expires = matchInt(tail, /;expires=(\d+)/);
	return {
		rawParams,
		covered,
		keyid,
		alg,
		...(created !== undefined ? { created } : {}),
		...(expires !== undefined ? { expires } : {}),
	};
}

function matchQuoted(s: string, re: RegExp): string | null {
	const m = s.match(re);
	return m ? (m[1] ?? "") : null;
}

function matchInt(s: string, re: RegExp): number | undefined {
	const m = s.match(re);
	return m ? Number(m[1]) : undefined;
}

/** Parse the RFC 9421 `Signature` header value `label=:<STANDARD-base64>:`. */
function parseSignatureBytes(raw: string): Uint8Array<ArrayBuffer> | undefined {
	const first = raw.indexOf(":");
	const last = raw.lastIndexOf(":");
	if (first < 0 || last <= first) return undefined;
	return decodeBase64Url(raw.slice(first + 1, last));
}

// The replay nonce mirrors connectserver.replayNonce: keyid + NUL +
// STANDARD-base64(signature bytes), so neither part can forge the boundary and
// the value is independent of incidental wire whitespace.
function replayNonce(keyid: string, sigBytes: Uint8Array<ArrayBuffer>): string {
	return `${keyid}\u0000${stdBase64(sigBytes)}`;
}

export async function ed25519Verify(
	pub: Uint8Array<ArrayBuffer>,
	sig: Uint8Array<ArrayBuffer>,
	message: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
	try {
		const key = await crypto.subtle.importKey(
			"raw",
			pub,
			{ name: "Ed25519" },
			false,
			["verify"],
		);
		return await crypto.subtle.verify("Ed25519", key, sig, message);
	} catch {
		return false;
	}
}

/** The request-level covered fields shared across every hop of a request. */
export interface RequestVerifyFields {
	method: string;
	url: string;
	digestHeader: string;
	authorization: string;
	signatureAgent: string;
	body: Uint8Array<ArrayBuffer>;
	/**
	 * The entitlement-token header value (empty/undefined when absent). When
	 * non-empty, enforceEntitlementCoverage requires the covered set to commit to
	 * "x-entitlement-token" — an entitlement token cannot be slipped under an
	 * otherwise-valid signature.
	 */
	entitlementHeader?: string;
}

/** The parsed per-signature params the verify core judges (one hop). */
export interface ParsedSignatureParams {
	/** Verbatim inner-list + params tail — the base @signature-params value. */
	rawParams: string;
	covered: ReadonlySet<string>;
	keyid: string | null;
	alg: string | null;
	created?: number;
	expires?: number;
}

/**
 * The per-signature verify core shared by the single-sig and multisig paths
 * (mirrors Go verifySingleSignature, MINUS replay): alg + required
 * covered set + created/expires window + content-digest + key resolution +
 * Ed25519 over the reconstructed base. Returns true iff the signature is authentic
 * and policy-valid. `chainLink`, when present, inserts the forwarding-chain base
 * line for a chained hop (sigN, N>1). NO replay — the caller owns that so the
 * multisig loop never touches a ReplayStore. `maxSignatureAge` (seconds, mirrors
 * Go VerifyOptions.MaxSignatureAge) clamps the declared lifetime per hop: when
 * > 0 a window (expires − created) EXCEEDING it is rejected; 0/undefined =
 * unbounded, and the bound is inclusive.
 */
export async function verifyParsedSignature(
	fields: RequestVerifyFields,
	parsed: ParsedSignatureParams,
	sigBytes: Uint8Array<ArrayBuffer> | undefined,
	resolve: RequestKeyResolver,
	nowSec: number,
	chainLink?: ChainLink,
	maxSignatureAge?: number,
): Promise<boolean> {
	if (parsed.keyid === null) return false;
	if (parsed.alg === null || parsed.alg.toLowerCase() !== "ed25519") return false;
	for (const need of REQUIRED_COVERED) {
		if (!parsed.covered.has(need)) return false;
	}
	// Entitlement coverage (mirrors Go enforceEntitlementCoverage, run right after
	// enforceRequiredComponents): iff the request carries the entitlement-token
	// header, the covered set MUST commit to it; absent → no constraint.
	if (fields.entitlementHeader && !parsed.covered.has(ENTITLEMENT_COVERED)) {
		return false;
	}
	if (parsed.created === undefined || parsed.expires === undefined) return false;
	if (parsed.expires < nowSec) return false;
	if (parsed.created > nowSec + MAX_FUTURE_SKEW_SEC) return false;
	// Lifetime clamp (mirrors Go enforceCreatedExpires MaxSignatureAge): reject a
	// declared window longer than the verifier allows. 0/undefined = unbounded;
	// the bound is inclusive (strictly-greater is rejected).
	if (
		maxSignatureAge !== undefined &&
		maxSignatureAge > 0 &&
		parsed.expires - parsed.created > maxSignatureAge
	) {
		return false;
	}

	const expectedDigest = await contentDigest(fields.body);
	if (fields.digestHeader.trim() !== expectedDigest) return false;
	if (!sigBytes) return false;

	const pub = resolve.resolve(parsed.keyid);
	if (!pub || pub.length !== 32) return false;

	const base = buildRequestSignatureBase(
		{
			method: fields.method,
			url: fields.url,
			digestHeader: fields.digestHeader,
			authorization: fields.authorization,
			signatureAgent: fields.signatureAgent,
		},
		parsed.rawParams,
		chainLink,
	);
	return ed25519Verify(pub, sigBytes, utf8Bytes(base));
}

/**
 * Verify an inbound single-signature RAMP request; return a reason-tagged verdict.
 *
 * Mirrors the Go connectserver single-sig verify order: required covered-set →
 * created/expires window → content-digest → key resolution → Ed25519 check over
 * the reconstructed base → two-phase replay. Every authenticity/freshness/key/
 * covered-set failure collapses to "signature" (the Go default branch); a replayed
 * nonce is "replay". Keys resolve ONLY through `resolve`; replay state lives ONLY
 * in `replayStore` when supplied; time is read ONLY through `now`.
 */
export async function verifyRequestServer(
	input: VerifyRequestServerInput,
): Promise<VerifyVerdict> {
	// ABSENT is not EMPTY. See the header type for why the distinction is the whole
	// point of putting an empty covered header on the wire.
	if (
		input.headers.authorization === undefined ||
		input.headers["signature-agent"] === undefined
	) {
		return reject(REASON_SIGNATURE);
	}
	const parsed = parseSignatureInput(input.headers["signature-input"]);
	if (!parsed) return reject(REASON_SIGNATURE);

	const nowSec = Math.floor(input.now());
	const sigBytes = parseSignatureBytes(input.headers.signature);

	// The full per-signature core (covered set / window / digest / key / Ed25519),
	// shared with the multisig path; replay stays here so the multisig loop never
	// touches a ReplayStore.
	const ok = await verifyParsedSignature(
		{
			method: input.method,
			url: input.url,
			digestHeader: input.headers["content-digest"],
			authorization: input.headers.authorization,
			signatureAgent: input.headers["signature-agent"],
			body: input.body,
			...(input.headers["x-entitlement-token"]
				? { entitlementHeader: input.headers["x-entitlement-token"] }
				: {}),
		},
		parsed,
		sigBytes,
		input.resolve,
		nowSec,
		undefined,
		input.maxSignatureAge,
	);
	if (!ok || parsed.keyid === null || !sigBytes) return reject(REASON_SIGNATURE);

	if (input.replayStore) {
		// Two-phase (read-only Seen, then SeenOrAdd) mirrors connectserver.verify so a
		// part-way rejection never burns the nonce (single-sig: one signature).
		const nonce = replayNonce(parsed.keyid, sigBytes);
		if (await input.replayStore.seenNonce(nonce)) return reject(REASON_REPLAY);
		if (await input.replayStore.seenOrAdd(nonce)) return reject(REASON_REPLAY);
	}

	return accept;
}
