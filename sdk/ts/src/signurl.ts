// sdk/ts Ed25519 signed delivery-URL SIGN face — the Exchange-minting
// sibling of src/verify.ts. Mirror of the Go oracle helpers.SignURLEd25519.
//
// THE CONTRACT: the signature covers "GET\n<url>" as
// OPAQUE URL BYTES. Neither signer nor verifier re-normalizes scheme/host/path —
// a mixed-case host, an explicit default port, and a raw space or percent in the
// path are all preserved verbatim. The ONLY transform is deterministic query
// handling (add exp/kid/agent_id, remove sig, sort the query). This is why the
// canonical string is built by splitting the raw URL at its first "?" and keeping
// the prefix byte-for-byte, rather than round-tripping through `new URL()` (which
// WHATWG-lowercases the host, strips :443, and re-escapes the path).
//
// The query is re-encoded to match Go's url.Values.Encode() byte-for-byte
// (sort by key, space -> "+", unreserved A-Za-z0-9-._~ kept, everything else
// %XX uppercase) so the three SDKs produce identical bytes — see canonicalUrl.

import { encodeBase64Url, utf8Bytes } from "./base64url.ts";
import { opaqueUrl } from "./opaque-url.ts";

const SIG_PARAM = "sig";
const EXP_PARAM = "exp";
const KID_PARAM = "kid";
const AGENT_ID_PARAM = "agent_id";

/** Signed-URL sign inputs. An empty agentId yields a bearer (unbound) URL; an
 * empty kid omits the kid param — mirror the Go signer's conditional sets. */
export interface SignUrlParams {
	kid: string;
	agentId: string;
	expUnix: number;
}

/**
 * signEd25519SignedUrl signs `source` with `privateKey`, embedding exp (and kid
 * when set, agent_id when set) plus the base64url-no-pad signature over
 * "GET\n<url>". The URL is signed as OPAQUE BYTES — scheme/host/path are
 * preserved verbatim; only the query is deterministically re-encoded. The emitted
 * string is byte-identical to the Go oracle (helpers.SignURLEd25519).
 */
export async function signEd25519SignedUrl(
	source: string,
	params: SignUrlParams,
	privateKey: CryptoKey,
): Promise<string> {
	// Coerce a URL-like source (a Fastly Compute request URL object) to its opaque
	// string form ONCE at the boundary; canonicalUrl needs string ops. No-op for
	// string callers (verbatim bytes preserved).
	const src = opaqueUrl(source);
	const unsigned = canonicalUrl(src, (pairs) => {
		setParam(pairs, EXP_PARAM, String(params.expUnix));
		if (params.kid !== "") setParam(pairs, KID_PARAM, params.kid);
		if (params.agentId !== "") setParam(pairs, AGENT_ID_PARAM, params.agentId);
	});
	const sig = new Uint8Array(
		await crypto.subtle.sign("Ed25519", privateKey, utf8Bytes(`GET\n${unsigned}`)),
	);
	const sigParam = encodeBase64Url(sig);
	return canonicalUrl(unsigned, (pairs) => setParam(pairs, SIG_PARAM, sigParam));
}

/**
 * canonicalUrl builds the URL whose bytes the signature covers: the raw prefix
 * (scheme+host+path, VERBATIM) plus the deterministically re-encoded query. It
 * drops sig, applies `mutate`, sorts, and re-encodes. Shared by the sign face
 * (here) and the verify face (verify.ts::canonicalMessage) so both agree on the
 * byte contract by construction. Exported for that reuse only.
 */
export function canonicalUrl(
	rawUrl: string,
	mutate?: (pairs: Array<[string, string]>) => void,
): string {
	const q = rawUrl.indexOf("?");
	const prefix = q >= 0 ? rawUrl.slice(0, q) : rawUrl;
	const rawQuery = q >= 0 ? rawUrl.slice(q + 1) : "";
	const pairs = parseQueryPairs(rawQuery).filter(([k]) => k !== SIG_PARAM);
	mutate?.(pairs);
	const encoded = encodeQuery(pairs);
	return encoded === "" ? prefix : `${prefix}?${encoded}`;
}

/** setParam overwrites an existing key in place (preserving order) or appends. */
function setParam(pairs: Array<[string, string]>, key: string, value: string): void {
	const existing = pairs.find(([k]) => k === key);
	if (existing) existing[1] = value;
	else pairs.push([key, value]);
}

/** parseQueryPairs splits a raw query into ordered [key, value] pairs, decoding
 * each side exactly as Go's url.ParseQuery (a "+" decodes to a space). */
function parseQueryPairs(rawQuery: string): Array<[string, string]> {
	if (rawQuery === "") return [];
	const out: Array<[string, string]> = [];
	for (const part of rawQuery.split("&")) {
		if (part === "") continue;
		const eq = part.indexOf("=");
		const key = eq >= 0 ? part.slice(0, eq) : part;
		const value = eq >= 0 ? part.slice(eq + 1) : "";
		out.push([queryUnescape(key), queryUnescape(value)]);
	}
	return out;
}

/** encodeQuery serializes pairs byte-identically to Go's url.Values.Encode():
 * sort by key (stable per-key value order), escape each side, join "k=v&k=v". */
function encodeQuery(pairs: Array<[string, string]>): string {
	const sorted = [...pairs].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
	return sorted.map(([k, v]) => `${queryEscape(k)}=${queryEscape(v)}`).join("&");
}

/** Go url.QueryUnescape: "+" -> space, "%XX" -> byte, then UTF-8 decode. */
function queryUnescape(s: string): string {
	return decodeURIComponent(s.replaceAll("+", " "));
}

/** Go url.QueryEscape: unreserved A-Za-z0-9-._~ kept, space -> "+", everything
 * else percent-encoded uppercase (UTF-8). decodeURIComponent/encodeURIComponent
 * keep a slightly wider unreserved set (!'()*), so post-process those to match. */
function queryEscape(s: string): string {
	const encoded = encodeURIComponent(s)
		.replaceAll("%20", "+")
		.replaceAll("!", "%21")
		.replaceAll("'", "%27")
		.replaceAll("(", "%28")
		.replaceAll(")", "%29")
		.replaceAll("*", "%2A");
	return encoded;
}
