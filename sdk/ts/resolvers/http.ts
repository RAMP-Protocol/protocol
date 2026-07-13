// The one HTTP transport seam the fetching resolvers share. Transport-neutral
// per the SDK dependency policy (the resolvers accept an injected fetch-compatible
// callable) but the DEFAULT transport now runs on a maintained HTTP client
// (undici) instead of a hand-rolled node:http request. undici owns the response
// state machine — status, redirects, 1xx, decompression — so this module owns
// only the SSRF guard (an injectable connection-level connector) and the
// fail-closed status→body taxonomy. Integration tests / on-prem deployments that
// must reach a private origin inject their own FetchLike (the escape hatch).

import { lookup as dnsLookup } from "node:dns/promises";

import {
	Agent,
	buildConnector,
	type Dispatcher,
	interceptors,
	request as undiciRequest,
} from "undici";

import { DirectoryUnavailable } from "./errors.ts";
import { allowedScheme, blockedAddress, MAX_REDIRECTS } from "./ssrf.ts";

/** The minimal response shape the resolvers read — a structural subset of the
 * WHATWG `Response`, so the global `fetch` (and undici's) satisfies it. */
export interface FetchResponse {
	status: number;
	text(): Promise<string>;
}

/** An injected HTTP GET. Defaults to the SSRF-guarded transport (guardedFetch). */
export type FetchLike = (url: string) => Promise<FetchResponse>;

/** Bounds the guarded default transport's GET so a slow origin cannot pin a
 * Resolve call or the poller (Go: defaultWBAHTTPTimeout). */
const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
/** Well-known documents are small; bound the body read (Go: maxDocBytes). */
const MAX_DOC_BYTES = 1 << 20; // 1 MiB

/** An SSRF error surfaced when the guarded transport refuses to dial a target.
 * fetchStrict/fetchSoft see it as an ordinary transport failure (fail-closed
 * DirectoryUnavailable / best-effort undefined), so the guard never resolves a
 * blocked host as a valid — merely empty — directory. */
export class SsrfBlockedError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SsrfBlockedError";
	}
}

/** The GENERIC dial-refusal the guard raises for EVERY refuse reason — an
 * unresolvable host, an empty resolution, or a resolved-reserved address all yield
 * the SAME message. It names only the caller-supplied host (already known to the
 * caller), never the resolved IP, and does not distinguish an NXDOMAIN from a
 * resolved-private answer, so it cannot serve as a pre-auth DNS oracle against
 * internal networks. Identical wording across the three SDKs. */
function ssrfRefusal(host: string): SsrfBlockedError {
	return new SsrfBlockedError(`SSRF guard: refusing to dial ${host}`);
}

/** An SSRF-guarded undici connector, injectable into any undici Dispatcher.
 *
 * DX: `new Agent({ connect: ssrfGuard() })`. The guard runs at the CONNECTION
 * (dial) seam — the only place the DNS-REBINDING window is actually closed: it
 * resolves the host, checks EVERY resolved address against blockedAddress, and
 * pins the dial to a checked IP literal (undici does not re-resolve it), while
 * the TLS `servername` keeps the original hostname so cert/SNI validation is
 * unaffected. Because undici re-dials every followed redirect through the same
 * connector, each redirect hop is re-vetted too (consistent with the Go and
 * Python guards); a redirect into a non-http(s) scheme is a WHATWG-fetch network
 * error, so the scheme allowlist is deny-by-default without a redirect handler. */
export function ssrfGuard(): buildConnector.connector {
	const base = buildConnector({});
	return (opts, cb) => {
		const originalHostname = opts.hostname;
		dnsLookup(originalHostname, { all: true })
			.then((records) => {
				// Fail closed on an empty resolution OR any reserved address in the set (the
				// multi-address any-reserved rule: a MIXED public/reserved answer is refused
				// outright, so a rebinding/round-robin trick cannot land a later connect on
				// the reserved member). Every refuse path raises the SAME generic error.
				if (
					records.length === 0 ||
					records.some(({ address }) => blockedAddress(address))
				) {
					cb(ssrfRefusal(originalHostname), null);
					return;
				}
				// Every address passed; pin to the first (all public) checked IP literal
				// — no re-resolution at connect — and keep servername = original host.
				base(
					{
						...opts,
						hostname: records[0]?.address ?? originalHostname,
						servername: opts.servername || originalHostname,
					},
					cb,
				);
			})
			.catch(() => {
				cb(ssrfRefusal(originalHostname), null);
			});
	};
}

/** The single guarded Dispatcher backing the default guarded transport. The SSRF
 * connector vets + pins every dial (initial and each followed redirect hop); the
 * composed redirect interceptor bounds the chain to the shared MAX_REDIRECTS cap so
 * undici does not inherit its ~20-hop default. Beyond the cap the interceptor stops
 * following and surfaces the 3xx as an ordinary non-2xx (fail-closed at fetchStrict). */
const guardedAgent = new Agent({ connect: ssrfGuard() }).compose(
	interceptors.redirect({ maxRedirections: MAX_REDIRECTS }),
);

/** Reads an undici response body as text, bounded to MAX_DOC_BYTES. Iterates the
 * body stream (async-iterable in Node) so a hostile origin cannot force an
 * unbounded read; breaking the loop cancels the stream once the cap is hit. */
async function readBounded(
	body: AsyncIterable<Uint8Array> | null,
): Promise<string> {
	if (body === null) return "";
	const chunks: Uint8Array[] = [];
	let total = 0;
	for await (const chunk of body) {
		chunks.push(chunk);
		total += chunk.length;
		if (total >= MAX_DOC_BYTES) break;
	}
	const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
	return buf.subarray(0, MAX_DOC_BYTES).toString("utf8");
}

/** GET `url` through `dispatcher` (an undici Agent carrying the SSRF connector
 * and the redirect-cap interceptor), gating the initial scheme with `allowScheme`
 * and bounding the body to MAX_DOC_BYTES. undici owns status/redirect/1xx/decompress
 * and the interceptor bounds the redirect chain, so this owns only the scheme gate
 * and the body cap. A blocked target surfaces as the precise SsrfBlockedError (the
 * connector rejects directly or via `err.cause`); non-guard errors propagate. The
 * one request path both guarded faces share, so their wiring cannot drift. */
async function requestBounded(
	url: string,
	dispatcher: Dispatcher,
	allowScheme: (scheme: string) => boolean,
): Promise<FetchResponse> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch (err) {
		throw new SsrfBlockedError(
			`SSRF guard: unparseable url ${url}: ${String(err)}`,
		);
	}
	// Gate the scheme BEFORE any dial. URL.protocol carries a trailing colon ("https:").
	const scheme = parsed.protocol.replace(/:$/, "");
	if (!allowScheme(scheme)) {
		throw new SsrfBlockedError(
			`SSRF guard: refusing disallowed scheme ${parsed.protocol}`,
		);
	}
	let resp: Awaited<ReturnType<typeof undiciRequest>>;
	try {
		resp = await undiciRequest(url, {
			dispatcher,
			signal: AbortSignal.timeout(DEFAULT_HTTP_TIMEOUT_MS),
		});
	} catch (err) {
		if (err instanceof SsrfBlockedError) throw err;
		const cause = (err as { cause?: unknown }).cause;
		if (cause instanceof SsrfBlockedError) throw cause;
		throw err;
	}
	const body = await readBounded(resp.body as AsyncIterable<Uint8Array> | null);
	return { status: resp.statusCode, text: () => Promise.resolve(body) };
}

/** The SSRF-guarded default transport. The directory host is derived from a
 * caller-supplied Signature-Agent and the fetch runs BEFORE the ed25519 check,
 * so an unguarded default would be a pre-auth SSRF lever. Runs on undici through
 * the guarded connector (see ssrfGuard): the initial URL's scheme is vetted
 * deny-by-default, every dial (initial + each redirect hop) is address-checked and
 * pinned, the redirect chain is bounded to MAX_REDIRECTS, and undici owns
 * status/redirect/1xx so a non-2xx is an ordinary response, never a crash. */
export const guardedFetch: FetchLike = (url) =>
	requestBounded(url, guardedAgent, allowedScheme);

// ---------------------------------------------------------------------------
// The ONE env-driven, best-effort guarded fetch factory.
// ---------------------------------------------------------------------------

/** Read a boolean env flag: true iff the value is "true" (any case) or "1". Every
 * other value (including unset and "0") is false. */
function envFlag(name: string): boolean {
	return ["true", "1"].includes((process.env[name] ?? "").toLowerCase());
}

/** Whether the dial-time address guard is disabled (SKIP_SSRF). Default: off. */
function skipSSRF(): boolean {
	return envFlag("SKIP_SSRF");
}

/** Whether plaintext http is permitted (ALLOW_INSECURE); else https-only. Default: off. */
function allowInsecure(): boolean {
	return envFlag("ALLOW_INSECURE");
}

/** The two-flag scheme decision: https always, http only under ALLOW_INSECURE,
 * everything else denied (a scheme denylist is unwinnable — ftp, telnet, gopher,
 * file, data, …). Case-insensitive. */
function schemeGuardAllows(scheme: string): boolean {
	const s = scheme.toLowerCase();
	if (s === "https") return true;
	return s === "http" && allowInsecure();
}

/** The ONE public env-driven best-effort guarded fetch factory — every consumer's
 * fetch for any third-party-influenceable request. Two orthogonal env flags drive
 * it: SKIP_SSRF toggles the dial-time address guard (default: on), ALLOW_INSECURE
 * toggles the scheme guard (default: https-only). There is no deployment-stack
 * allow-list and no config error. Both paths use a per-factory undici Agent that
 * ignores HTTP(S)_PROXY env, so a proxied CONNECT cannot tunnel a private target
 * past the (guarded) dial guard, and both carry the same request timeout. Returns
 * a FetchLike closing over one dispatcher. */
export function guardedFetchFromEnv(): FetchLike {
	// One dispatcher per factory: the SSRF connector (unless SKIP_SSRF) plus the
	// redirect-cap interceptor, so a proxied CONNECT cannot tunnel past the (guarded)
	// dial guard and the redirect chain is bounded to the shared MAX_REDIRECTS cap.
	const base = skipSSRF() ? new Agent() : new Agent({ connect: ssrfGuard() });
	const dispatcher = base.compose(
		interceptors.redirect({ maxRedirections: MAX_REDIRECTS }),
	);
	return (url) => requestBounded(url, dispatcher, schemeGuardAllows);
}

/** Default transport for a resolver whose URL is caller-configured (well-known
 * JWKS / ramp.json): a plain fetch. It is NOT SSRF-guarded — the operator, not an
 * attacker, chooses that URL, and an on-prem JWKS may legitimately be private.
 * Only the WBA resolver (whose host comes from the request-supplied
 * Signature-Agent, fetched pre-auth) defaults to `guardedFetch`, matching the Go
 * oracle, which guards only its WBA client. */
export const defaultFetch: FetchLike = async (url) => {
	const r = await fetch(url);
	// Bound the body read even on the unguarded path: a misconfigured / hostile
	// well-known origin cannot force an unbounded read into the JSON decoder. The
	// WHATWG Response body is async-iterable in Node, so it reuses readBounded (the
	// same 1 MiB cap as the guarded transport and the Go/Python well-known paths).
	const body = await readBounded(
		r.body as unknown as AsyncIterable<Uint8Array> | null,
	);
	return { status: r.status, text: () => Promise.resolve(body) };
};

/** GET `url` and return the body text. A transport failure or a non-200 status
 * throws DirectoryUnavailable (fail-closed halt) — the taxonomy a composite
 * relies on to distinguish an outage from an unknown key. A blocked SSRF target
 * is a transport failure and surfaces the same way (never a valid empty doc). */
export async function fetchStrict(
	fetchFn: FetchLike,
	url: string,
): Promise<string> {
	let resp: FetchResponse;
	try {
		resp = await fetchFn(url);
	} catch (err) {
		throw new DirectoryUnavailable(`fetch ${url}`, { cause: err });
	}
	if (resp.status !== 200) {
		throw new DirectoryUnavailable(`status ${resp.status} for ${url}`);
	}
	return resp.text();
}

/** Best-effort GET: returns the body text on 200, or `undefined` on any
 * transport/status failure. The revocation refresh uses this so a fetch blip
 * leaves the prior snapshot in place (Go: best-effort refresh) rather than
 * propagating — a stale-but-present snapshot is safer than dropping revocations. */
export async function fetchSoft(
	fetchFn: FetchLike,
	url: string,
): Promise<string | undefined> {
	try {
		const resp = await fetchFn(url);
		if (resp.status !== 200) return undefined;
		return await resp.text();
	} catch {
		return undefined;
	}
}
