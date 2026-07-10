// The one HTTP transport seam the fetching resolvers share. Transport-neutral
// per the SDK dependency policy (the resolvers accept an injected fetch-compatible
// callable) but the DEFAULT transport now runs on a maintained HTTP client
// (undici) instead of a hand-rolled node:http request. undici owns the response
// state machine — status, redirects, 1xx, decompression — so this module owns
// only the SSRF guard (an injectable connection-level connector) and the
// fail-closed status→body taxonomy. Integration tests / on-prem deployments that
// must reach a private origin inject their own FetchLike (the escape hatch).

import { lookup as dnsLookup } from "node:dns/promises";

import { Agent, buildConnector, fetch as undiciFetch } from "undici";

import { DirectoryUnavailable } from "./errors.ts";
import { allowedScheme, blockedAddress } from "./ssrf.ts";

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
        if (records.length === 0) {
          cb(new SsrfBlockedError(`SSRF guard: no address for ${originalHostname}`), null);
          return;
        }
        for (const { address } of records) {
          if (blockedAddress(address)) {
            cb(
              new SsrfBlockedError(
                `SSRF guard: refusing to dial non-public address ${address} for ${originalHostname}`,
              ),
              null,
            );
            return;
          }
        }
        // Every address passed; pin to the first (all public) checked IP literal
        // — no re-resolution at connect — and keep servername = original host.
        base(
          { ...opts, hostname: records[0]?.address ?? originalHostname, servername: opts.servername || originalHostname },
          cb,
        );
      })
      .catch((err: unknown) => {
        cb(new SsrfBlockedError(`SSRF guard: cannot resolve ${originalHostname}: ${String(err)}`), null);
      });
  };
}

/** The single guarded Dispatcher backing the default guarded transport. */
const guardedAgent = new Agent({ connect: ssrfGuard() });

/** Reads an undici response body as text, bounded to MAX_DOC_BYTES. Iterates the
 * body stream (async-iterable in Node) so a hostile origin cannot force an
 * unbounded read; breaking the loop cancels the stream once the cap is hit. */
async function readBounded(body: AsyncIterable<Uint8Array> | null): Promise<string> {
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

/** The SSRF-guarded default transport. The directory host is derived from a
 * caller-supplied Signature-Agent and the fetch runs BEFORE the ed25519 check,
 * so an unguarded default would be a pre-auth SSRF lever. Runs on undici through
 * the guarded connector (see ssrfGuard): the initial URL's scheme is vetted
 * deny-by-default, every dial (initial + each redirect hop) is address-checked
 * and pinned, and undici owns status/redirect/1xx so a non-2xx is an ordinary
 * response, never a crash. */
export const guardedFetch: FetchLike = async (url) => {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new SsrfBlockedError(`SSRF guard: unparseable url ${url}: ${String(err)}`);
  }
  // Deny-by-default scheme allowlist (only http/https) on the initial URL.
  // URL.protocol carries a trailing colon ("https:"); strip it before the check.
  const scheme = parsed.protocol.replace(/:$/, "");
  if (!allowedScheme(scheme)) {
    throw new SsrfBlockedError(`SSRF guard: refusing non-http(s) scheme ${parsed.protocol}`);
  }
  let resp: Awaited<ReturnType<typeof undiciFetch>>;
  try {
    resp = await undiciFetch(url, {
      dispatcher: guardedAgent,
      redirect: "follow",
      signal: AbortSignal.timeout(DEFAULT_HTTP_TIMEOUT_MS),
    });
  } catch (err) {
    // undici wraps a connector error; surface the precise SsrfBlockedError so a
    // blocked target is a clear, SSRF-labelled failure (fetchStrict/fetchSoft map
    // it the same way regardless). Non-guard transport errors propagate unchanged.
    if (err instanceof SsrfBlockedError) throw err;
    const cause = (err as { cause?: unknown }).cause;
    if (cause instanceof SsrfBlockedError) throw cause;
    throw err;
  }
  const body = await readBounded(resp.body as AsyncIterable<Uint8Array> | null);
  return { status: resp.status, text: () => Promise.resolve(body) };
};

/** Default transport for a resolver whose URL is caller-configured (well-known
 * JWKS / ramp.json): a plain fetch. It is NOT SSRF-guarded — the operator, not an
 * attacker, chooses that URL, and an on-prem JWKS may legitimately be private.
 * Only the WBA resolver (whose host comes from the request-supplied
 * Signature-Agent, fetched pre-auth) defaults to `guardedFetch`, matching the Go
 * oracle, which guards only its WBA client. */
export const defaultFetch: FetchLike = async (url) => {
  const r = await fetch(url);
  return { status: r.status, text: () => r.text() };
};

/** GET `url` and return the body text. A transport failure or a non-200 status
 * throws DirectoryUnavailable (fail-closed halt) — the taxonomy a composite
 * relies on to distinguish an outage from an unknown key. A blocked SSRF target
 * is a transport failure and surfaces the same way (never a valid empty doc). */
export async function fetchStrict(fetchFn: FetchLike, url: string): Promise<string> {
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
export async function fetchSoft(fetchFn: FetchLike, url: string): Promise<string | undefined> {
  try {
    const resp = await fetchFn(url);
    if (resp.status !== 200) return undefined;
    return await resp.text();
  } catch {
    return undefined;
  }
}
