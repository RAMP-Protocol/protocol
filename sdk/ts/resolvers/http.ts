// The one HTTP transport seam the fetching resolvers share. Transport-neutral
// per the SDK dependency policy (no framework HTTP client): the resolvers accept
// an injected fetch-compatible callable and default to an SSRF-GUARDED transport
// (see guardedFetch) — matching the Go oracle's safe-by-default guarded client.
// Integration tests / on-prem deployments that must reach a private origin
// inject their own FetchLike (the escape hatch); the injected callable is never
// mocked, only pointed at a real in-process origin.

import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest, type RequestOptions } from "node:https";

import { DirectoryUnavailable } from "./errors.ts";
import { allowedScheme, blockedAddress } from "./ssrf.ts";

/** The minimal response shape the resolvers read — a structural subset of the
 * WHATWG `Response`, so the global `fetch` satisfies it without an adapter. */
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

/** The SSRF-guarded default transport. Ports sdk/go/helpers newGuardedWBAClient.
 *
 * The directory host is derived from a caller-supplied Signature-Agent and the
 * fetch runs BEFORE the ed25519 signature check, so an unguarded default is a
 * pre-auth SSRF lever. This transport closes the DNS-REBINDING window: it
 * resolves the host ONCE, checks EVERY resolved address against blockedAddress,
 * and then connects PINNED to a checked IP — the request dials the IP directly
 * while the TLS `servername` (and `Host` header) carry the original hostname, so
 * the host is NOT re-resolved between the check and the connect. A resolve →
 * check → fetch-by-hostname sequence would re-resolve at connect time and reopen
 * the window; pinning to the already-checked address forecloses it. */
export const guardedFetch: FetchLike = async (url) => {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new SsrfBlockedError(`SSRF guard: unparseable url ${url}: ${String(err)}`);
  }
  // Deny-by-default scheme allowlist (only http/https). URL.protocol carries a
  // trailing colon ("https:"), so strip it before the allowlist check. TS
  // follows no redirects, so there is no redirect target to re-vet — the
  // initial-URL scheme is the only one dialed.
  const scheme = parsed.protocol.replace(/:$/, "");
  if (!allowedScheme(scheme)) {
    throw new SsrfBlockedError(`SSRF guard: refusing non-http(s) scheme ${parsed.protocol}`);
  }
  const isHttps = scheme.toLowerCase() === "https";
  const hostname = stripBrackets(parsed.hostname);

  // Resolve ONCE and vet every candidate address; pin to the first that passes.
  const pinnedIp = await resolveAndVet(hostname);

  const port = parsed.port !== "" ? Number(parsed.port) : isHttps ? 443 : 80;
  const requestFn = isHttps ? httpsRequest : httpRequest;
  const options: RequestOptions = {
    host: pinnedIp, // dial the CHECKED address — no hostname re-resolution
    port,
    method: "GET",
    path: `${parsed.pathname}${parsed.search}`,
    // Carry the original hostname so vhost routing (Host) and TLS cert
    // validation (servername/SNI) still target the intended origin.
    headers: { Host: parsed.host },
    servername: hostname,
    timeout: DEFAULT_HTTP_TIMEOUT_MS,
  };

  return await new Promise<FetchResponse>((resolve, reject) => {
    const req = requestFn(options, (res) => {
      const status = res.statusCode ?? 0;
      const chunks: Buffer[] = [];
      let total = 0;
      res.on("data", (chunk: Buffer) => {
        total += chunk.length;
        if (total > MAX_DOC_BYTES) {
          res.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        resolve({ status, text: () => Promise.resolve(body) });
      });
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("SSRF guard: request timeout")));
    req.on("error", reject);
    req.end();
  });
};

/** Resolve `hostname` and return one address that passed the SSRF check. When
 * the input is already a numeric literal, dns.lookup returns it verbatim; either
 * way EVERY resolved address is vetted and a blocked one aborts the dial. */
async function resolveAndVet(hostname: string): Promise<string> {
  let records: { address: string }[];
  try {
    records = await dnsLookup(hostname, { all: true });
  } catch (err) {
    throw new SsrfBlockedError(`SSRF guard: cannot resolve ${hostname}: ${String(err)}`);
  }
  if (records.length === 0) {
    throw new SsrfBlockedError(`SSRF guard: no address for ${hostname}`);
  }
  for (const { address } of records) {
    if (blockedAddress(address)) {
      throw new SsrfBlockedError(
        `SSRF guard: refusing to dial non-public address ${address} for ${hostname}`,
      );
    }
  }
  // Every address passed; pin to the first (all are public, so any is safe).
  return records[0]?.address as string;
}

function stripBrackets(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

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
