// The one HTTP transport seam the fetching resolvers share. Transport-neutral
// per the SDK dependency policy (no framework HTTP client): the resolvers accept
// an injected fetch-compatible callable and default to the WHATWG global `fetch`.
// Integration tests point the default at a REAL in-process origin — the callable
// is never mocked; only the clock/poll seams are injected.

import { DirectoryUnavailable } from "./errors.ts";

/** The minimal response shape the resolvers read — a structural subset of the
 * WHATWG `Response`, so the global `fetch` satisfies it without an adapter. */
export interface FetchResponse {
  status: number;
  text(): Promise<string>;
}

/** An injected HTTP GET. Defaults to the global `fetch`. */
export type FetchLike = (url: string) => Promise<FetchResponse>;

/** Default transport: the WHATWG global `fetch`. */
export const defaultFetch: FetchLike = (url) => fetch(url);

/** GET `url` and return the body text. A transport failure or a non-200 status
 * throws DirectoryUnavailable (fail-closed halt) — the taxonomy a composite
 * relies on to distinguish an outage from an unknown key. */
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
