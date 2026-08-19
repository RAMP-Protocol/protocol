// The two well-known fetching faces: WellKnownKeyResolver (one fixed JWKS URL,
// kid-keyed) and WellKnownEndpointResolver (host-keyed ramp.json → endpoint).
// Both port the Go oracle's lazy-fetch + TTL-cache + single-flight coalescing and
// its fail-closed taxonomy: a fetch/decode failure throws DirectoryUnavailable;
// an unknown kid is `undefined`; a manifest with no endpoint throws NoEndpoint.

import { hostAnchored, isBareHost } from "../src/hosts.ts";
import { DirectoryUnavailable, EndpointRefused, NoEndpoint } from "./errors.ts";
import { type FetchLike, defaultFetch, fetchStrict } from "./http.ts";
import { ed25519KeysFromJwks } from "./jwks.ts";

const DEFAULT_TTL_MS = 300_000; // 5 minutes

/** Why an endpoint a manifest advertises may not be handed back, or undefined
 * when it may.
 *
 * The manifest that named this endpoint is served by the very host the call is
 * bound for, so the endpoint is only as trustworthy as that host. An Exchange may
 * advertise itself or a subdomain of itself, on the same port, and nothing else —
 * a dial-time address guard has no objection to an unrelated PUBLIC host, so
 * nothing below this catches one.
 *
 * Userinfo is refused for a different reason with the same shape: the host
 * comparison reads the authority's host and ignores any user:password before it,
 * so an endpoint carrying credentials would pass the host check and then have the
 * HTTP client stamp an Authorization header the SDK never chose, on a leg that
 * already carries the caller's own signature.
 *
 * It runs HERE, in the resolver, rather than in each caller: the check is a
 * property of reading an endpoint out of a manifest, not of any one caller's plans
 * for it. (The Go oracle keeps the same rule in a shared internal package because
 * it has a second call site — a typed client that re-checks an injected resolver's
 * answer. This SDK has only the one, so the rule lives with it.)
 *
 * Both halves read the reference the SAME way. A value naming no scheme is a URL
 * to one parser and a path to another, and the two answers put a credential on
 * opposite sides of the check — "u:p@exchange.example" is where they part. */
function endpointRefusal(host: string, endpoint: string): string | undefined {
  // Normalized exactly as the anchor predicate normalizes it: a reference naming
  // no scheme is read as https, since a bare domain is otherwise
  // indistinguishable from a path.
  const work = endpoint.includes("://") ? endpoint : `https://${endpoint}`;
  const rest = work.slice(work.indexOf("://") + 3);
  const end = rest.search(/[/?#]/);
  const authority = end < 0 ? rest : rest.slice(0, end);
  if (authority.includes("@")) {
    // Deliberately does not echo the endpoint: it carries the credential.
    return `host=${JSON.stringify(host)} advertises an endpoint carrying userinfo`;
  }
  try {
    if (!hostAnchored(host, endpoint)) {
      return `host=${JSON.stringify(host)} advertises endpoint ${JSON.stringify(endpoint)} on a different host`;
    }
  } catch (err) {
    return `host=${JSON.stringify(host)} endpoint=${JSON.stringify(endpoint)}: ${String(err)}`;
  }
  return undefined;
}

/** Options for the well-known fetching resolvers. `now` is epoch-ms; tests inject
 * it for deterministic TTL expiry. `fetch` defaults to the global fetch. */
export interface WellKnownOptions {
  ttlMs?: number;
  now?: () => number;
  fetch?: FetchLike;
  /** Trust allowlist: a keyid (key resolver) or host (endpoint resolver) the
   * allowlist rejects never reaches the network. */
  allow?: (id: string) => boolean;
}

/** Options for the endpoint resolver; adds the URL scheme used to build
 * `{scheme}://{host}/.well-known/ramp.json` (tests inject "http"). */
export interface EndpointOptions extends WellKnownOptions {
  scheme?: string;
}

/** The well-known JWKS key face. */
export interface WellKnownKeyResolver {
  resolve(keyid: string): Promise<Uint8Array | undefined>;
}

/** The host-keyed endpoint face. */
export interface WellKnownEndpointResolver {
  resolveEndpoint(host: string): Promise<string>;
}

/** Lazily fetch the JWKS at `url`, cache resolved keys with a TTL. */
export function createWellKnownKeyResolver(
  url: string,
  opts: WellKnownOptions = {},
): WellKnownKeyResolver {
  return new KeyResolverImpl(url, opts);
}

/** Host-keyed resolver of an Exchange domain → its self-advertised endpoint. */
export function createWellKnownEndpointResolver(
  opts: EndpointOptions = {},
): WellKnownEndpointResolver {
  return new EndpointResolverImpl(opts);
}

class KeyResolverImpl implements WellKnownKeyResolver {
  private readonly fetchFn: FetchLike;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly allow: ((id: string) => boolean) | undefined;
  private cache = new Map<string, Uint8Array>();
  private cacheExp = 0;
  private inflight: Promise<void> | undefined;

  constructor(
    private readonly url: string,
    opts: WellKnownOptions,
  ) {
    this.fetchFn = opts.fetch ?? defaultFetch;
    this.ttlMs = opts.ttlMs && opts.ttlMs > 0 ? opts.ttlMs : DEFAULT_TTL_MS;
    this.now = opts.now ?? Date.now;
    this.allow = opts.allow;
  }

  async resolve(keyid: string): Promise<Uint8Array | undefined> {
    if (this.allow && !this.allow(keyid)) return undefined;
    const hit = this.cachedKey(keyid);
    if (hit) return hit;
    await this.refresh();
    return this.cachedKey(keyid);
  }

  private cachedKey(keyid: string): Uint8Array | undefined {
    if (this.now() > this.cacheExp) return undefined;
    return this.cache.get(keyid);
  }

  private async refresh(): Promise<void> {
    if (this.now() <= this.cacheExp) return; // another refresh won the race
    if (this.inflight) return this.inflight;
    this.inflight = this.doRefresh();
    try {
      await this.inflight;
    } finally {
      this.inflight = undefined;
    }
  }

  private async doRefresh(): Promise<void> {
    const body = await fetchStrict(this.fetchFn, this.url);
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch (err) {
      throw new DirectoryUnavailable(`jwks decode ${this.url}`, { cause: err });
    }
    this.cache = ed25519KeysFromJwks(parsed);
    this.cacheExp = this.now() + this.ttlMs;
  }
}

interface EndpointEntry {
  endpoint: string;
  exp: number;
}

class EndpointResolverImpl implements WellKnownEndpointResolver {
  private readonly fetchFn: FetchLike;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly scheme: string;
  private readonly allow: ((id: string) => boolean) | undefined;
  private readonly cache = new Map<string, EndpointEntry>();
  private readonly flight = new Map<string, Promise<string>>();

  constructor(opts: EndpointOptions) {
    this.fetchFn = opts.fetch ?? defaultFetch;
    this.ttlMs = opts.ttlMs && opts.ttlMs > 0 ? opts.ttlMs : DEFAULT_TTL_MS;
    this.now = opts.now ?? Date.now;
    this.scheme = opts.scheme && opts.scheme !== "" ? opts.scheme : "https";
    this.allow = opts.allow;
  }

  async resolveEndpoint(host: string): Promise<string> {
    // Checked BEFORE the allow overlay and before the cache. The fetch URL is
    // built by concatenation, so a value carrying a path or a query would choose
    // WHAT gets fetched rather than merely where from — and the raw string is the
    // cache key, so admitting one would also put it in a shared map.
    // A fault in the CALLER's value, not a verdict on the Exchange's answer, so
    // it is the same invalid-host error isBareHost itself throws for a reference
    // it cannot read at all — the oracle uses one sentinel across both branches
    // here for the same reason. EndpointRefused stays what it says: the manifest
    // was read and its answer is unusable.
    if (!isBareHost(host)) {
      throw new Error(
        `hosts: reference is not a usable host: not a bare host: ${JSON.stringify(host)}`,
      );
    }
    if (this.allow && !this.allow(host)) throw new NoEndpoint(`host ${host} not allowed`);
    const hit = this.cached(host);
    if (hit !== undefined) return hit;
    let flight = this.flight.get(host);
    if (!flight) {
      flight = this.fetchEndpoint(host);
      this.flight.set(host, flight);
    }
    try {
      return await flight;
    } finally {
      this.flight.delete(host);
    }
  }

  private cached(host: string): string | undefined {
    const entry = this.cache.get(host);
    if (!entry || this.now() > entry.exp) return undefined;
    return entry.endpoint;
  }

  private async fetchEndpoint(host: string): Promise<string> {
    const hit = this.cached(host);
    if (hit !== undefined) return hit; // filled while we queued behind the flight lock
    const url = `${this.scheme}://${host}/.well-known/ramp.json`;
    const body = await fetchStrict(this.fetchFn, url);
    let doc: unknown;
    try {
      doc = JSON.parse(body);
    } catch (err) {
      throw new DirectoryUnavailable(`manifest decode ${url}`, { cause: err });
    }
    const endpoint = (doc as { endpoint?: unknown }).endpoint;
    if (typeof endpoint !== "string" || endpoint === "") {
      throw new NoEndpoint(`host=${host}`);
    }
    // Vetted BEFORE it is cached, so a refused endpoint is not held for the TTL
    // and then served to every later caller out of memory.
    const refusal = endpointRefusal(host, endpoint);
    if (refusal !== undefined) {
      throw new EndpointRefused(refusal);
    }
    this.cache.set(host, { endpoint, exp: this.now() + this.ttlMs });
    return endpoint;
  }
}
