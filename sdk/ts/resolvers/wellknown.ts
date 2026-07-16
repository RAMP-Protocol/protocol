// The two well-known fetching faces: WellKnownKeyResolver (one fixed JWKS URL,
// kid-keyed) and WellKnownEndpointResolver (host-keyed ramp.json → endpoint).
// Both port the Go oracle's lazy-fetch + TTL-cache + single-flight coalescing and
// its fail-closed taxonomy: a fetch/decode failure throws DirectoryUnavailable;
// an unknown kid is `undefined`; a manifest with no endpoint throws NoEndpoint.

import { DirectoryUnavailable, NoEndpoint } from "./errors.ts";
import { type FetchLike, defaultFetch, fetchStrict } from "./http.ts";
import { ed25519KeysFromJwks } from "./jwks.ts";

const DEFAULT_TTL_MS = 300_000; // 5 minutes

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
    this.cache.set(host, { endpoint, exp: this.now() + this.ttlMs });
    return endpoint;
  }
}
