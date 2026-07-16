// Public surface of the RAMP SDK resolver faces (ADR-020 §4). These are the FIRST
// IO in the TS SDK, so they live OUTSIDE the IO-free core/src tree (exported via
// package.json `exports`) to keep the transport-neutrality invariant on core
// green. Four faces port the Go oracle: a static named map, a well-known JWKS
// key resolver, a host-keyed well-known endpoint resolver, and the WBA
// identity-directory resolver + revocation poller. The typed error classes
// preserve the oracle's errors.Is-DISTINCT fail-closed taxonomy.

export {
	DirectoryUnavailable,
	KeyExpired,
	KeyRevoked,
	NoEndpoint,
	ResolverError,
	RevocationUnevaluated,
	UnknownKey,
} from "./errors.ts";
export type { FetchLike, FetchResponse } from "./http.ts";
export { guardedFetchFromEnv, SsrfBlockedError, ssrfGuard } from "./http.ts";
export {
	type CachedOfferKeyResolver,
	type CachedOfferKeyResolverOptions,
	clampOfferKeyExpiry,
	createCachedOfferKeyResolver,
	createWBAOfferDirectoryFetch,
	type OfferDirectoryFetch,
} from "./offer-key-cache.ts";
export { allowedScheme, blockedAddress } from "./ssrf.ts";
export { createStaticKeyResolver, type StaticKeyResolver } from "./static.ts";
export {
	activeEd25519Key,
	activeEd25519KeyScreened,
	activeEd25519KeyWithExpiry,
	activeEd25519KeyWithExpiryScreened,
	createWBAKeyResolver,
	WBA_DIRECTORY_PATH,
	type WBAKeyResolver,
	type WBAKeyResolverOptions,
	wbaDirectoryURL,
} from "./wba.ts";
export {
	type EndpointOptions,
	createWellKnownEndpointResolver,
	createWellKnownKeyResolver,
	type WellKnownEndpointResolver,
	type WellKnownKeyResolver,
	type WellKnownOptions,
} from "./wellknown.ts";
