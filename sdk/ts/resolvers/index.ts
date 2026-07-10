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
} from "./errors.ts";
export type { FetchLike, FetchResponse } from "./http.ts";
export { SsrfBlockedError, ssrfGuard } from "./http.ts";
export { allowedScheme, blockedAddress } from "./ssrf.ts";
export { type StaticKeyResolver, newStaticKeyResolver } from "./static.ts";
export {
  type EndpointOptions,
  type WellKnownEndpointResolver,
  type WellKnownKeyResolver,
  type WellKnownOptions,
  newWellKnownEndpointResolver,
  newWellKnownKeyResolver,
} from "./wellknown.ts";
export {
  type WBAKeyResolver,
  type WBAKeyResolverOptions,
  activeEd25519Key,
  activeEd25519KeyWithExpiry,
  newWBAKeyResolver,
} from "./wba.ts";
