// Typed error surface for the fetching resolver faces. The Go oracle uses
// errors.Is-DISTINCT sentinels (ErrKeyRevoked / ErrKeyExpired /
// ErrDirectoryUnavailable / ErrNoEndpoint / ErrUnknownKey) so a composite
// resolver can HALT on a fail-closed verdict rather than fall through as if the
// key were merely unknown. The TS port preserves that distinctness as distinct
// thrown classes. The SDK's own RequestKeyResolver faces still signal a plain
// miss with the `undefined` return (never a throw); UnknownKey below is the
// catchable class of that same verdict for consumers and composite stacks that
// need the error-shaped face Go and Python expose.

/** Base of every resolver verdict. */
export class ResolverError extends Error {}

/** No key is known for the requested keyid/thumbprint (fall-through miss) —
 * the class face of Go `ErrUnknownKey` / Python `UnknownKeyError`. The SDK's
 * own resolver faces signal this verdict with an `undefined` return; the class
 * exists for consumers and fail-closed composite stacks that surface the miss
 * as a catchable error, keeping the taxonomy identical across all three SDKs. */
export class UnknownKey extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "UnknownKey";
  }
}

/** The WBA identity directory (or a well-known JWKS/manifest) could not be
 * fetched, returned non-200, or failed to decode. DISTINCT from unknown-key so a
 * fail-closed composite halts on an outage instead of falling through. */
export class DirectoryUnavailable extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DirectoryUnavailable";
  }
}

/** The thumbprint is present in the directory host's current revocation snapshot. */
export class KeyRevoked extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "KeyRevoked";
  }
}

/** The key exists but `now` falls outside its [not_before, not_after) window. */
export class KeyExpired extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "KeyExpired";
  }
}

/** The key resolved, but its directory declares a revocation_url whose snapshot
 * has never been fetched (unreachable or not host-anchored) — so revocation was
 * NEVER EVALUATED, DISTINCT from KeyRevoked ("evaluated and revoked"). Only
 * thrown when the resolver's `requireRevocation` option is set; the default
 * keeps the prior best-effort behavior (a declared-but-unreachable revocation
 * channel does not block resolution). It lets a caller that treats revocation as
 * mandatory fail closed instead of trusting an unevaluated key. */
export class RevocationUnevaluated extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "RevocationUnevaluated";
  }
}

/** A well-known manifest was fetched and decoded, but advertises no endpoint.
 * DISTINCT from DirectoryUnavailable: the manifest is reachable, simply inert. */
export class NoEndpoint extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "NoEndpoint";
  }
}

/** A well-known manifest was read and advertises an endpoint this resolver will
 * not hand back: one on a host or port unrelated to the domain that served the
 * manifest, or one carrying userinfo.
 *
 * DISTINCT from NoEndpoint and from DirectoryUnavailable because it is a VERDICT
 * — the Exchange answered, and the answer is not usable. A caller that classifies
 * retryability reads this as final rather than as something to try again in a
 * moment. */
export class EndpointRefused extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "EndpointRefused";
  }
}

/** The deployment's allow overlay excluded this Exchange domain, before anything
 * was dialled — the class face of Go `ErrExchangeNotPermitted` / Python
 * `ExchangeNotPermittedError`. It says nothing about whether the Exchange exists
 * or answers, only that this deployment declined to ask, so the remedy is a
 * configuration change rather than a retry. */
export class ExchangeNotPermitted extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ExchangeNotPermitted";
  }
}

/** The document served at the domain's well-known path describes some other role
 * — the class face of Go `ErrManifestNotExchange` / Python
 * `ManifestNotExchangeError`. Registration requirements are an Exchange's to
 * publish, so a manifest claiming to be an agent, a broker or a publisher is
 * refused rather than read for members it has no business carrying. A manifest
 * naming no role at all is refused the same way: the field is required by the
 * contract, and reading silence as assent would make the check advisory. */
export class ManifestNotExchange extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ManifestNotExchange";
  }
}
