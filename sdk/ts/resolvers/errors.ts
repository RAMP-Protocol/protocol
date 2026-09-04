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

/** A /.well-known/ramp.json was fetched and parsed but carries a
 * WellKnownManifest.ver this resolver does not accept: an unrecognised major
 * version, a value that is not MAJOR.MINOR, or no version at all. The rule is
 * manifestVersionRefusal in src/wire.ts.
 *
 * Checked BEFORE any other member of the document is read. The manifest sits at
 * a fixed, unversioned path and is read before any signature is checked, so a
 * layout the reader cannot classify must not supply the endpoint a signed call
 * is then sent to. Like EndpointRefused it is a VERDICT — final, not a transport
 * failure to retry — and it is never cached. */
export class ManifestVersionRefused extends ResolverError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ManifestVersionRefused";
  }
}
