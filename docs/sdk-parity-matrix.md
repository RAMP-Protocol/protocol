# SDK API-Surface Parity Matrix (go · python · ts)

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Source of truth:
       • API surface   — sdk/parity/symbol-map.json
                          (enforced against live exports by
                           sdk/python/tests/test_api_surface_parity.py)
       • Vector replay  — sdk/go/{helpers,resolvers}/testdata/*-vectors.json
                          (enforced by test_corpus_replay_completeness.py)
     Regenerate:  python3 scripts/gen-parity-matrix.py
     Drift-gated in scripts/ci-local.sh. Narrative/rationale: docs/design-history.md. -->

Go is the oracle (`sdk/go/{helpers,resolvers,core,connect,connectserver}`); Python and TS mirror it. This document is **generated** from the same two artifacts CI already enforces against the code, so it cannot drift from the real surface — a mismatch fails the API-surface gate or the corpus-completeness gate before it can reach this file.

**At a glance:** 77 symbols at cross-language parity · 14 documented divergences · 133 Go-idiomatic exclusions · 23 conformance corpora, each tri-replayed.

Layering (L1 pure trust core vs L2 I/O resolvers), the SSRF transport-wiring invariant, and naming conventions are recorded in [`design-history.md`](./design-history.md).

## API surface — parity per Go public symbol

Legend: a name = the public face in that language · `—` = intentionally none (see Documented divergences). Every row here is at parity by construction: the gate rejects a mapped name that is absent from the live surface.

### helpers — L1 pure primitives (crypto, canonicalization, money, scopes)

| Go | python | ts |
|---|---|---|
| `AcceptanceSignatureAlgorithm` | `ACCEPTANCE_SIGNATURE_ALGORITHM` | `ACCEPTANCE_SIGNATURE_ALGORITHM` |
| `AgentKeyHeader` | `AGENT_KEY_HEADER` | `AGENT_KEY_HEADER` |
| `AppendSignature` | `append_signature` | `appendSignature` |
| `ApplyScopes` | `apply_scopes` | `applyScopes` |
| `CanonicalAcceptanceBytes` | `jcs_acceptance_payload` | `acceptancePayload` |
| `CanonicalOfferBytes` | `canonical_offer_payload` | `canonicalOfferPayload` |
| `CanonicalizeMoney` | `canonicalize_money` | `canonicalizeMoney` |
| `CatalogRejectionDetail` | `catalog_rejection_detail` | `catalogRejectionDetail` |
| `ConnectProtocolVersion` | `ConnectProtocolVersion` | `ConnectProtocolVersion` |
| `ConnectProtocolVersionHeader` | `ConnectProtocolVersionHeader` | `ConnectProtocolVersionHeader` |
| `ContentDigest` | `content_digest` | `contentDigest` |
| `ContentTypeJSON` | `ContentTypeJSON` | `ContentTypeJSON` |
| `ContentTypeProto` | `ContentTypeProto` | `ContentTypeProto` |
| `DisputeFailureDetail` | `dispute_failure_detail` | `disputeFailureDetail` |
| `DomainVerificationFailureDetail` | `domain_verification_failure_detail` | `domainVerificationFailureDetail` |
| `ErrUnknownKey` | `UnknownKeyError` | `UnknownKey` |
| `FormatMoney` | `format_money` | `formatMoney` |
| `HashURL` | `hash_url` | `hashUrl` |
| `KeyResolver` | `KeyResolver` | `RequestKeyResolver` |
| `NewIdempotencyKey` | `generate_idempotency_key` | `generateIdempotencyKey` |
| `NormalizeScopes` | `normalize_scopes` | `normalizeScopes` |
| `OfferSignatureAlgorithm` | `OFFER_SIGNATURE_ALGORITHM` | `OFFER_SIGNATURE_ALGORITHM` |
| `ParseMoney` | `parse_money` | `parseMoney` |
| `ProtocolVersion` | `ProtocolVersion` | `ProtocolVersion` |
| `Reason` | `reason` | `reason` |
| `RegistrationFailureDetail` | `registration_failure_detail` | `registrationFailureDetail` |
| `RequestIDHeader` | `RequestIDHeader` | `RequestIDHeader` |
| `RetrievalAuthFailureDetail` | `retrieval_auth_failure_detail` | `retrievalAuthFailureDetail` |
| `ScopesSubset` | `scopes_subset` | `scopesSubset` |
| `SignAgentBinding` | `sign_agent_binding` | `signInbound` |
| `SignOffer` | `sign_offer_jcs` | `signOffer` |
| `SignOfferAcceptance` | `sign_offer_acceptance_jcs` | `signOfferAcceptance` |
| `SignRequest` | `sign_request` | `signRequest` |
| `SignURLEd25519` | `sign_ed25519_signed_url` | `signEd25519SignedUrl` |
| `SignatureAgentHeader` | `SignatureAgentHeader` | `SignatureAgentHeader` |
| `StaticKeyResolver` | `StaticKeyResolver` | `StaticKeyResolver` |
| `Thumbprint` | `thumbprint` | `thumbprint` |
| `TransactionDenialDetail` | `transaction_denial_detail` | `transactionDenialDetail` |
| `UsageReportRejectionDetail` | `usage_report_rejection_detail` | `usageReportRejectionDetail` |
| `ValidateIdempotencyKey` | `validate_idempotency_key` | `validateIdempotencyKey` |
| `ValidationRuleIDs` | `cross_field_rule_ids` | `crossFieldRuleIds` |
| `VerifyMultisigRequest` | `verify_multisig_request_server` | `verifyMultisigRequestServer` |
| `VerifyOfferAcceptance` | `verify_offer_acceptance_jcs` | `verifyOfferAcceptance` |
| `VerifyRequest` | `verify_request` | `verifyRequestServer` |
| `VerifyURLEd25519` | `verify_ed25519_signed_url` | `verifyEd25519SignedUrl` |

### resolvers — L2 I/O (key/endpoint resolution, active-key, SSRF-guarded fetch)

| Go | python | ts |
|---|---|---|
| `ActiveEd25519Key` | `active_ed25519_key` | `activeEd25519Key` |
| `ActiveEd25519KeyScreened` | `active_ed25519_key_screened` | `activeEd25519KeyScreened` |
| `ActiveEd25519KeyWithExpiry` | `active_ed25519_key_with_expiry` | `activeEd25519KeyWithExpiry` |
| `ActiveEd25519KeyWithExpiryScreened` | `active_ed25519_key_with_expiry_screened` | `activeEd25519KeyWithExpiryScreened` |
| `CachedOfferKeyResolver` | `CachedOfferKeyResolver` | `CachedOfferKeyResolver` |
| `ErrDirectoryUnavailable` | `DirectoryUnavailableError` | `DirectoryUnavailable` |
| `ErrKeyExpired` | `KeyExpiredError` | `KeyExpired` |
| `ErrKeyRevoked` | `KeyRevokedError` | `KeyRevoked` |
| `ErrNoEndpoint` | `NoEndpointError` | `NoEndpoint` |
| `ErrRevocationUnevaluated` | `RevocationUnevaluatedError` | `RevocationUnevaluated` |
| `ErrUnknownKey` | `UnknownKeyError` | `UnknownKey` |
| `NewGuardedClientFromEnv` | `guarded_client` | `guardedFetchFromEnv` |
| `OfferDirectoryFetcher` | `DirectoryFetch` | `OfferDirectoryFetch` |
| `SSRFGuard` | `ssrf_guard` | `ssrfGuard` |
| `WBADirectoryPath` | `WBA_DIRECTORY_PATH` | `WBA_DIRECTORY_PATH` |
| `WBADirectoryURL` | `wba_directory_url` | `wbaDirectoryURL` |
| `WBAKeyResolver` | `WBAKeyResolver` | `WBAKeyResolver` |
| `WellKnownEndpointResolver` | `WellKnownEndpointResolver` | `WellKnownEndpointResolver` |
| `WellKnownKeyResolver` | `WellKnownKeyResolver` | `WellKnownKeyResolver` |

### core — L2 composition (verifier, signing transport, windows, replay)

| Go | python | ts |
|---|---|---|
| `ClockWindow` | `clock_window` | `clockWindow` |
| `Mode` | `Mode` | `Mode` |
| `MonotonicWindow` | `monotonic_window` | `monotonicWindow` |
| `NewSigningTransport` | `SigningTransport` | `createSigningTransport` |
| `RejectedOffer` | `RejectedOffer` | `RejectedOffer` |
| `ReplayStore` | `ReplayStore` | `ReplayStore` |
| `RequestIDHeader` | `RequestIDHeader` | `RequestIDHeader` |
| `Result` | `Result` | `Result` |
| `VerifiedOffer` | `VerifiedOffer` | `VerifiedOffer` |
| `Verifier` | `Verifier` | `Verifier` |
| `Window` | `Window` | `Window` |

### connect — Connect client + interceptors

| Go | python | ts |
|---|---|---|
| `ErrorDetailFrom` | `error_detail_from` | `errorDetailFrom` |

### connectserver — server-verify handler binding

| Go | python | ts |
|---|---|---|
| `RejectReason` | `RejectReason` | `RejectReason` |

## Documented divergences & DECISIONs

Deliberate, reason-backed asymmetries. The allowlist is **shrink-only** — a new undocumented gap cannot ship green. Each entry's rationale is the `allowlist_reason` from the symbol map; DECISION anchors are cross-checked by `test_api_surface_parity.py`.

### Architectural DECISIONs

- **DECISION — full Connect handler binding.** Go-only full Connect Broker handler binding — OPEN DECISION in docs/sdk-parity-matrix.md _(symbols: `connectserver.NewBrokerServiceHandler`, `connectserver.NewExchangeServiceHandler`)_
- **DECISION — typed Connect **client** — OPEN.** Go-only typed Connect client covering the agent verb set (Discover, Resolve, Execute, ReportUsage, Dispute, Fetch) — OPEN DECISION in docs/sdk-parity-matrix.md: the API-surface design governs and specifies a thin Connect-unary JSON client for TypeScript and Python with the SAME verb names, so this is an implementation difference pending that work, not a settled API divergence _(symbols: `connect.Client`, `connect.NewClient`)_

### Mapped symbols with an intentional per-language gap

| Go symbol | python | ts | rationale |
|---|---|---|---|
| `connect.Client` | — | — | Go-only typed Connect client covering the agent verb set (Discover, Resolve, Execute, ReportUsage, Dispute, Fetch) — OPEN DECISION in docs/sdk-parity-matrix.md: the API-surface design governs and specifies a thin Connect-unary JSON client for TypeScript and Python with the SAME verb names, so this is an implementation difference pending that work, not a settled API divergence |
| `connect.NewClient` | — | — | Go-only typed Connect client constructor (NewClient plus NewBrokerClient) — OPEN DECISION in docs/sdk-parity-matrix.md, pending the TypeScript and Python unary client that carries the same verb names |
| `connectserver.NewBrokerServiceHandler` | — | — | Go-only full Connect Broker handler binding — OPEN DECISION in docs/sdk-parity-matrix.md |
| `connectserver.NewExchangeServiceHandler` | — | — | Go-only full Connect Exchange handler binding — OPEN DECISION in docs/sdk-parity-matrix.md |
| `core.NewVerifier` | — | `createVerifier` | Go NewVerifier factory folds into the Python class constructor (Verifier(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the createVerifier factory. |
| `helpers.NewStaticKeyResolver` | — | `createStaticKeyResolver` | Go NewStaticKeyResolver factory folds into the Python class constructor (StaticKeyResolver(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the createStaticKeyResolver factory. |
| `resolvers.CachedOfferKeyResolverConfig` | — | `CachedOfferKeyResolverOptions` | Go config struct / TS options object folds into Python constructor keyword arguments (CachedOfferKeyResolver(...)); idiomatic Python has no separate options type. |
| `resolvers.NewCachedOfferKeyResolver` | — | `createCachedOfferKeyResolver` | Go NewCachedOfferKeyResolver factory folds into the Python class constructor (CachedOfferKeyResolver(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the createCachedOfferKeyResolver factory. |
| `resolvers.NewWBADirectoryFetcher` | — | `createWBAOfferDirectoryFetch` | Go's default OfferDirectoryFetcher factory folds into the Python WBAKeyResolver's injected directory-fetch seam (constructor default); no separate public factory symbol exists. TS keeps the createWBAOfferDirectoryFetch factory. |
| `resolvers.NewWBAKeyResolver` | — | `createWBAKeyResolver` | Go NewWBAKeyResolver factory folds into the Python class constructor (WBAKeyResolver(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the createWBAKeyResolver factory. |
| `resolvers.NewWellKnownEndpointResolver` | — | `createWellKnownEndpointResolver` | Go NewWellKnownEndpointResolver factory folds into the Python class constructor (WellKnownEndpointResolver(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the createWellKnownEndpointResolver factory. |
| `resolvers.NewWellKnownKeyResolver` | — | `createWellKnownKeyResolver` | Go NewWellKnownKeyResolver factory folds into the Python class constructor (WellKnownKeyResolver(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the createWellKnownKeyResolver factory. |
| `resolvers.WBAKeyResolverOptions` | — | `WBAKeyResolverOptions` | Go options struct / TS options object folds into Python constructor keyword arguments (WBAKeyResolver(...)); idiomatic Python has no separate options type. |
| `resolvers.WellKnownOptions` | — | `WellKnownOptions` | Go options struct (shared by the well-known key/endpoint resolvers) / TS options object folds into Python constructor keyword arguments (WellKnownKeyResolver(...) / WellKnownEndpointResolver(...)); idiomatic Python has no separate options type. |

### Go-idiomatic symbols with no cross-language face (by design)

Go constructs (functional-option builders, `errors.Is` sentinels, value types, context accessors) that Python/TS express idiomatically inline rather than as a named public symbol.

| Go symbol | why no py/ts face |
|---|---|
| `connect.BrokerClient` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.CallError` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.CallErrorKind` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.CallOption` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.ClientOption` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.EndpointResolver` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.ExecuteOption` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.NewBrokerClient` | Part of the Go-only typed Connect client; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.NewValidateInterceptor` | Go-only protovalidate interceptor (matrix SERVER-role validation row: TS/Py absent). |
| `connect.Validation` | Part of the Go-only typed Connect client validation option; see the OPEN Connect-client DECISION in docs/sdk-parity-matrix.md. |
| `connect.WithAcceptanceSigner` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithAgentKey` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithEndpointResolver` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithFetchTransport` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithHTTPClient` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithIdempotencyKey` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithInterceptors` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithKeyResolver` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithOfferKey` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithProofWindow` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithRequestIDFunc` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithRequester` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithSigner` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithValidation` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithVerification` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.AsConnectError` | Go-only Connect error mapping; TS/Python emit reject-reason tokens only (matrix SERVER-role reject-mapping row). |
| `connectserver.AttachDetail` | Go-only Connect ErrorDetail attach; TS/Python emit reject-reason tokens only (matrix SERVER-role reject-mapping row). |
| `connectserver.AttachErrorDetail` | Go-only Connect ErrorDetail attach; TS/Python emit reject-reason tokens only (matrix SERVER-role reject-mapping row). |
| `connectserver.ClassifyReject` | Go-only reject classifier; part of the Go Connect handler binding (connectserver-handler DECISION). |
| `connectserver.EmitUnpopulatedJSONCodec` | Go connect-go codec; n/a for TS/Python (no Connect binding) per the matrix Codec row. |
| `connectserver.ErrReplayed` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `connectserver.NewErrorDetail` | Go-only Connect ErrorDetail envelope build (the build half of AttachErrorDetail, exposed for callers that set a typed reason before attaching); TS/Python emit reject-reason tokens only (matrix SERVER-role reject-mapping row). |
| `connectserver.ServerOption` | Part of the Go-only Connect handler binding; see the connectserver-handler DECISION in docs/sdk-parity-matrix.md. |
| `connectserver.WithEmitUnpopulated` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithHandlerOptions` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithInterceptors` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithKeyResolver` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithMaxSignatureAge` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithMaxSignatures` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithOnReject` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithReplayStore` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithReplayTTL` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithRequestIDFunc` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithValidation` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithVerifyGate` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connectserver.WithoutReplayStore` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `core.DefaultRequestID` | Go default request-id minter; py/ts mint request-ids inline. |
| `core.DiscoveryResult` | Go per-URI discovery result carrying the fail-closed split plus the typed absence reasons; py/ts gain the same shape with their client verbs. |
| `core.ErrOfferExpired` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `core.OfferGroupResult` | Go per-URI group within a discovery result; py/ts gain the same shape with their client verbs. |
| `core.RequestIDFunc` | Go request-id function type; py/ts pass a callable inline. |
| `core.RequestIDMiddleware` | Go-only request-id middleware (matrix SERVER-role request-id row: TS/Py absent). |
| `core.SigningOption` | Go functional-option type for the signing transport; py/ts pass options objects. |
| `core.WithAppendSigner` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `core.WithSignPredicate` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `core.WithSignatureAgent` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `core.WithWindow` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `helpers.AgentBinding` | Go value struct holding the three proof header values; Python returns a tuple of them and TS returns a prepared request, so neither names a public type. |
| `helpers.AgentIDParam` | Signed-URL query-parameter name; language-idiomatic inline constant, no cross-language public face. |
| `helpers.AlgEd25519` | RFC 9421 alg tag constant; inlined per language. |
| `helpers.AllSignaturesFromContext` | Go context.Context accessor; py/ts thread multisig state explicitly. |
| `helpers.BrokerKeyIDPrefix` | Relay keyID wire-prefix constant; inlined per language. |
| `helpers.ComponentParam` | Go value type for an RFC 9421 covered-component parameter; py/ts model components inline. |
| `helpers.CoveredComponent` | Go value type for an RFC 9421 covered component; py/ts model components inline. |
| `helpers.ErrAcceptanceSignatureInvalid` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrBrokenSignatureChain` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrDigestMismatch` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrEmptyIdempotencyKey` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrEmptyMoney` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrExpired` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrFutureCreated` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrInvalidHost` | Go errors.Is sentinel for an unusable host reference; py/ts raise/throw instead of exporting sentinels. |
| `helpers.ErrInvalidKeyLength` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrKeyIDMismatch` | Go errors.Is sentinel for a keyid that is not the presented key's thumbprint; py/ts raise/throw instead of exporting sentinels. |
| `helpers.ErrMalformedSignatureInput` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrMissingContentDigest` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrMissingCreated` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrMissingExpires` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrMissingRequiredComponent` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrMissingSignature` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrMissingSignatureInput` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrMissingTargetURI` | Go errors.Is sentinel for a proof requested without the URL it binds; py/ts raise/throw instead of exporting sentinels. |
| `helpers.ErrOfferExpired` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrOfferSignatureInvalid` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrProofOfPossessionMismatch` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrSignatureLifetimeTooLong` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrSignatureVerify` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrTooManyHops` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrURLExpired` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrURLMissingExpiry` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrURLMissingSignature` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrURLNotAgentBound` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrURLSignatureInvalid` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrUnknownFields` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrUnsupportedAlgorithm` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.FromContext` | Go context.Context accessor; py/ts thread verified-request state explicitly. |
| `helpers.HostAnchored` | Go label-boundary same-host predicate. Present in Python and TS only as a private resolver helper; exporting both is tracked follow-up work. |
| `helpers.HostOf` | Go host-extraction helper behind the two routing predicates; Python and TS keep the equivalent private inside their resolver modules. |
| `helpers.IsBareHost` | Go plain-hostname predicate for the report leg's first check. No other SDK exposes an equivalent today; exporting the pair in Python and TS is tracked follow-up work. |
| `helpers.NewContext` | Go context.Context accessor; py/ts thread verified-request state explicitly. |
| `helpers.NewEd25519Signer` | Go Ed25519 Signer constructor; py/ts inject a sign function rather than constructing a named signer. |
| `helpers.NewEd25519SignerFromSeed` | Go Ed25519 Signer-from-seed constructor; py/ts inject a sign function rather than constructing a named signer. |
| `helpers.NewMultisigContext` | Go context.Context accessor; py/ts thread multisig state explicitly. |
| `helpers.PoPOptions` | Go options struct for the delivery-proof signer; Python takes the same values as keyword arguments and TS as an options object. |
| `helpers.RedactURL` | Go query-stripping helper for a signed URL headed to a log; py/ts redact inline at the log site. |
| `helpers.RetrievalAuthFailureReasonFromToken` | Go lookup from the delivery edge's refusal token to the typed enum; py/ts branch on the token string directly. |
| `helpers.SharedValidator` | Go protovalidate validator singleton; TS/Python ship no protovalidate face. |
| `helpers.SignOfferAcceptanceWith` | Go Signer-custody variant of SignOfferAcceptance so the SDK never holds the key; py/ts pass key material directly to their single acceptance signer. |
| `helpers.SignOptions` | Go options struct for SignRequest; py/ts pass options via kwargs/options objects. |
| `helpers.SignatureAgentFromContext` | Go context.Context accessor; py/ts thread signature-agent state explicitly. |
| `helpers.SignedURL` | Go signed-URL result value type; py/ts return language-native result objects. |
| `helpers.Signer` | Go Signer interface; py/ts inject a sign function (TS Ed25519SignFn; Python a signing callable) rather than a named Signer type — divergent handle shape, not a missing operation. |
| `helpers.ThumbprintBytes` | Go raw-[32]byte thumbprint variant; py/ts expose only the string thumbprint. |
| `helpers.Validate` | Go protovalidate wrapper; TS/Python ship no validation interceptor (matrix SERVER-role validation row: TS/Py absent). |
| `helpers.VerifiedRequest` | Go verified-request result value type; py/ts return language-native verdict objects. |
| `helpers.VerifiedURL` | Go verified-URL result value type (PoP via CheckProofOfPossession); py/ts expose verify_agent_binding/verifyAgentBinding. |
| `helpers.VerifyMultisigRequestResolved` | Go resolver-injected multisig-verify overload; py/ts expose a single multisig-verify entry point. |
| `helpers.VerifyOffer` | Go low-level offer-signature verify; py/ts route offer verification through the Verifier face (core.Verifier). |
| `helpers.VerifyOptions` | Go options struct for verify; py/ts pass options via kwargs/options objects. |
| `helpers.VerifyPresentedOffer` | Go low-level presented-offer freshness verify; py/ts route offer verification through the Verifier face. |
| `helpers.VerifyRequestResolved` | Go resolver-injected VerifyRequest overload; py/ts expose a single verify entry point. |
| `helpers.WithSignatureAgent` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `resolvers.ActiveKeyScanOptions` | Go scan-options struct; py/ts pass scan options inline. |
| `resolvers.Content` | Go value struct for one fetched resource; py/ts return their runtime-native body/type pair. |
| `resolvers.ContentFetchOptions` | Go options struct for the content-download leg; py/ts pass the same values as kwargs/an options object. |
| `resolvers.ContentFetcher` | Part of the Go content-download leg; the TS/Python download verbs are tracked with their unary client work. |
| `resolvers.DefaultContentTimeout` | Go default bound for one content fetch; py/ts carry the same default inline in their client. |
| `resolvers.DefaultMaxContentBytes` | Go default body cap for one content fetch; py/ts carry the same default inline in their client. |
| `resolvers.FetchError` | Go typed error for the content leg; py/ts raise/throw a runtime-native error carrying the same class and reason. |
| `resolvers.FetchFailure` | Go failure-class enum for the content leg; py/ts express the same classes as string literals. |
| `resolvers.NewContentFetcher` | Go constructor for the content-download leg; py/ts fold construction into their client. |
| `resolvers.ProofSigner` | Go interface seam that keeps key custody out of the dialing tier; py/ts inject a signing callable instead of a named interface. |
| `resolvers.SSRFCheckRedirect` | Go redirect-policy hook; py/ts fold redirect checks into the guard (async_ssrf_guard / the guarded fetch). |

## Cross-language conformance-vector replay

Go emits each `*-vectors.json` oracle; Python and TS replay it. The completeness gate holds the un-replayed count at **zero with no exemption mechanism**, so every corpus below is referenced by all three trees.

| Corpus | go | python | ts |
|---|---|---|---|
| `helpers/testdata/acceptance-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/error-detail-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/hashurl-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/idempotency-validate-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/money-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/multisig-chain-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/offer-verify-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/pop-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/scopes-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/sign-request-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/signedurl-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/thumbprint-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/verify-request-neg-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/wire-canonical-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/wire-constants-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/active-ed25519-key-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/offer-key-clamp-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/revocation-membership-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-address-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-hostset-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-redirect-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-scheme-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/wba-url-vectors.json` | ✅ | ✅ | ✅ |

