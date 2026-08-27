# SDK API-Surface Parity Matrix (go · python · ts)

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Source of truth:
       • API surface   — sdk/parity/symbol-map.json
                          (enforced against live exports by
                           sdk/python/tests/test_api_surface_parity.py)
       • Vector replay  — sdk/go/{helpers,resolvers,connect}/testdata/*-vectors.json
                          (enforced by test_corpus_replay_completeness.py)
     Regenerate:  python3 scripts/gen-parity-matrix.py
     Drift-gated in scripts/ci-local.sh. Narrative/rationale: docs/design-history.md. -->

Go is the oracle (`sdk/go/{helpers,resolvers,core,connect,connectserver}`); Python and TS mirror it. This document is **generated** from the same two artifacts CI already enforces against the code, so it cannot drift from the real surface — a mismatch fails the API-surface gate or the corpus-completeness gate before it can reach this file.

**At a glance:** 116 symbols at cross-language parity · 14 documented divergences · 174 Go-idiomatic exclusions · 33 conformance corpora, each tri-replayed.

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
| `AudienceVerdict` | `AudienceVerdict` | `AudienceVerdict` |
| `BareDomainPattern` | `BARE_DOMAIN_PATTERN` | `bareDomainPattern` |
| `CanonicalAcceptanceBytes` | `jcs_acceptance_payload` | `acceptancePayload` |
| `CanonicalOfferBytes` | `canonical_offer_payload` | `canonicalOfferPayload` |
| `CanonicalizeMoney` | `canonicalize_money` | `canonicalizeMoney` |
| `CatalogRejectionDetail` | `catalog_rejection_detail` | `catalogRejectionDetail` |
| `CheckAudience` | `check_audience` | `checkAudience` |
| `CheckRegistrationData` | `check_registration_data` | `checkRegistrationData` |
| `CompileRegistrationSchema` | `compile_registration_schema` | `compileRegistrationSchema` |
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
| `HostAnchored` | `host_anchored` | `hostAnchored` |
| `HostOf` | `host_of` | `hostOf` |
| `IsBareDomain` | `is_bare_domain` | `isBareDomain` |
| `IsBareHost` | `is_bare_host` | `isBareHost` |
| `IsSafeSchemaPattern` | `is_safe_schema_pattern` | `isSafeSchemaPattern` |
| `KeyResolver` | `KeyResolver` | `RequestKeyResolver` |
| `MaxBareDomainLen` | `MAX_BARE_DOMAIN_LEN` | `maxBareDomainLen` |
| `MaxRegistrationDataBytes` | `MAX_REGISTRATION_DATA_BYTES` | `maxRegistrationDataBytes` |
| `MaxRegistrationDataDepth` | `MAX_REGISTRATION_DATA_DEPTH` | `maxRegistrationDataDepth` |
| `MaxRegistrationDataMembers` | `MAX_REGISTRATION_DATA_MEMBERS` | `maxRegistrationDataMembers` |
| `MaxRegistrationFieldErrorPathLen` | `MAX_REGISTRATION_FIELD_ERROR_PATH_LEN` | `maxRegistrationFieldErrorPathLen` |
| `MaxRegistrationFieldErrorTextLen` | `MAX_REGISTRATION_FIELD_ERROR_TEXT_LEN` | `maxRegistrationFieldErrorTextLen` |
| `MaxRegistrationFieldErrors` | `MAX_REGISTRATION_FIELD_ERRORS` | `maxRegistrationFieldErrors` |
| `MaxRegistrationSchemaBytes` | `MAX_REGISTRATION_SCHEMA_BYTES` | `maxRegistrationSchemaBytes` |
| `MaxRegistrationSchemaDepth` | `MAX_REGISTRATION_SCHEMA_DEPTH` | `maxRegistrationSchemaDepth` |
| `MaxRegistrationSchemaEvaluations` | `MAX_REGISTRATION_SCHEMA_EVALUATIONS` | `maxRegistrationSchemaEvaluations` |
| `MaxRegistrationSchemaRefHops` | `MAX_REGISTRATION_SCHEMA_REF_HOPS` | `maxRegistrationSchemaRefHops` |
| `NewIdempotencyKey` | `generate_idempotency_key` | `generateIdempotencyKey` |
| `NormalizeScopes` | `normalize_scopes` | `normalizeScopes` |
| `OfferSignatureAlgorithm` | `OFFER_SIGNATURE_ALGORITHM` | `OFFER_SIGNATURE_ALGORITHM` |
| `ParseMoney` | `parse_money` | `parseMoney` |
| `ProtocolVersion` | `ProtocolVersion` | `ProtocolVersion` |
| `Reason` | `reason` | `reason` |
| `RegistrationDataVerdict` | `RegistrationDataVerdict` | `RegistrationDataVerdict` |
| `RegistrationFailureDetail` | `registration_failure_detail` | `registrationFailureDetail` |
| `RegistrationSchema` | `RegistrationSchema` | `RegistrationSchema` |
| `RegistrationSchemaDialect` | `REGISTRATION_SCHEMA_DIALECT` | `registrationSchemaDialect` |
| `RequestIDHeader` | `RequestIDHeader` | `RequestIDHeader` |
| `RetrievalAuthFailureDetail` | `retrieval_auth_failure_detail` | `retrievalAuthFailureDetail` |
| `SchemaVerdict` | `SchemaVerdict` | `SchemaVerdict` |
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
| `Content` | `Content` | `Content` |
| `DefaultContentTimeout` | `DEFAULT_CONTENT_TIMEOUT_SEC` | `DEFAULT_CONTENT_TIMEOUT_MS` |
| `DefaultMaxContentBytes` | `DEFAULT_MAX_CONTENT_BYTES` | `DEFAULT_MAX_CONTENT_BYTES` |
| `ErrDirectoryUnavailable` | `DirectoryUnavailableError` | `DirectoryUnavailable` |
| `ErrEndpointRefused` | `EndpointRefusedError` | `EndpointRefused` |
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
| `DiscoveryResult` | `DiscoveryResult` | `DiscoveryResult` |
| `Mode` | `Mode` | `Mode` |
| `MonotonicWindow` | `monotonic_window` | `monotonicWindow` |
| `NewSigningTransport` | `SigningTransport` | `createSigningTransport` |
| `OfferGroupResult` | `OfferGroupResult` | `OfferGroupResult` |
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
| `BrokerClient` | `BrokerClient` | `BrokerClient` |
| `CallError` | `CallError` | `RampCallError` |
| `CallErrorKind` | `CallErrorKind` | `CallErrorKind` |
| `Client` | `Client` | `Client` |
| `DefaultCallTimeout` | `DEFAULT_CALL_TIMEOUT_SEC` | `DEFAULT_CALL_TIMEOUT_MS` |
| `DefaultMaxRPCReadBytes` | `DEFAULT_MAX_RPC_READ_BYTES` | `DEFAULT_MAX_RPC_READ_BYTES` |
| `EndpointResolver` | `EndpointResolver` | `EndpointResolver` |
| `ErrorDetailFrom` | `error_detail_from` | `errorDetailFrom` |
| `Validation` | `Validation` | `Validation` |

### connectserver — server-verify handler binding

| Go | python | ts |
|---|---|---|
| `RejectReason` | `RejectReason` | `RejectReason` |

## Documented divergences & DECISIONs

Deliberate, reason-backed asymmetries. The allowlist is **shrink-only** — a new undocumented gap cannot ship green. Each entry's rationale is the `allowlist_reason` from the symbol map; DECISION anchors are cross-checked by `test_api_surface_parity.py`.

### Architectural DECISIONs

- **DECISION — full Connect handler binding.** Go-only full Connect Broker handler binding — OPEN DECISION in docs/sdk-parity-matrix.md _(symbols: `connectserver.NewBrokerServiceHandler`, `connectserver.NewExchangeServiceHandler`)_

### Mapped symbols with an intentional per-language gap

| Go symbol | python | ts | rationale |
|---|---|---|---|
| `connect.NewBrokerClient` | — | `createBrokerClient` | Go NewX factory folds into the Python class constructor (BrokerClient(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the create* object-factory prefix. |
| `connect.NewClient` | — | `createClient` | Go NewX factory folds into the Python class constructor (Client(...)); idiomatic Python exposes the class, not a separate factory symbol. TS keeps the create* object-factory prefix. |
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
| `connect.CallMalformed` | Member of the mapped connect.CallErrorKind enum. Go declares each as a package-level constant; Python spells it CallErrorKind.<NAME> and TypeScript as a member of the CallErrorKind literal union, so neither is a top-level export the surface enumerator can see. The TYPE carries the parity claim and the shared corpora pin the values. |
| `connect.CallNotSent` | Member of the mapped connect.CallErrorKind enum. Go declares each as a package-level constant; Python spells it CallErrorKind.<NAME> and TypeScript as a member of the CallErrorKind literal union, so neither is a top-level export the surface enumerator can see. The TYPE carries the parity claim and the shared corpora pin the values. |
| `connect.CallNotSignable` | Member of the mapped connect.CallErrorKind enum. Go declares each as a package-level constant; Python spells it CallErrorKind.<NAME> and TypeScript as a member of the CallErrorKind literal union, so neither is a top-level export the surface enumerator can see. The TYPE carries the parity claim and the shared corpora pin the values. |
| `connect.CallOption` | Go functional-option type for the per-call knobs; py/ts pass options objects (TS ClientOptions / CallOptions, Python ClientConfig and keyword arguments). |
| `connect.CallRefused` | Member of the mapped connect.CallErrorKind enum. Go declares each as a package-level constant; Python spells it CallErrorKind.<NAME> and TypeScript as a member of the CallErrorKind literal union, so neither is a top-level export the surface enumerator can see. The TYPE carries the parity claim and the shared corpora pin the values. |
| `connect.CallTooLarge` | Member of the mapped connect.CallErrorKind enum. Go declares each as a package-level constant; Python spells it CallErrorKind.<NAME> and TypeScript as a member of the CallErrorKind literal union, so neither is a top-level export the surface enumerator can see. The TYPE carries the parity claim and the shared corpora pin the values. |
| `connect.CallUnknown` | Member of the mapped connect.CallErrorKind enum. Go declares each as a package-level constant; Python spells it CallErrorKind.<NAME> and TypeScript as a member of the CallErrorKind literal union, so neither is a top-level export the surface enumerator can see. The TYPE carries the parity claim and the shared corpora pin the values. |
| `connect.CallUnreachable` | Member of the mapped connect.CallErrorKind enum. Go declares each as a package-level constant; Python spells it CallErrorKind.<NAME> and TypeScript as a member of the CallErrorKind literal union, so neither is a top-level export the surface enumerator can see. The TYPE carries the parity claim and the shared corpora pin the values. |
| `connect.ClientOption` | Go functional-option type for the client; py/ts pass options objects (TS ClientOptions / CallOptions, Python ClientConfig and keyword arguments). |
| `connect.ExecuteOption` | Go type alias kept for continuity with the original execute-only option name; py/ts have one per-call options shape and no alias to mirror. |
| `connect.NewValidateInterceptor` | Go protovalidate interceptor. The two JSON clients DO check an outbound request, against its generated model rather than through an interceptor — a field-level check, not protovalidate's cross-field CEL — so what has no counterpart is the interceptor, not the validation (see connect.Validation). |
| `connect.ValidationOff` | Member of the mapped connect.Validation enum. Python and TypeScript spell it as a literal ("off" / "strict") rather than a named export. The defaults differ deliberately and that divergence is recorded in docs/design-history.md, not here. |
| `connect.ValidationStrict` | Member of the mapped connect.Validation enum. Python and TypeScript spell it as a literal ("off" / "strict") rather than a named export. The defaults differ deliberately and that divergence is recorded in docs/design-history.md, not here. |
| `connect.WithAgentKey` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithClientOptions` | Go escape hatch for raw connectrpc.ClientOption values, mirroring connectserver.WithHandlerOptions; py/ts have no Connect option type to pass through. |
| `connect.WithContentTimeout` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithEndpointResolver` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithGuardedBaseTransport` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithHTTPClient` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithIdempotencyKey` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithInterceptors` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithKeyResolver` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithMaxContentBytes` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithOfferKey` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithProofWindow` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithRequestIDFunc` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithRequester` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithSignWindow` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `connect.WithSignatureAgent` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
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
| `connectserver.ReasonBrokenChain` | Member of the mapped connectserver.RejectReason enum. Python spells it RejectReason.<NAME> and TypeScript as a literal-union member; neither is a top-level export. |
| `connectserver.ReasonHopBudget` | Member of the mapped connectserver.RejectReason enum. Python spells it RejectReason.<NAME> and TypeScript as a literal-union member; neither is a top-level export. |
| `connectserver.ReasonReplay` | Member of the mapped connectserver.RejectReason enum. Python spells it RejectReason.<NAME> and TypeScript as a literal-union member; neither is a top-level export. |
| `connectserver.ReasonSignature` | Member of the mapped connectserver.RejectReason enum. Python spells it RejectReason.<NAME> and TypeScript as a literal-union member; neither is a top-level export. |
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
| `core.ErrOfferExpired` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `core.Off` | Member of the mapped core.Mode enum. Python spells it Mode.STRICT / Mode.OFF and TypeScript as the literal "strict" / "off". |
| `core.RequestIDFunc` | Go request-id function type; py/ts pass a callable inline. |
| `core.RequestIDMiddleware` | Go-only request-id middleware (matrix SERVER-role request-id row: TS/Py absent). |
| `core.SigningOption` | Go functional-option type for the signing transport; py/ts pass options objects. |
| `core.Strict` | Member of the mapped core.Mode enum. Python spells it Mode.STRICT / Mode.OFF and TypeScript as the literal "strict" / "off". |
| `core.WithAppendSigner` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `core.WithSignPredicate` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `core.WithSignatureAgent` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `core.WithWindow` | Go functional-option builder; py/ts pass options via kwargs/options objects. |
| `helpers.AgentBinding` | Go value struct holding the three proof header values; Python returns a tuple of them and TS returns a prepared request, so neither names a public type. |
| `helpers.AgentIDParam` | Signed-URL query-parameter name; language-idiomatic inline constant, no cross-language public face. |
| `helpers.AlgEd25519` | RFC 9421 alg tag constant; inlined per language. |
| `helpers.AllSignaturesFromContext` | Go context.Context accessor; py/ts thread multisig state explicitly. |
| `helpers.AudienceAccepted` | Member of the mapped helpers.AudienceVerdict vocabulary. Python and TypeScript spell it as a literal rather than a named export, and the shared audience corpus pins the token every language must answer. |
| `helpers.AudienceEmpty` | Member of the mapped helpers.AudienceVerdict vocabulary. Python and TypeScript spell it as a literal rather than a named export, and the shared audience corpus pins the token every language must answer. |
| `helpers.AudienceMalformed` | Member of the mapped helpers.AudienceVerdict vocabulary. Python and TypeScript spell it as a literal rather than a named export, and the shared audience corpus pins the token every language must answer. |
| `helpers.AudienceMismatch` | Member of the mapped helpers.AudienceVerdict vocabulary. Python and TypeScript spell it as a literal rather than a named export, and the shared audience corpus pins the token every language must answer. |
| `helpers.AudienceNoVerdict` | Member of the mapped helpers.AudienceVerdict vocabulary. Python and TypeScript spell it as a literal rather than a named export, and the shared audience corpus pins the token every language must answer. |
| `helpers.BrokerKeyIDPrefix` | Relay keyID wire-prefix constant; inlined per language. |
| `helpers.CheckRegistrationDataStruct` | Go-only raw-Struct face of the mapped helpers.CheckRegistrationData, and deliberately absent from the ports: it exists because a payload with NO JSON REPRESENTATION loses the evidence for that when Go converts a Struct to a map. The class has two members and the conversion erases both — a non-finite number becomes the string "NaN", "Infinity" or "-Infinity", which a payload may also carry legitimately, and a Value with no member of its kind oneof set becomes nil, which is also what a real JSON null gives — so the check has to run before the conversion. Python and TypeScript are handed a decoded object rather than protobuf nodes: it keeps the real float, so their check_registration_data / checkRegistrationData already see the non-finite member, and the unset-kind member has no spelling in either language. A second entry point there would be an alias with nothing to do. The verdict vocabulary is what the three share, and the registration-schema corpus pins it; neither member has a vector in any language, because JSON cannot write either value down. |
| `helpers.ComponentParam` | Go value type for an RFC 9421 covered-component parameter; py/ts model components inline. |
| `helpers.CoveredComponent` | Go value type for an RFC 9421 covered component; py/ts model components inline. |
| `helpers.ErrAcceptanceSignatureInvalid` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrAudienceIdentity` | Go errors.Is sentinel for an unusable configured Exchange identity; py/ts raise/throw instead of exporting sentinels. |
| `helpers.ErrBrokenSignatureChain` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrDigestMismatch` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrEmptyIdempotencyKey` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrEmptyMoney` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrExpired` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrFutureCreated` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrInvalidHost` | Go errors.Is sentinel for an unusable host reference; py/ts raise/throw instead of exporting sentinels. |
| `helpers.ErrInvalidKeyLength` | Go errors.Is sentinel; py/ts express verification failures via typed failure unions / exception classes, not per-reason named sentinels. |
| `helpers.ErrInvalidPoPInput` | Go errors.Is sentinel for a proof input that cannot be written into a signature base; py/ts raise/throw instead of exporting sentinels. |
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
| `helpers.NewContext` | Go context.Context accessor; py/ts thread verified-request state explicitly. |
| `helpers.NewEd25519Signer` | Go Ed25519 Signer constructor; py/ts inject a sign function rather than constructing a named signer. |
| `helpers.NewEd25519SignerFromSeed` | Go Ed25519 Signer-from-seed constructor; py/ts inject a sign function rather than constructing a named signer. |
| `helpers.NewMultisigContext` | Go context.Context accessor; py/ts thread multisig state explicitly. |
| `helpers.PoPOptions` | Go options struct for the delivery-proof signer; Python takes the same values as keyword arguments and TS as an options object. |
| `helpers.RedactURL` | Go query-stripping helper for a signed URL headed to a log; py/ts redact inline at the log site. |
| `helpers.RegistrationDataAccepted` | Member of the mapped helpers.RegistrationDataVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.RegistrationDataNoVerdict` | Member of the mapped helpers.RegistrationDataVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.RegistrationDataTooDeep` | Member of the mapped helpers.RegistrationDataVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.RegistrationDataTooLarge` | Member of the mapped helpers.RegistrationDataVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.RegistrationDataTooManyMembers` | Member of the mapped helpers.RegistrationDataVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.RegistrationDataUncanonicalizable` | Member of the mapped helpers.RegistrationDataVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.RegistrationSchemaCompileTimeout` | Go-only wall-clock backstop on compilation, not part of the accepted/refused contract and deliberately absent from the ports: Go's runtime preempts, while a CPU-bound spin holds CPython's interpreter and blocks Node's event loop, so a timer there cannot interrupt the work it names. What bounds all three identically is static — the size, depth and evaluation caps and the pattern alphabet — and no admitted schema should ever reach this timeout. |
| `helpers.RetrievalAuthFailureReasonFromToken` | Go lookup from the delivery edge's refusal token to the typed enum; py/ts branch on the token string directly. |
| `helpers.SchemaAccepted` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaCompileTimeout` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaMalformed` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaNoVerdict` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaNotPublished` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaRefChainTooLong` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaRefCycle` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaRemoteRef` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaTooComplex` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaTooDeep` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaTooLarge` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaUncompilable` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaUnsafePattern` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
| `helpers.SchemaWrongDialect` | Member of the mapped helpers.SchemaVerdict vocabulary. Python and TypeScript spell it as a literal; the shared registration-schema corpus pins the token. |
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
| `resolvers.ContentFetchOptions` | Go options struct for the content-download leg; TS passes the same values as an options object to its fetch, Python as ClientConfig fields. |
| `resolvers.ContentFetcher` | Go value that owns the content-download leg; py/ts fold it into the client's fetch verb, which is the only caller either has. |
| `resolvers.FetchError` | Go typed error for the content leg; py/ts report a delivery failure through the client's own CallError, so a caller branches on one failure type for every verb. |
| `resolvers.FetchFailure` | Go failure-class enum for the content leg; py/ts fold the same classes into CallErrorKind rather than carrying a second, parallel taxonomy. |
| `resolvers.FetchMalformed` | Member of the resolvers.FetchFailure enum, which is itself a documented Go-only divergence — the ports fold the same classes into CallErrorKind. The shared content-fetch corpus pins the class every language must answer. |
| `resolvers.FetchNotSignable` | Member of the resolvers.FetchFailure enum, which is itself a documented Go-only divergence — the ports fold the same classes into CallErrorKind. The shared content-fetch corpus pins the class every language must answer. |
| `resolvers.FetchRefused` | Member of the resolvers.FetchFailure enum, which is itself a documented Go-only divergence — the ports fold the same classes into CallErrorKind. The shared content-fetch corpus pins the class every language must answer. |
| `resolvers.FetchTooLarge` | Member of the resolvers.FetchFailure enum, which is itself a documented Go-only divergence — the ports fold the same classes into CallErrorKind. The shared content-fetch corpus pins the class every language must answer. |
| `resolvers.FetchUnknown` | Member of the resolvers.FetchFailure enum, which is itself a documented Go-only divergence — the ports fold the same classes into CallErrorKind. The shared content-fetch corpus pins the class every language must answer. |
| `resolvers.FetchUnreachable` | Member of the resolvers.FetchFailure enum, which is itself a documented Go-only divergence — the ports fold the same classes into CallErrorKind. The shared content-fetch corpus pins the class every language must answer. |
| `resolvers.NewContentFetcher` | Go constructor for the content-download leg; py/ts fold construction into their client, so there is no fetcher to build separately. |
| `resolvers.NewGuardedTransport` | Go constructor composing the SSRF guard over a caller's base transport; py/ts expose their guarded fetch as a single factory with no separable base. |
| `resolvers.ProofSigner` | Go interface seam that keeps key custody out of the dialing tier; py/ts inject a signing callable instead of a named interface. |
| `resolvers.SSRFCheckRedirect` | Go redirect-policy hook; py/ts fold redirect checks into the guard (async_ssrf_guard / the guarded fetch). |

## Cross-language conformance-vector replay

Go emits each `*-vectors.json` oracle; Python and TS replay it. The completeness gate holds the un-replayed count at **zero with no exemption mechanism**, so every corpus below is referenced by all three trees.

| Corpus | go | python | ts |
|---|---|---|---|
| `helpers/testdata/acceptance-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/audience-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/error-detail-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/hashurl-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/host-rule-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/idempotency-validate-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/money-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/multisig-chain-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/offer-verify-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/pop-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/registration-schema-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/scopes-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/sign-request-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/signedurl-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/thumbprint-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/verify-request-neg-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/wire-canonical-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/wire-constants-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/wire-names-vectors.json` | ✅ | ✅ | ✅ |
| `helpers/testdata/wire-null-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/active-ed25519-key-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/content-fetch-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/endpoint-vet-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/offer-key-clamp-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/revocation-membership-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-address-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-hostset-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-redirect-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/ssrf-scheme-vectors.json` | ✅ | ✅ | ✅ |
| `resolvers/testdata/wba-url-vectors.json` | ✅ | ✅ | ✅ |
| `connect/testdata/client-request-vectors.json` | ✅ | ✅ | ✅ |
| `connect/testdata/connect-error-vectors.json` | ✅ | ✅ | ✅ |
| `connect/testdata/transport-failure-vectors.json` | ✅ | ✅ | ✅ |

