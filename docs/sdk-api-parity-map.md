# RAMP SDK Cross-Language Parity + Naming Audit

Scope: `sdk/{go,python,ts}` in `github.com/RAMP-Protocol/protocol`. Read-only audit.
Go is the oracle (emits `testdata/*-vectors.json`); Python + TS replay.

---

## Q4 — The well-known URL builder / WellKnownEndpointResolver (ANSWER FIRST)

**A consumer CAN call an SDK `WellKnownEndpointResolver` directly in all three languages. The app's hand-rolled `endpoint_resolver.py` is now redundant — but there is a genuine, narrower gap the app also hit: there is NO pure "well-known URL builder" function in any language, and no `RAMP_WELLKNOWN_SCHEME` env plumbing in the SDK at all.**

Present in all three, same shape:

| | symbol | URL it builds | scheme source |
|---|---|---|---|
| Go | `resolvers.NewWellKnownEndpointResolver(WellKnownOptions).ResolveEndpoint(ctx, host)` | `{scheme}://{host}/.well-known/ramp.json` | `opts.Scheme` (default `https`) |
| Python | `resolvers.WellKnownEndpointResolver(scheme=...).resolve_endpoint(host)` | same | `scheme=` kwarg (default `https`) |
| TS | `newWellKnownEndpointResolver({scheme}).resolveEndpoint(host)` | same | `opts.scheme` (default `https`) |

So the app claim "could not import an SDK builder" is **partially real, partially stale**:

1. **The full host-keyed endpoint resolver EXISTS in Python** (`ramp_sdk.resolvers.WellKnownEndpointResolver`, exported from both `ramp_sdk.resolvers` and top-level `ramp_sdk`). The app's `src/mcp/.../endpoint_resolver.py` duplicates it (the file's own docstring admits this: "the RAMP-96 work should absorb/relocate it later"). **The duplication is removable today** — swap the hand-rolled resolver for `ramp_sdk.resolvers.WellKnownEndpointResolver`.

2. **But no language exposes scheme selection from `RAMP_WELLKNOWN_SCHEME`.** `RAMP_WELLKNOWN_SCHEME` appears ONLY in the app (`offer_verify._wba_url`, `endpoint_resolver`, `broker.py`), NEVER in the SDK. The SDK takes scheme as an explicit option. The app reads the env itself and passes it in — that thin env-read is legitimately app-side glue and is NOT something the SDK provides.

3. **There is no pure `wellKnownUrl(host, scheme)` / `wbaUrl(host, scheme)` string builder anywhere.** `offer_verify._wba_url` builds `{scheme}://{host}/.well-known/http-message-signatures-directory` by hand. The SDK only exposes the path *constant* (`WBADirectoryPath` in Go / `_WBA_DIRECTORY_PATH` Python-private / `WBA_DIRECTORY_PATH` TS-private) and buries URL assembly inside the resolvers. **The one true "builder" gap: no exported pure URL-assembly helper**, so any consumer that needs the URL string (not the fetch+cache resolver) must still hand-roll `scheme + "://" + host + PATH`. That is why `_wba_url` exists — and it cannot be replaced by the endpoint resolver because it targets the WBA directory path, not `ramp.json`.

**Bottom line for the app:** `endpoint_resolver.py` → delete, use `ramp_sdk.resolvers.WellKnownEndpointResolver`. `_wba_url` → still needs a hand-roll OR a new SDK export (`WBADirectoryPath` should be made a *public* Python/TS constant, and ideally a `wba_directory_url(host, scheme)` helper added across all three).

---

## Summary counts

- **GAP: 6** (symbols missing in Python and/or TS)
- **DIVERGENT: 4** (present but different signature/name/behavior)
- **UNTESTED-PARITY: 7** (same shape in all 3, but NO cross-language corpus vector)
- **Naming-smell: 7** (`new`-prefixed / PascalCase factories transliterated from Go's `NewX`)

The corpus-completeness gate (`python/tests/test_corpus_replay_completeness.py`) is strong: it enumerates every `testdata/*-vectors.json` and hard-fails CI unless each is referenced by a Go emitter AND a Python replay AND a TS replay, with **no exemption mechanism**. This means every *vectored* behavior is genuinely tri-replayed. UNTESTED-PARITY below is therefore exclusively behavior with **no vector at all** (network IO, caching, single-flight, outbound transport) — parity asserted by convention, not by test.

---

## Parity table

Legend: ✅ present · ❌ absent · ⚠️ present-but-divergent. Verdict column is the classification.

### Resolvers / well-known / WBA / offer-key

| symbol (Go) | go | python | ts | verdict |
|---|---|---|---|---|
| `WellKnownKeyResolver` / `NewWellKnownKeyResolver` | ✅ | ✅ `WellKnownKeyResolver` | ✅ `newWellKnownKeyResolver` | UNTESTED-PARITY (fetch+TTL+single-flight, no vector) |
| `WellKnownEndpointResolver` / `NewWellKnownEndpointResolver` / `ResolveEndpoint` | ✅ | ✅ `resolve_endpoint` | ✅ `resolveEndpoint` | UNTESTED-PARITY (host-keyed fetch/cache, no vector) |
| `WBAKeyResolver` / `NewWBAKeyResolver` / `.Resolve` / `.Run` / `.Revoked` | ✅ | ✅ `WBAKeyResolver` (+poller) | ✅ `newWBAKeyResolver` | UNTESTED-PARITY (revocation *membership* IS vectored; fetch/poll loop is not) |
| `ActiveEd25519Key` (+`WithExpiry`/`Screened`/`WithExpiryScreened`) | ✅ | ✅ `active_ed25519_key` ×4 | ✅ `activeEd25519Key` ×4 | **PARITY** (active-ed25519-key-vectors.json) |
| revocation membership | ✅ | ✅ | ✅ | **PARITY** (revocation-membership-vectors.json) |
| `CachedOfferKeyResolver` / `NewCachedOfferKeyResolver` / `DirectoryFetch`/`OfferDirectoryFetcher` | ✅ | ✅ `CachedOfferKeyResolver`,`DirectoryFetch` | ❌ | **GAP** (TS has no offer-key cache) |
| `NewWBADirectoryFetcher` | ✅ | ⚠️ (folded into app seam) | ❌ | GAP/DIVERGENT |
| `WBADirectoryPath` (public path const) | ✅ public | ⚠️ `_WBA_DIRECTORY_PATH` (private) | ⚠️ `WBA_DIRECTORY_PATH` (module-private, not exported) | DIVERGENT (Go public, py/ts private) |

### SSRF + guarded HTTP client

| symbol (Go) | go | python | ts | verdict |
|---|---|---|---|---|
| `SSRFGuard` / `SSRFCheckRedirect` (address/scheme/redirect/hostset logic) | ✅ | ✅ `ssrf_guard`,`blocked_address` | ✅ `ssrfGuard`,`blockedAddress`,`allowedScheme` | **PARITY** (ssrf-address/scheme/redirect/hostset vectors, all tri-replayed) |
| `NewGuardedClientFromEnv` (SKIP_SSRF / ALLOW_INSECURE two-flag) | ✅ | ✅ `guarded_client`/`guarded_async_client` | ✅ `guardedFetchFromEnv` | DIVERGENT-NAME (env semantics parity ✅; factory names differ) |

### Signing / SigningTransport / signed URL / offer

| symbol (Go) | go | python | ts | verdict |
|---|---|---|---|---|
| `core.NewSigningTransport` / `SigningOption` (`WithWindow`/`WithAppendSigner`/`WithSignatureAgent`/`WithSignPredicate`) | ✅ | ✅ `SigningTransport`,`SignedOutbound` (NOT in `__all__`) | ❌ | **GAP** (TS has no outbound signing transport; only `buildRequestSignatureBase` primitive) |
| `SignRequest` / `AppendSignature` / `ContentDigest` | ✅ | ✅ `sign_request`,`append_signature`,`content_digest` | ✅ (via core/sign-request primitives) | **PARITY** (sign-request-vectors.json) |
| `VerifyRequest*` / `VerifyMultisigRequest*` | ✅ | ✅ `verify_request`,`verify_request_server`,`verify_multisig_request_server` | ✅ `verify.ts`,`core/verify-request`,`verify-multisig-request` | **PARITY** (verify-request-neg + multisig-chain vectors) |
| `SignOffer` / `VerifyOffer` / `VerifyPresentedOffer` | ✅ | ✅ `sign_offer_jcs` (+`verify_offer_acceptance_jcs`) | ✅ `signOffer` / core `Verifier` | **PARITY** (offer-verify + offer-sign vectors) |
| `SignURLEd25519` / `VerifyURLEd25519` / `CheckProofOfPossession` | ✅ | ✅ `sign_ed25519_signed_url`,`verify_ed25519_signed_url` | ✅ `signurl.ts` `canonicalUrl`, `verify.ts` | **PARITY** (signedurl + pop vectors) |
| `SignOfferAcceptance` / `VerifyOfferAcceptance` | ✅ | ✅ `sign_offer_acceptance(_jcs)` | ✅ `acceptance.ts` `acceptancePayload` | **PARITY** (acceptance-vectors.json) |
| PoP `sign_agent_binding`/`verify_agent_binding` | ✅ (`CheckProofOfPossession`) | ✅ | ✅ `pop.ts` | **PARITY** (pop-vectors.json) |
| `Signer` / `NewEd25519Signer(FromSeed)` | ✅ | ⚠️ (seed passed directly to funcs) | ⚠️ (`CryptoKey` passed directly) | DIVERGENT-by-runtime (acceptable: crypto handle shape differs per lang) |

### Thumbprint / canonicalization / money / idempotency / scopes / wire / error-detail

| symbol (Go) | go | python | ts | verdict |
|---|---|---|---|---|
| `Thumbprint` / `ThumbprintBytes` | ✅ | ✅ `thumbprint` | ✅ `thumbprint` | **PARITY** (thumbprint-vectors.json) |
| JCS canonical offer/acceptance payload | ✅ (`SignOffer` path) | ✅ `canonical_offer_payload`,`jcs_acceptance_payload` | ✅ `canonicalOfferPayload`, `fromWireOffer` | **PARITY** (wire-canonical + offer vectors) |
| `ParseMoney`/`FormatMoney`/`CanonicalizeMoney` | ✅ | ✅ `parse_money`,`format_money`,`canonicalize_money` | ✅ `parseMoney`,`formatMoney`,`canonicalizeMoney` | **PARITY** (money-vectors.json) |
| `NewIdempotencyKey` (generate) | ✅ | ✅ `new_idempotency_key` | ✅ `newIdempotencyKey` | UNTESTED-PARITY (random output → format only spot-checked; not corpus-locked) |
| `ValidateIdempotencyKey` | ✅ | ✅ `validate_idempotency_key` | ✅ `validateIdempotencyKey` | **PARITY** (idempotency-validate-vectors.json) |
| `NormalizeScopes`/`ScopesSubset`/`ApplyScopes` | ✅ | ✅ | ✅ | **PARITY** (scopes-vectors.json) |
| wire constants (`ContentTypeJSON`, `RequestIDHeader`, `SignatureAgentHeader`, …) | ✅ | ✅ | ✅ | **PARITY** (wire-constants-vectors.json) |
| `HashURL` | ✅ | ✅ `hash_url` | ✅ `hashUrl` | **PARITY** (hashurl-vectors.json) |
| cross-field CEL `ValidationRuleIDs` | ✅ | ✅ `cross_field_rule_ids` | ✅ `crossFieldRuleIds` | **PARITY** (crossfield parity test) |
| error-detail parse: `Reason`/`ErrorDetailFrom`/`parseErrorDetail` | ✅ (`connect.ErrorDetailFrom`, `helpers.Reason`) | ✅ `error_detail_from`,`parse_error_detail`,`reason` | ✅ `errorDetailFrom`,`parseErrorDetail`,`reason` | **PARITY** (error-detail-vectors.json) |
| domain detail builders (`TransactionDenialDetail`, `CatalogRejectionDetail`, `RetrievalAuthFailureDetail`, `DisputeFailureDetail`, `RegistrationFailureDetail`, `DomainVerificationFailureDetail`, `UsageReportRejectionDetail`) | ✅ (7 builders) | ❌ (only generic `error_detail_from`) | ❌ | **GAP** (Go-only typed detail constructors) |

### Connect client / connectserver (transport layer)

| symbol (Go) | go | python | ts | verdict |
|---|---|---|---|---|
| `connect.Client` / `NewClient` / `.Discover` / `.Execute` / `ClientOption`s | ✅ | ❌ | ❌ | **DECISION** — Go-only client is an intentional runtime-native divergence (TS edge zero-RPC; Python shim's 3 legs are single non-orchestration RPCs, no `gen/` client substrate). Recorded in `sdk-parity-matrix.md`; reopen only for multi-RPC Discover→Execute orchestration. |
| `connectserver` handlers (`NewExchangeServiceHandler`, `NewBrokerServiceHandler`, `AttachErrorDetail`, `ClassifyReject`, `AsConnectError`, `EmitUnpopulatedJSONCodec`, `ServerOption`s) | ✅ | ⚠️ `verify_request_server` only | ⚠️ `hono/middleware.rampVerify` only | DIVERGENT-by-runtime (server adapter is transport-specific; verify-gate parity exists, handler wiring does not) |
| `core.Verifier` / `NewVerifier` / `Mode` / `RejectedOffer` / `VerifiedOffer` / `Result` | ✅ | ✅ `Verifier`,`Mode`,`VerifiedOffer`,`RejectedOffer`,`Result` | ✅ `Verifier`,`NewVerifier`,`Mode`,… | **PARITY** (core-offer-verify parity test) — but see naming smell `NewVerifier` (TS) |
| `RequestIDMiddleware` / `DefaultRequestID` / `ClockWindow` / `MonotonicWindow` | ✅ | ✅ `clock_window`,`monotonic_window`,`Window` | ✅ `clockWindow`,`monotonicWindow` | **PARITY** (request-id middleware Go-only, windows tri-present) |

---

## Prioritized GAP list (by consumer impact)

1. **TS `CachedOfferKeyResolver` — MISSING.** Go + Python both ship `CachedOfferKeyResolver` (offer-key/active-key selection with directory fetch + TTL cache); TS `resolvers/` has no offer-key cache module at all. Any TS Broker/consumer that needs to resolve an `Offer.exchange` signing key must hand-roll fetch+active-key-select+cache. High impact — this is core routing machinery.
2. **TS SigningTransport — MISSING.** Go `core.NewSigningTransport` and Python `SigningTransport` wrap an outbound `http`/httpx transport to auto-sign every RAMP request (RFC 9421 + window + append-signer + signature-agent). TS has only the low-level `buildRequestSignatureBase` primitive, so a TS client must assemble signing by hand. High impact for any TS-side outbound caller.
3. **Python `SigningTransport` present but NOT barrel-exported.** `ramp_sdk/signing_transport.py` exists with `SigningTransport`/`SignedOutbound` but neither is in `ramp_sdk.__all__` — consumers must reach into the submodule. Half-shipped surface; add to `__all__`.
4. **No pure well-known / WBA URL builder in any language (Q4 root gap).** URL assembly is trapped inside the stateful resolvers; `WBADirectoryPath` is public only in Go (`_WBA_DIRECTORY_PATH` / `WBA_DIRECTORY_PATH` are private in py/ts). Consumers that need the URL string (e.g. the app's `_wba_url`) must hand-roll. Fix: export the path constant in py/ts + add `wba_directory_url(host, scheme)` / `well_known_url(host, scheme)` helpers across all three.
5. **Go-only typed error-detail builders (7 of them).** `TransactionDenialDetail`, `CatalogRejectionDetail`, `RetrievalAuthFailureDetail`, `DisputeFailureDetail`, `RegistrationFailureDetail`, `DomainVerificationFailureDetail`, `UsageReportRejectionDetail` have no py/ts counterpart — py/ts can only parse details, not construct typed ones. Medium impact (only servers emit; Go is the server today).
6. **Go-only Connect client (`connect.Client`) — RESOLVED as an intentional divergence.** Discover/Execute convenience client is Go-only. py/ts are edge/agent roles that mostly verify, not orchestrate: TS edge makes zero outbound RPC, and the Python shim's three legs (Broker Resolve, broker-relay execute, exchange-direct ReportUsage) are single fire-and-forget RPCs already DRY via `outbound.py`, not the multi-RPC Discover→Execute lifecycle. No `gen/` client substrate. Documented as a DECISION in `sdk-parity-matrix.md` — no longer a silent gap.

---

## UNTESTED-PARITY list (same shape in all 3, no cross-language vector)

These are corpus-completeness blind spots — parity asserted by hand-porting, not locked by a replayed vector. Because they involve network IO / caching / timing, they are structurally hard to vector, but they are exactly where silent divergence hides:

1. `WellKnownKeyResolver` fetch + TTL + single-flight coalescing behavior.
2. `WellKnownEndpointResolver` host-keyed fetch/cache/flight (the Q4 surface).
3. `WBAKeyResolver` directory fetch + `.Run` revocation-poll loop + far-future as_of clamp (only the revocation *membership* decision is vectored; the poll/refresh orchestration is not).
4. `CachedOfferKeyResolver` cache/clamp/single-flight (and it's TS-absent anyway — see GAP 1).
5. `NewGuardedClientFromEnv` / `guarded_client` / `guardedFetchFromEnv` — the SSRF *address/scheme/redirect* decisions ARE vectored, but the env-flag → client-assembly wiring (which flag toggles which guard, default-on/off) is only per-language unit-tested, not cross-replayed.
6. `SigningTransport` outbound auto-sign round-trip (Go+Python; TS absent).
7. `NewIdempotencyKey` generation (random; only the *validate* side is vectored — the generated format/charset/length is not cross-checked against a shared expectation).

---

## Naming hygiene list

**DO NOT FLAG Go `NewX`.** `NewWellKnownEndpointResolver`, `NewWBAKeyResolver`, `NewStaticKeyResolver`, `NewIdempotencyKey`, `NewCachedOfferKeyResolver`, `NewGuardedClientFromEnv`, `NewVerifier`, `NewClient`, `NewEd25519Signer`, etc. are **idiomatic Go and required by revive/golint** (constructor convention). Leave every Go `NewX` exactly as-is; "fixing" them would break lint and Go convention.

Non-idiomatic transliterations of Go's `NewX` into other languages:

| language | current symbol | file | why it smells | idiomatic target |
|---|---|---|---|---|
| TS | `newWellKnownEndpointResolver` | `ts/resolvers/wellknown.ts` | `new`-prefixed factory returning an interface; TS reserves `new` for the operator | drop prefix → `wellKnownEndpointResolver(...)` or `createWellKnownEndpointResolver(...)`, or export the class |
| TS | `newWellKnownKeyResolver` | `ts/resolvers/wellknown.ts` | same | `wellKnownKeyResolver` / `createWellKnownKeyResolver` |
| TS | `newWBAKeyResolver` | `ts/resolvers/wba.ts` | same | `wbaKeyResolver` / `createWbaKeyResolver` |
| TS | `newStaticKeyResolver` | `ts/resolvers/static.ts` | same | `staticKeyResolver` / `createStaticKeyResolver` |
| TS | `newIdempotencyKey` | `ts/src/idempotency.ts` | borderline — reads as verb "make a new key" — but still a Go-ism; inconsistent with the rest of the pure-helper module (`validateIdempotencyKey`, `parseMoney`) | `generateIdempotencyKey` or `createIdempotencyKey` (verb-first) |
| TS | `NewVerifier` | `ts/core/verifier.ts` | **PascalCase function** — worst offender: PascalCase in TS signals a class/constructor, but this is a plain factory function; a straight `s/New/`-transliteration of Go `NewVerifier` | `newVerifier`→ no; use `createVerifier(...)` or export `Verifier` class + `Verifier.create(...)` |
| Python | `new_idempotency_key` | `python/ramp_sdk/idempotency.py` | `new_`-prefixed snake_case transliteration of Go `NewIdempotencyKey`; Python convention is a plain verb or classmethod | `generate_idempotency_key` (plain function) — verb-first, matches `validate_idempotency_key` sibling |

Extra find beyond the task's seed list: **TS `NewVerifier` (PascalCase)** — the most jarring because PascalCase falsely implies a class. Confirmed seed items all present. `newIdempotencyKey`/`new_idempotency_key` are the mildest (generator "new" reads as a verb) but remain inconsistent with their pure-helper module siblings.

Note: TS `guardedFetchFromEnv` and Python `guarded_client`/`guarded_async_client` correctly AVOID the `new` prefix (idiomatic) even though Go names it `NewGuardedClientFromEnv` — good precedent that the resolver factories should follow.
