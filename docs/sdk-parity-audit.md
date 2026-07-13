# RAMP SDK Cross-Language Parity Audit

**Scope:** `sdk/go`, `sdk/ts`, `sdk/python` (the active-key-consolidation revision:
the network-fetching resolvers now live in `sdk/go/resolvers`, split out of
`sdk/go/helpers`).
**Method:** code + test files are the source of truth. The pre-existing
`docs/sdk-parity-matrix.md` was read first, then every claim was verified against
the actual source. Where the doc and code diverge, this audit records the code.
**Nature:** read-only audit. No source or test files were modified.

The Go SDK is the reference/oracle: it emits the shared conformance vectors under
`sdk/go/helpers/testdata/*.json`, and TS + Python parity tests import those exact
files (relative-path import in TS, `GO_TESTDATA` in Python `conftest.py`).

---

## 1. Go SDK feature/method inventory (the reference surface)

### package `helpers` (L1 primitives)

| Symbol | File | Purpose |
|---|---|---|
| `Signer` iface, `NewEd25519Signer`, `NewEd25519SignerFromSeed` | sign.go:30,48,59 | Ed25519 signer abstraction for RFC 9421 |
| `SignRequest` | sign.go:86 | RFC 9421 HTTP message signature — sign side (outbound RPC) |
| `AppendSignature` | sign.go:113 | Multisig append (2-component set) onto existing chain |
| `VerifyRequest` | verify.go:88 | RFC 9421 verify side (single signer) |
| `VerifyMultisigRequest` / `...Resolved` | verify.go:477, keyresolver.go:227 | Multisig chain verify (+hop budget) |
| `VerifyRequestResolved` | keyresolver.go:203 | Verify via `KeyResolver` |
| `SignURLEd25519` | signedurl.go:65 | Ed25519 signed-URL — sign side |
| `VerifyURLEd25519` | signedurl.go:96 | Ed25519 signed-URL — verify side |
| `VerifiedURL.CheckProofOfPossession` | signedurl.go:137 | 3-way GET-PoP binding to URL `agent_id` |
| `HashURL` | signedurl.go:153 | Audit hash of a signed URL |
| `SignOffer` | offer.go:30 | Offer signature — sign side (JCS/8785 + ed25519) |
| `VerifyOffer` | offer.go:45 | Offer signature — verify side |
| `SignOfferAcceptance` / `VerifyOfferAcceptance` | acceptance.go:67,81 | Agent offer-acceptance detached sig (JCS + ed25519) |
| `VerifyPresentedOffer` | presented_offer.go:32 | Exchange-presented offer verify (freshness + sig) |
| `Thumbprint` / `ThumbprintBytes` | thumbprint.go:37,48 | RFC 7638 JWK thumbprint |
| `KeyResolver` iface, `NewStaticKeyResolver` | keyresolver.go:21,38 | Static key map resolver (the pure resolver kept in L1; the IO-fetching resolvers moved to `resolvers` — see below) |
| `VerifyRequestResolved` / `VerifyMultisigRequestResolved` | keyresolver.go:67,91 | Verify via an injected `KeyResolver` |
| `ContentDigest`, `CoveredComponent`, `ComponentParam` | sigbase.go:106,35,26 | RFC 9421 signature-base construction |
| `canonicalSignPayload` (unexported) | canonicalsign.go | `JCS(protojson(msg, snake, no-emit))` — the pinned canonical signing bytes for BOTH offer + acceptance |
| `NormalizeScopes`, `ApplyScopes`, `ScopesSubset` | scopes.go:25,50,61 | Scope algebra |
| `ParseMoney`, `FormatMoney`, `CanonicalizeMoney` | money.go:35,53,71 | Money canonicalization (decimal) |
| `NewIdempotencyKey`, `ValidateIdempotencyKey` | idempotency.go:26,36 | Idempotency keys |
| `SharedValidator`, `Validate`, `ValidationRuleIDs` | validate.go:31,39,50 | protovalidate oracle + stable rule-ids |
| wire constants | constants.go | Header names, content types, algorithm strings |

### package `resolvers` (L2 I/O — the network-fetching tier)

Split out of `helpers` this cycle. This is the **only** SDK tier that dials the
network: every third-party-influenceable fetch runs here behind one SSRF-guarded
HTTP client (Go `net/http`), so the pure L1 trust core holds no client to be tricked
into an SSRF. It composes `helpers`, never the reverse (io-leaf guard enforced).

| Symbol | File | Purpose |
|---|---|---|
| `NewWellKnownKeyResolver`, `WellKnownOptions` | wellknownkeyresolver.go:64,39 | Well-known JWKS fetch resolver (TTL cache) |
| `NewWBAKeyResolver` (+`Run` poller) | wbakeyresolver.go:410,521 | WBA directory resolver, revocation/expiry-aware |
| `NewWellKnownEndpointResolver`, `WellKnownEndpointResolver`, `ErrNoEndpoint` | endpointresolver.go:106,78,28 | `ramp.json` endpoint discovery |
| `ActiveEd25519Key` / `ActiveEd25519KeyWithExpiry` (+`ActiveKeyScanOptions`) | wbakeyresolver.go:893,913 | Window-active Ed25519 key by document order (unbounded scan by default) |
| `ActiveEd25519KeyScreened` / `ActiveEd25519KeyWithExpiryScreened` | wbakeyresolver.go:932,945 | The two active-key faces made revocation-aware (skip revoked thumbprints) |
| `NewCachedOfferKeyResolver` | cachedofferkeyresolver.go:70 | Offer-key cache; TTL clamped to the selected key's `not_after` |
| `NewGuardedClientFromEnv` | guardedclient_fromenv.go:57 | The single env-driven guarded client (`SKIP_SSRF`, `ALLOW_INSECURE`) |
| `SSRFGuard`, `SSRFCheckRedirect` | wbakeyresolver.go:219,286 | Injectable dial-time address guard + redirect re-vet for a custom `http.Client` |

### package `core` (L2 composition)

| Symbol | File | Purpose |
|---|---|---|
| `Verifier`, `NewVerifier`, `Verifier.Sort` | verifier.go:80,91,99 | Split offers → {verified, rejected}; unforgeable `VerifiedOffer` brand |
| `VerifiedOffer` / `RejectedOffer` / `Result` | verifier.go:41,54,69 | Sorted-offer result types |
| `NewSigningTransport` (+`With*` options) | transport.go:109 | `http.RoundTripper` that signs outbound (window, append, signature-agent, predicate) |
| `Window`, `ClockWindow`, `MonotonicWindow` | sigwindow.go:17,24,40 | Injectable created/expires source |
| `ReplayStore` iface | replay.go:19 | Replay-window store |
| `RequestIDMiddleware`, `DefaultRequestID` | requestid.go:36,22 | Request-ID correlation |

### packages `connect` / `connectserver` (server role)

| Symbol | File | Purpose |
|---|---|---|
| `NewExchangeServiceHandler` / `NewBrokerServiceHandler` | connectserver/handler.go:25,40 | Server-verify middleware over all `/ramp.*` procedures |
| `ServerOption` set (`WithKeyResolver`, `WithReplayStore`, `WithMaxSignatures`, `WithValidation`, `WithVerifyGate`, `WithOnReject`, …) | connectserver/options.go | Server wiring |
| `EmitUnpopulatedJSONCodec`, `WithEmitUnpopulated` | connectserver/codec.go:32,39 | Connect JSON codec, EmitUnpopulated snake wire |
| `ClassifyReject`, `RejectReason` | connectserver/classify.go:53,14 | Reject classification |
| `AsConnectError` | connectserver/reject.go:56 | Domain reject → `connect.Code` + `ErrorDetail` |
| `AttachErrorDetail`, `AttachDetail` | connectserver/errordetail.go:28,46 | Attach a typed `ErrorDetail` to a Connect error (server emits) |
| `NewValidateInterceptor`, `ErrorDetailFrom` (connect pkg) | connect/interceptors.go, errordetail.go | Validation interceptor + error-detail extraction (decode) |

---

## 2. Parity matrix

Legend — **T** = real behavioral test (round-trip and/or byte-parity against Go
oracle vectors), **guard** = structural/compile guard only, **—** = absent.

| Capability | Go | TS | Python | Verdict |
|---|---|---|---|---|
| **RFC 9421 httpsig — sign** | `helpers.SignRequest` (sign.go:86) · T (`sign_internal_test`, gen_vectors) | `core/sign-request.ts signRequest` (+`appendSignature`) · T (`sign-request.parity.test.ts`, byte-identical) | `httpsig.sign_request` (httpsig.py:101) · T (`test_signrequest_parity`, byte-identical) | **PARITY** |
| **RFC 9421 httpsig — verify** | `helpers.VerifyRequest` (verify.go:88) · T (`verify_test`) | `core/verify-request.ts verifyRequestServer` (single-sig verdict) + hono `rampVerify` (GET-PoP edge) · T (`verify-request.parity.test.ts`) | `httpsig.verify_request` + `server_verify.verify_request_server` · T (`test_verifyrequest_server_parity`) | **PARITY** (single-sig; full Connect handler binding still Go-only) |
| **GET-PoP (agent binding) — sign** | via `AppendSignature`/transport · T | `core/sign.ts signInbound` | `pop.sign_agent_binding` (pop.py:159) · T (`test_pop_sign_helper`) | **PARITY** |
| **GET-PoP — verify** | `VerifiedURL.CheckProofOfPossession` · T | `src/pop.ts verifyAgentBinding` · T (default+injected primitive) | `pop.verify_agent_binding` · T (default+injected) | **PARITY** |
| **Ed25519 signed-URL — sign** | `helpers.SignURLEd25519` (signedurl.go:65) · T | `src/signurl.ts signEd25519SignedUrl` · T | `signedurl.sign_ed25519_signed_url` · T (`test_signedurl_sign_parity`) | **PARITY** |
| **Ed25519 signed-URL — verify** | `helpers.VerifyURLEd25519` · T | `src/verify.ts verifyEd25519SignedUrl` (verify.ts:43) · T (`signedurl-pop.parity`) | `signedurl.verify_ed25519_signed_url` · T (`test_signedurl_pop_parity`) | **PARITY** |
| **Offer signing (JCS/8785 + ed25519) — sign** | `helpers.SignOffer` (offer.go:30) · T (`offer_test`) | `src/offer-sign.ts signOffer` · T | `core.sign_offer_jcs` (core.py:158) · T | **PARITY** |
| **Offer signing — verify** | `helpers.VerifyOffer` + `core.Verifier.Sort` · T | `core.canonicalOfferPayload` + `Verifier.sort` · T (`core-offer-verify.parity`) | `core.canonical_offer_payload` + `Verifier.sort` · T (`test_core_offer_verify_parity`) | **PARITY** |
| **Offer-acceptance — sign** | `helpers.SignOfferAcceptance` · T | `src/acceptance.ts signOfferAcceptance` · T (byte-identical) | `core.sign_offer_acceptance_jcs` (+`acceptance` alias) · T | **PARITY** |
| **Offer-acceptance — verify** | `helpers.VerifyOfferAcceptance` · T | `src/acceptance.ts verifyOfferAcceptance` · T (+tamper-negative) | `core.verify_offer_acceptance_jcs` · T | **PARITY** |
| **Multisig append / verify** | `AppendSignature` / `VerifyMultisigRequest[Resolved]` · T (`multisig_chain_*`) | `appendSignature` (core/sign-request.ts) / `verifyMultisigRequestServer` (core/verify-multisig-request.ts) · T (`multisig-chain.parity.test.ts`) | `append_signature` (httpsig) / `verify_multisig_request_server` (server_verify) · T | **PARITY** |
| **JCS canonical offer payload** | `canonicalSignPayload` (unexported; sign/verify public) · T | `core.canonicalOfferPayload` · T | `core.canonical_offer_payload` · T | **PARITY** |
| **JCS canonical acceptance payload** | unexported; sign/verify public · T | `src/acceptance.ts acceptancePayload` (exported) · T | `core.jcs_acceptance_payload` · T | **PARITY** |
| **JWK thumbprint (RFC 7638)** | `helpers.Thumbprint` · T | `src/thumbprint.ts thumbprint` · T (`thumbprint.parity`) | `thumbprint.thumbprint` · T (`test_thumbprint_parity`) | **PARITY** |
| **base64url codec** | stdlib inline (no exported face) | `src/base64url.ts` (+`utf8Bytes`) · T (indirect) | `b64` · T (`test_b64_public_home`) | **PARITY** (Go needs none) |
| **Key resolver — static** (pure L1) | `helpers.NewStaticKeyResolver` · T | `resolvers.newStaticKeyResolver` · T | `keyresolver.StaticKeyResolver` · T | **PARITY** |
| **Key resolver — well-known JWKS** (L2 I/O) | `resolvers.NewWellKnownKeyResolver` · T (httptest) | `resolvers.newWellKnownKeyResolver` · T (`resolvers-wellknown.integration`) | `resolvers.WellKnownKeyResolver` · T | **PARITY** |
| **Key resolver — WBA (revocation-aware)** (L2 I/O) | `resolvers.NewWBAKeyResolver` (+poller) · T (httptest) | `resolvers.newWBAKeyResolver` (+`run` poller) · T (`resolvers-wba*`) | `resolvers.WBAKeyResolver` (+`run` poller) · T | **PARITY** |
| **Endpoint resolver — ramp.json** (L2 I/O) | `resolvers.NewWellKnownEndpointResolver` · T | `resolvers.newWellKnownEndpointResolver` · T | `resolvers.WellKnownEndpointResolver` · T | **PARITY** |
| **Active-key selection (window-active, doc order)** | `resolvers.ActiveEd25519Key[WithExpiry]` · T (`active-ed25519-key-vectors`) | `resolvers.activeEd25519Key[WithExpiry]` · T | `resolvers.active_ed25519_key[_with_expiry]` · T | **PARITY** |
| **Active-key selection — revocation-aware (screened)** | `resolvers.ActiveEd25519Key[WithExpiry]Screened` · T | `resolvers.activeEd25519Key[WithExpiry]Screened` · T | `resolvers.active_ed25519_key[_with_expiry]_screened` · T | **PARITY** |
| **Cached offer-key resolver** | `resolvers.NewCachedOfferKeyResolver` · T | **—** (TS composes the selector directly) | `resolvers.CachedOfferKeyResolver` · T | **PARITY** (Go+Py; TS n/a by design) |
| **SSRF-guarded fetch client (env-driven)** | `resolvers.NewGuardedClientFromEnv` (+`SSRFGuard`/`SSRFCheckRedirect`) · T | `resolvers.guardedFetchFromEnv` (+`ssrfGuard`) · T | `resolvers.guarded_client` (+`ssrf_guard`) · T | **PARITY** |
| **ErrorDetail reader (decode typed failure)** | `connect.ErrorDetailFrom` · T | `src/errordetail.ts parseErrorDetail`/`errorDetailFrom` · T (`error-detail-vectors`) | `errordetail.parse_error_detail`/`error_detail_from` · T | **PARITY** |
| **Reject classification** | `ClassifyReject` · T (`classify_test`) | reject-reason tokens on the verify verdict (`RejectReason`) — no `ClassifyReject` face | reject-reason tokens on the verdict (`VerifiedRequest.reason`) — no `ClassifyReject` face | **PARTIAL** (Go-only classifier; TS/Python emit the reason tokens) |
| **Connect JSON codec / snake wire** | `EmitUnpopulatedJSONCodec` · T (`codec_test`) | n/a (no Connect binding) | n/a | **PARTIAL** (Go-only, n/a others) |
| **Server-verify middleware (all RPCs)** | `New{Exchange,Broker}ServiceHandler` · T | `core/verify-request.ts verifyRequestServer` (framework-agnostic single-sig verdict) + hono `rampVerify` GET-PoP edge · T (`verify-request.parity`, smoke) | `server_verify.verify_request_server` (framework-agnostic single-sig verdict) · T (`test_verifyrequest_server_parity`) | **PARTIAL** (single-sig verdict in all 3; full Connect handler binding still Go-only) |
| **Cross-field validation (stable rule-ids)** | `helpers.ValidationRuleIDs` · T (corpus) | `src/crossfield.ts crossFieldRuleIds` · T (`crossfield.parity`) | `crossfield.cross_field_rule_ids` · T | **PARITY** |
| **Scopes / Money / Idempotency / HashURL / wire consts / Window** | full · T | `src/{scopes,money,idempotency,hashurl,wire}.ts` + `core/window.ts` · T | `{scopes,money,idempotency,hashurl,wire,window}` · T | **PARITY** |
| **Wire→canonical (snake → pruned-snake)** | n/a (Go emits) | **—** (no from-wire face) | `wire_canon.from_wire_offer` · T (`test_wire_canon`) | **PARTIAL** (TS from-wire face absent) |

---

## 3. Signature & verification surface — per language

The crypto sign/verify surface is what the audit was asked to focus on. Present
**and** backed by a real behavioral test (✅) vs absent (❌):

| Signature capability | Go | TS | Python |
|---|---|---|---|
| RFC 9421 HTTP message sig — **sign** | ✅ | ✅ (byte-identical to oracle) | ✅ (byte-identical to oracle) |
| RFC 9421 HTTP message sig — **verify** | ✅ | ✅ single-sig `verifyRequestServer` (full RPC handler binding still Go-only) | ✅ single-sig `verify_request_server` |
| Ed25519 signed-URL — **sign** | ✅ | ✅ (`src/signurl.ts signEd25519SignedUrl`) | ✅ |
| Ed25519 signed-URL — **verify** | ✅ | ✅ | ✅ |
| GET-PoP agent binding — sign / verify | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
| Offer signing (JCS/8785) — **sign** | ✅ | ✅ (`src/offer-sign.ts signOffer`) | ✅ (`core.sign_offer_jcs`) |
| Offer signing — **verify** | ✅ | ✅ | ✅ |
| Offer-acceptance — **sign** | ✅ | ✅ | ✅ |
| Offer-acceptance — **verify** | ✅ | ✅ | ✅ |
| Multisig chain — append / verify | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |

### Cross-language conformance vectors

Oracle vectors live in two homes — `sdk/go/helpers/testdata/*.json` (L1 crypto) and
`sdk/go/resolvers/testdata/*.json` (L2 I/O), emitted by the respective `gen_*_test.go`
generators. Consumption:

| Vector | Go (emit+consume) | TS consumes | Python consumes |
|---|---|---|---|
| thumbprint-vectors.json | ✅ | ✅ | ✅ |
| signedurl-vectors.json | ✅ | ✅ | ✅ |
| pop-vectors.json | ✅ | ✅ | ✅ |
| offer-verify-vectors.json | ✅ | ✅ | ✅ |
| acceptance-vectors.json (`"canonicalization":"jcs"`) | ✅ | ✅ (byte-identical sig) | ✅ |
| **sign-request-vectors.json** | ✅ | ✅ (`sign-request.parity.test.ts`, byte-identical) | ✅ (byte-identical) |
| verify-request-neg-vectors.json | ✅ | ✅ | ✅ |
| multisig-chain-vectors.json | ✅ | ✅ (`multisig-chain.parity.test.ts`) | ✅ |
| error-detail-vectors.json | ✅ | ✅ (`errordetail.parity.test.ts`) | ✅ |
| wire-canonical-vectors.json | ✅ | ✅ (`wire-canonical.parity.test.ts`, `fromWireOffer`) | ✅ |
| conformance/corpus/crossfield.json | ✅ | ✅ | ✅ |
| resolvers: active-ed25519-key-vectors.json | ✅ | ✅ | ✅ |
| resolvers: revocation-membership-vectors.json | ✅ | ✅ | ✅ |
| resolvers: ssrf-{address,scheme,hostset,redirect}-vectors.json | ✅ | ✅ | ✅ |

**Corpus-completeness ratchet (the standing rule for adding SDK behavior).** The
shared-corpus convention only prevents divergence if EVERY committed corpus is actually
replayed by all three languages — an emitted-but-unreplayed corpus is an *orphan* that
silently asserts nothing (exactly how the SSRF redirect-depth and multi-address gaps
once slipped through: their vector files existed but no test read them). This is now a
hard gate: `sdk/python/tests/test_corpus_replay_completeness.py` enumerates every
`testdata/*-vectors.json` in both homes and fails CI unless each is referenced by a Go
emitter/consumer AND a Python replay AND a TS replay. There is deliberately **NO
exemption mechanism** — no allowlist, no opt-out, no per-corpus waiver: the count of
un-replayed corpora is zero, always, with no way to make it anything else. **Rule:**
whenever a new SDK behavior has a byte-deterministic oracle, add its corpus AND all
three replays in the same change, or the gate rejects it.

The parity-doc claim "TS consumes acceptance vectors byte-identical" is **verified
true** (`acceptance.parity.test.ts:100,105` assert `canonical_jcs` and
`signature_hex` equality). The prior claim "no TS consumer for sign-request-vectors"
is now **false at HEAD**: `sign-request.parity.test.ts` imports the file and asserts
base + Signature-Input + signature byte-equality against the Go oracle. The only
remaining TS vector gap is `wire-canonical-vectors.json` (no TS from-wire face).

**All present cross-language tests are real, not stubs.** Confirmed by reading the
bodies: they assert byte-identical signatures / canonical payloads against the Go
oracle and drive sign→verify round-trips plus tamper-negatives (e.g.
`acceptance.parity.test.ts:114` tampered idempotency key fails verify;
`test_signrequest_parity.py:103-108` asserts base + Signature-Input + signature
byte-equality). The one "structural check IS the test" file
(`helpers/library_adoption_guard_test.go`) is an explicitly-sanctioned exception
covering a byte-parity-preserving library-adoption refactor, backed by the
behavioral vector suites.

### SSRF-guarded transport (WBA directory fetch)

The WBA directory host is a caller-supplied `Signature-Agent` fetched BEFORE the
ed25519 check, so the default transport is SSRF-guarded in all three SDKs. Per
issue #20 the transport lives in the **I/O layer** (L2) — Go `sdk/go/resolvers`,
TS `sdk/ts/resolvers`, Python `ramp_sdk.resolvers` — never the pure trust core,
and it runs on a **maintained HTTP client** (Go `net/http`, TS `undici`, Python
`httpx`) rather than a hand-rolled transport: the client owns the response state
machine (status, redirects, 1xx, decompression) and the SDK owns only the SSRF
check, injected as a **connection-level hook**:

| SDK | Client | Injectable guard | DX |
|---|---|---|---|
| Go | `net/http` | `SSRFGuard(*http.Transport)` + `SSRFCheckRedirect` | `&http.Client{Transport: resolvers.SSRFGuard(nil), CheckRedirect: resolvers.SSRFCheckRedirect}` |
| Python | `httpx` | `ssrf_guard() -> httpx.HTTPTransport` | `httpx.Client(transport=ssrf_guard())` |
| TS | `undici` | `ssrfGuard(): buildConnector.connector` | `new Agent({ connect: ssrfGuard() })` |

The guard is split into a **data** part (corpus-locked) and a **wiring** part
(behaviorally tested), because only the former is expressible as vectors:

| Concern | Shared corpus (`sdk/go/resolvers/testdata`) | Consumed by |
|---|---|---|
| Reserved / non-public address classification | `ssrf-address-vectors.json` (26) | Go (emit+self-check) · TS · Python |
| URL-scheme allowlist (deny-by-default: http/https) | `ssrf-scheme-vectors.json` (11) | Go (emit+self-check) · TS · Python |
| Multi-address host decision (fail-closed if ANY resolved address is reserved) | `ssrf-hostset-vectors.json` (8) | Go (emit+self-check) · TS · Python |
| Redirect-hop policy (re-vet each `Location`; depth cap = 5) | `ssrf-redirect-vectors.json` (6) | Go (emit+self-check) · TS · Python |

**Transport policy now locked by corpus (normative for any future SDK):** one
env-driven guarded client per SDK (`NewGuardedClientFromEnv` / `guarded_client` /
`guardedFetchFromEnv`), governed by exactly two orthogonal flags — `SKIP_SSRF` (drop
the dial-time address guard) and `ALLOW_INSECURE` (permit plaintext http) — both
defaulting to the guarded posture. Fixed caps, identical across languages:
redirect-depth cap **5**, well-known/JWKS body cap **1 MiB**, and **fail-closed if any**
resolved address of a host is reserved. Python additionally imposes an overall
wall-clock deadline on one guarded GET (its per-phase `httpx` timeout cannot bound a
hostile `getaddrinfo`). The default `WellKnownEndpointResolver` client is guarded too
(`NewGuardedClientFromEnv`), not an unguarded stock client.

**Transport-wiring conformance invariant (normative for any future SDK):** *every
guarded transport MUST route each request — the initial URL and every redirect hop
— through both the address check and the scheme allowlist, and MUST surface a
non-2xx directory response as a status for the caller to classify (never as a
crash or an unmapped error).* A redirect target is just a scheme + a host→address,
so it is fully classified by the two corpora above; what the corpora cannot encode
is that the transport actually *applies* them on the `Location` hop and does not
crash on a non-2xx. That residual is covered behaviorally per language. With the
move to maintained clients the redirect mechanism is now **uniform**: all three
follow redirects and re-dial each hop through the same guarded connection, so
every hop is re-vetted (previously TS followed none — that divergence is gone):

| Behavior | Go | TS | Python |
|---|---|---|---|
| Refuses to dial loopback/private (initial URL) | `TestGuardedWBAClientBlocksLoopback` | `resolvers-ssrf.test.ts` (127.0.0.1 / [::1]) | `test_guarded_client_refuses_loopback` |
| Redirect into a non-http(s) scheme refused | `TestGuardedWBAClientRefusesRedirectScheme` | `resolvers-http-wiring.test.ts` | `test_guarded_client_refuses_redirect_to_ftp` |
| Redirect to an internal address refused (per-hop re-vet) | re-dial via `Dialer.Control` (corpus) | `resolvers-http-wiring.test.ts` (blocks only 169.254/16) | `test_guarded_client_refuses_redirect_to_internal_address` (blocks only 169.254/16) |
| Non-2xx surfaced as a status (no crash) | `TestGuardedWBAClientSurfacesNon2xx` | `resolvers-http-wiring.test.ts` | `test_guarded_client_non_2xx_returns_status_not_crash` |

A structural **io-leaf guard** in each SDK keeps this dependency scoped: the pure
trust core may not import the resolvers module or the HTTP client (`undici` in TS,
`httpx`/`httpcore` in Python), so the maintained-client dependency cannot leak
back into L1.

---

## 4. Gap assessment (risk-ranked)

**How far behind (at HEAD):** TS and Python are now at **full parity on the entire
sign/verify crypto surface** an agent or single-sig verifier needs — RFC 9421
request sign+verify (byte-identical to the Go oracle), GET-PoP, offer-acceptance
sign+verify, offer verify, multisig append/verify, and thumbprint. They also reach
parity on the key/endpoint **resolvers** (static, well-known JWKS, revocation-aware
WBA, `ramp.json` endpoint) and on the **utility** surface (scopes, money,
idempotency, HashURL, wire constants, injectable Window). The five gaps this section
flagged in the prior revision have **all landed** — see "Closed since last
revision" below. What remains is narrow and mostly architectural.

Both **offer sign** and **signed-URL sign** now reach full parity across Go/TS/Python
(`SignOffer` / `src/offer-sign.ts signOffer` / `core.sign_offer_jcs`, and
`SignURLEd25519` / `src/signurl.ts signEd25519SignedUrl` /
`signedurl.sign_ed25519_signed_url`). The prior "Go-only" / "role-split" framing no
longer holds — every SIGN face an agent, exchange, or edge component needs ships in
all three languages.

#### Closed since the last revision (were the prior Top-5)

- **TS outbound RFC 9421 request signer** — landed as `core/sign-request.ts
  signRequest` (+`appendSignature`), with `sign-request.parity.test.ts` asserting
  byte-identical output against `sign-request-vectors.json` (xbxk2).
- **Multisig append/verify in TS + Python** — `appendSignature` /
  `verifyMultisigRequestServer` (TS) and `append_signature` /
  `verify_multisig_request_server` (Python), both consuming
  `multisig-chain-vectors.json` (o3szv).
- **Key/endpoint resolvers in TS + Python** — `sdk/ts/resolvers/*` (named
  `newStaticKeyResolver`, `newWellKnownKeyResolver`, `newWBAKeyResolver` +poller,
  `newWellKnownEndpointResolver`) and `sdk/python/ramp_sdk/resolvers/*` +
  `keyresolver.StaticKeyResolver`, integration-tested (bsh8k).
- **Utility parity in TS + Python** — scopes, money, idempotency, HashURL, wire
  constants, injectable Window all present with parity tests (djeue).
- **Single-sig server-verify in TS + Python** — `verifyRequestServer` /
  `verify_request_server`, each enforcing the required-5 covered set,
  **entitlement-coverage** (an unsigned `X-Entitlement-Token` is rejected,
  parity with Go `enforceEntitlementCoverage`), and a two-phase injected-store
  replay check.

### Remaining gaps (risk-ranked)

1. **No full Connect handler binding outside Go (DECISION-gated).** Go's
   `connectserver.New{Exchange,Broker}ServiceHandler` binds verify over all
   `/ramp.*` procedures. TS/Python now ship a framework-agnostic **single-sig
   verify verdict** (`verifyRequestServer` / `verify_request_server`), but neither
   wires a full Connect/ASGI handler. A Broker/Exchange in TS/Python must wire the
   verdict into its own framework seam. Whether the SDK should ship that binding is
   an open architectural call, not a bug (`agentic-content-access-qqkro`).

2. **TS has no wire→canonical from-wire face.** Python has
   `wire_canon.from_wire_offer` (snake→pruned-snake, dropping unknown/empty fields)
   and consumes `wire-canonical-vectors.json`; TS has neither the face nor the
   vector consumer (the TS edge consumes already-canonical input today). Lowest
   risk — it only matters if a TS component must invert an untrusted wire offer.

3. **Reject → ErrorDetail mapping is Go-only.** TS/Python emit the reject-reason
   **tokens** ("signature"/"replay") on the verify verdict, but neither maps a
   domain reject to a structured `ErrorDetail` / `connect.Code` the way Go's
   `connectserver` + `connect.ErrorDetailFrom` do. Ties into gap 1 (it is part of
   the server-role binding).

### "Claims support but no real test" check

No language exports a signing/verification symbol that lacks behavioral backing.
Every present crypto face has a real test. The only structural-only test file is
the sanctioned library-adoption guard (Go), which sits on top of the behavioral
vector suites. The prior revision's two "stale-favorable" flags were re-checked at
HEAD: TS acceptance byte-parity is still **true**; the "TS sign-request gap" is now
**false** (the signer + vector consumer landed). The parity-matrix doc has been
reconciled to match the code in this pass.
