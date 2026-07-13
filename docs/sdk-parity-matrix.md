# SDK Full-Surface Parity Matrix (go · ts · python)

Decision: **3 SDKs mean 3 SDKs** — one must be able to build an agent, a broker,
an exchange, or an edge verifier in any of Go/TS/Python. This matrix is the
committed inventory of the intended surface per role, the per-language state,
and the gap list. Update it when a face lands or a gap ticket closes.

Surveyed at: sdk/go (helpers, resolvers, core, connect, connectserver), sdk/ts
(src, resolvers, core, hono), sdk/python (ramp_sdk incl. `ramp_sdk.resolvers`).
Legend: ✅ present (symbol named) · ⚠️ partial · ❌ absent. **Layer note:** the
network-fetching resolvers are the **L2 I/O** tier (Go `sdk/go/resolvers`, moved
out of `sdk/go/helpers` this cycle); `helpers` is the pure, IO-free L1 tier.
Consumers import the moved Go resolvers from `sdk/go/resolvers`, not `sdk/go/helpers`
(no alias shim).

## AGENT role

| Operation | go | ts | python |
|---|---|---|---|
| Request sign (RFC 9421, 5-component covered set) | ✅ `helpers.SignRequest` (+`core.NewSigningTransport` L2) | ✅ `core/sign-request.ts signRequest` (+`appendSignature`) | ✅ `httpsig.sign_request` (+`signing_transport.SigningTransport` L2) |
| PoP sign (GET agent binding) | ⚠️ via `AppendSignature` 2-component set; no dedicated face | ✅ `core/sign.ts signInbound` | ✅ `pop.sign_agent_binding` |
| Acceptance sign / verify | ✅ `helpers.SignOfferAcceptance` / `VerifyOfferAcceptance` | ✅ `src/acceptance.ts signOfferAcceptance` / `verifyOfferAcceptance` | ✅ `core.sign_offer_acceptance_jcs` / `verify_offer_acceptance_jcs` (+`acceptance` aliases) |
| Offer verify ({verified, rejected}, unforgeable VerifiedOffer) | ✅ `core.Verifier.Sort` + brand | ✅ `core/verifier.ts Verifier.sort` + brand | ✅ `core.Verifier.sort` + token-gated brand |
| Key resolution — static (pure L1) | ✅ `helpers.NewStaticKeyResolver` | ✅ `resolvers.newStaticKeyResolver` | ✅ `keyresolver.StaticKeyResolver` |
| Key resolution — well-known JWKS (L2 I/O) | ✅ `resolvers.NewWellKnownKeyResolver` | ✅ `resolvers.newWellKnownKeyResolver` | ✅ `resolvers.WellKnownKeyResolver` |
| Key resolution — WBA directory (revocation-aware, L2 I/O) | ✅ `resolvers.NewWBAKeyResolver` (+`Run` poller) | ✅ `resolvers.newWBAKeyResolver` (+`run` poller) | ✅ `resolvers.WBAKeyResolver` (+`run` poller) |
| Endpoint resolution — well-known ramp.json (L2 I/O) | ✅ `resolvers.NewWellKnownEndpointResolver` (`WellKnownOptions`, `ErrNoEndpoint`) | ✅ `resolvers.newWellKnownEndpointResolver` | ✅ `resolvers.WellKnownEndpointResolver` |
| Active-key selection — window-active, document order | ✅ `resolvers.ActiveEd25519Key` / `ActiveEd25519KeyWithExpiry` | ✅ `resolvers.activeEd25519Key` / `activeEd25519KeyWithExpiry` | ✅ `resolvers.active_ed25519_key` / `active_ed25519_key_with_expiry` |
| Active-key selection — revocation-aware (screened) | ✅ `resolvers.ActiveEd25519KeyScreened` / `ActiveEd25519KeyWithExpiryScreened` | ✅ `resolvers.activeEd25519KeyScreened` / `activeEd25519KeyWithExpiryScreened` | ✅ `resolvers.active_ed25519_key_screened` / `active_ed25519_key_with_expiry_screened` |
| Cached offer-key resolver (clamps TTL to key `not_after`) | ✅ `resolvers.NewCachedOfferKeyResolver` | ❌ (not intended; TS edge composes the selector directly) | ✅ `resolvers.CachedOfferKeyResolver` |
| SSRF-guarded fetch client (env-driven: `SKIP_SSRF`, `ALLOW_INSECURE`) | ✅ `resolvers.NewGuardedClientFromEnv` (+`SSRFGuard`/`SSRFCheckRedirect`) | ✅ `resolvers.guardedFetchFromEnv` (+`ssrfGuard`/`SsrfBlockedError`) | ✅ `resolvers.guarded_client` (+`ssrf_guard`/`async_ssrf_guard`) |
| Signed-URL fetch binding (3-way PoP against URL agent_id) | ✅ `helpers.VerifiedURL.CheckProofOfPossession` | ✅ `src/pop.ts verifyAgentBinding` | ✅ `pop.verify_agent_binding` |

## SERVER role (broker / exchange)

| Operation | go | ts | python |
|---|---|---|---|
| Server-verify middleware (all /ramp. procedures) | ✅ `connectserver.New{Exchange,Broker}ServiceHandler` + options | ⚠️ `core/verify-request.ts verifyRequestServer` (framework-agnostic single-sig verdict) + `hono rampVerify` edge GET-PoP binding — no full Connect handler binding | ⚠️ `server_verify.verify_request_server` (framework-agnostic single-sig verdict) — no full Connect/ASGI handler binding |
| Multisig append / verify (+hop budget) | ✅ `helpers.AppendSignature` / `VerifyMultisigRequest[Resolved]`, `core.WithAppendSigner` | ✅ `appendSignature` (core/sign-request.ts) / `verifyMultisigRequestServer` (core/verify-multisig-request.ts) | ✅ `append_signature` (httpsig) / `verify_multisig_request_server` (server_verify) |
| Codec (EmitUnpopulated JSON) | ✅ `connectserver.EmitUnpopulatedJSONCodec` / `WithEmitUnpopulated` | n/a (no Connect binding) | n/a |
| Reject / error mapping (emit) | ✅ `connectserver` reject mapping, `connect.ErrorDetailFrom`, `connectserver.AttachErrorDetail`/`AttachDetail`, `helpers.*Detail` | ⚠️ reject-reason tokens only (`RejectReason` "signature"/"replay" on the verify verdict) — no ErrorDetail emit mapping | ⚠️ reject-reason tokens only (`VerifiedRequest.reason` "signature"/"replay") — no ErrorDetail emit mapping |
| ErrorDetail readers (decode a typed failure) | ✅ `connect.ErrorDetailFrom` | ✅ `src/errordetail.ts parseErrorDetail` / `errorDetailFrom` | ✅ `errordetail.parse_error_detail` / `error_detail_from` |
| Replay window | ✅ `core.ReplayStore`, `core.MonotonicWindow` | ✅ `core/verify-request.ts ReplayStore` iface + two-phase replay (injected store, SDK owns no state) | ✅ `server_verify.ReplayStore` Protocol + two-phase replay (injected store, SDK owns no state) |
| Entitlement-coverage enforcement (unsigned X-Entitlement-Token rejected) | ✅ `helpers.enforceEntitlementCoverage` (verify.go) | ✅ `core/verify-request.ts` (covered-set commit check) | ✅ `server_verify.verify_request_server` (covered-set commit check) |
| Validation interceptor (protovalidate) | ✅ `connect.NewValidateInterceptor`, `helpers.Validate`/`ValidationRuleIDs` | ❌ (crossfield layer only) | ❌ (crossfield layer only) |
| Request-ID middleware | ✅ `core.RequestIDMiddleware` | ❌ | ❌ |

## EDGE role

| Operation | go | ts | python |
|---|---|---|---|
| Signed-URL sign | ✅ `helpers.SignURLEd25519` | ✅ `src/signurl.ts signEd25519SignedUrl` | ✅ `signedurl.sign_ed25519_signed_url` |
| Signed-URL verify | ✅ `helpers.VerifyURLEd25519` | ✅ `src/verify.ts verifyEd25519SignedUrl` (injectable `Ed25519Verifier` primitive for runtimes without native Ed25519) | ✅ `signedurl.verify_ed25519_signed_url` |
| GET-PoP verify | ✅ `VerifiedURL.CheckProofOfPossession` | ✅ `src/pop.ts verifyAgentBinding` (+`hono rampVerify` binding) | ✅ `pop.verify_agent_binding` |
| Thumbprint (RFC 7638) | ✅ `helpers.Thumbprint` | ✅ `src/thumbprint.ts` | ✅ `thumbprint.thumbprint` |
| HashURL (audit hash) | ✅ `helpers.HashURL` | ✅ `src/hashurl.ts hashUrl` | ✅ `hashurl.hash_url` |

## SHARED

| Operation | go | ts | python |
|---|---|---|---|
| base64url codec | ⚠️ stdlib inline (no exported face; none needed) | ✅ `src/base64url.ts` (+`utf8Bytes`) | ✅ `b64` |
| JCS canonical offer payload | ✅ (unexported; `SignOffer`/`VerifyOffer` public) | ✅ `core.canonicalOfferPayload` | ✅ `core.canonical_offer_payload` |
| JCS canonical acceptance payload | ✅ (unexported; sign/verify public) | ✅ `src/acceptance.ts acceptancePayload` (exported; also via sign/verify) | ✅ `core.jcs_acceptance_payload` |
| Wire→canonical offer (snake → pruned-snake, drops unknown/empty) | n/a (Go emits, never inverts) | ❌ (no TS from-wire face; TS edge consumes canonical input today) | ✅ `wire_canon.from_wire_offer` |
| Crossfield validation (stable rule-ids) | ✅ `helpers.ValidationRuleIDs` (protovalidate oracle) | ✅ `src/crossfield.ts crossFieldRuleIds` | ✅ `crossfield.cross_field_rule_ids` |
| Scopes normalize/apply/subset | ✅ `helpers.{Normalize,Apply}Scopes`, `ScopesSubset` | ✅ `src/scopes.ts {normalize,apply}Scopes/scopesSubset` | ✅ `scopes.{normalize,apply}_scopes/scopes_subset` |
| Money parse/format/canonicalize | ✅ `helpers.{Parse,Format,Canonicalize}Money` | ✅ `src/money.ts {parse,format,canonicalize}Money` | ✅ `money.{parse,format,canonicalize}_money` |
| Idempotency key mint/validate | ✅ `helpers.{New,Validate}IdempotencyKey` | ✅ `src/idempotency.ts {new,validate}IdempotencyKey` | ✅ `idempotency.{new,validate}_idempotency_key` |
| Wire constants (headers, content types) | ✅ `helpers` constants | ✅ `src/wire.ts` | ✅ `wire` |
| Window (created/expires source) | ✅ `core.Window`/`ClockWindow`/`MonotonicWindow` | ✅ `core/window.ts {clock,monotonic}Window` | ✅ `window.{clock,monotonic}_window` |

## Conformance-vector consumption (oracle: sdk/go/helpers/testdata + sdk/go/resolvers/testdata)

Vectors live in two homes: the L1 crypto corpora under `sdk/go/helpers/testdata` and
the L2 I/O corpora under `sdk/go/resolvers/testdata`. **Completeness ratchet (binding
— the standing rule for adding SDK behavior):** every committed
`testdata/*-vectors.json` MUST be replayed by all three SDKs. This is enforced by
`sdk/python/tests/test_corpus_replay_completeness.py`, which enumerates every corpus in
both homes and fails CI unless each is referenced by a Go emitter/consumer AND a Python
replay AND a TS replay — so an emitted-but-unreplayed corpus (an "orphan" that silently
asserts nothing) cannot ship. The gate carries a single **shrink-only** exemption:
`(wire-canonical-vectors.json, ts)`, re-verified on every run to still be genuinely
absent, so it must be deleted the moment TS gains a wire-canonical replay. Whenever you
add a behavior with a byte-deterministic oracle, add its corpus AND all three replays in
the same change — the ratchet will otherwise reject it.

| Vector | go | ts | python |
|---|---|---|---|
| thumbprint-vectors.json | ✅ emit+consume | ✅ | ✅ |
| signedurl-vectors.json | ✅ emit+consume | ✅ | ✅ |
| pop-vectors.json | ✅ emit+consume | ✅ | ✅ |
| sign-request-vectors.json | ✅ emit+consume | ✅ `sign-request.parity.test.ts` (byte-identical) | ✅ |
| acceptance-vectors.json | ✅ emit+consume | ✅ `acceptance.parity.test.ts` (byte-identical) | ✅ |
| offer-verify-vectors.json | ✅ emit+consume | ✅ | ✅ |
| wire-canonical-vectors.json | ✅ emit+consume | ❌ (no TS from-wire face; not currently intended) | ✅ |
| conformance/corpus/crossfield.json | ✅ | ✅ | ✅ |
| multisig-chain-vectors.json | ✅ emit+consume | ✅ | ✅ |
| scopes-vectors.json | ✅ emit+consume | ✅ | ✅ |
| money-vectors.json | ✅ emit+consume | ✅ | ✅ |
| idempotency-validate-vectors.json | ✅ emit+consume | ✅ | ✅ |
| hashurl-vectors.json | ✅ emit+consume | ✅ | ✅ |
| wire-constants-vectors.json | ✅ emit+consume | ✅ | ✅ |
| verify-request-neg-vectors.json | ✅ emit+consume | ✅ | ✅ |
| error-detail-vectors.json (`sdk/go/helpers/testdata`) | ✅ emit+consume | ✅ | ✅ |
| resolvers/active-ed25519-key-vectors.json | ✅ emit+consume | ✅ | ✅ |
| resolvers/revocation-membership-vectors.json | ✅ emit+consume | ✅ | ✅ |
| resolvers/ssrf-address-vectors.json | ✅ emit+consume | ✅ | ✅ |
| resolvers/ssrf-scheme-vectors.json | ✅ emit+consume | ✅ | ✅ |
| resolvers/ssrf-hostset-vectors.json | ✅ emit+consume | ✅ | ✅ |
| resolvers/ssrf-redirect-vectors.json | ✅ emit+consume | ✅ | ✅ |

## Gap tickets

Filed in the app repo's beads tracker as children of the SDK-adoption epic
(each fill ticket requires a Go-oracle conformance vector where the operation
is byte-deterministic). Genuinely-open items only:

- DECISION: full Connect handler binding for the TS/Python server role. Both now
  ship a framework-agnostic single-sig verify verdict (`verifyRequestServer` /
  `verify_request_server`, +entitlement-coverage +two-phase replay), but neither
  binds a full Connect/ASGI handler over all `/ramp.*` procedures the way Go's
  `connectserver.New{Exchange,Broker}ServiceHandler` does. Whether to ship that
  binding (vs. leaving framework wiring to the app) is the open call
  (`agentic-content-access-qqkro`).
- TS wire→canonical from-wire face: Python has `wire_canon.from_wire_offer` (and
  consumes wire-canonical-vectors); TS has no from-wire face and does not consume
  those vectors (TS edge consumes canonical input today).

CLOSED since the last revision (matrix rows now ✅): TS outbound request-sign
(`core/sign-request.ts signRequest`, xbxk2); TS+Python multisig append/verify
(o3szv); TS+Python key/endpoint resolvers (bsh8k); TS+Python utility parity —
scopes/money/idempotency/HashURL/wire constants/Window (djeue). Also DONE: TS
acceptance sign/verify (src/acceptance.ts), TS canonical acceptance payload
(`acceptancePayload`), signed-URL sign in TS + Python (`src/signurl.ts
signEd25519SignedUrl`, `sign_ed25519_signed_url`), and offer sign in TS + Python
(`src/offer-sign.ts signOffer`, `core.sign_offer_jcs`).

Tracked elsewhere (not duplicated): TS agentHash→agentId rename (ov97t.14),
CloudFront RSA TS helper (m8t96).
