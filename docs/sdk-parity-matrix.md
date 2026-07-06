# SDK Full-Surface Parity Matrix (go · ts · python)

Decision: **3 SDKs mean 3 SDKs** — one must be able to build an agent, a broker,
an exchange, or an edge verifier in any of Go/TS/Python. This matrix is the
committed inventory of the intended surface per role, the per-language state,
and the gap list. Update it when a face lands or a gap ticket closes.

Surveyed at: sdk/go (helpers, core, connect, connectserver), sdk/ts (src, core,
hono), sdk/python (ramp_sdk). Legend: ✅ present (symbol named) · ⚠️ partial ·
❌ absent.

## AGENT role

| Operation | go | ts | python |
|---|---|---|---|
| Request sign (RFC 9421, 5-component covered set) | ✅ `helpers.SignRequest` (+`core.NewSigningTransport` L2) | ⚠️ `core/sign.ts signInbound` is GET-PoP-only — no outbound RPC signer | ✅ `httpsig.sign_request` (+`signing_transport.SigningTransport` L2) |
| PoP sign (GET agent binding) | ⚠️ via `AppendSignature` 2-component set; no dedicated face | ✅ `core/sign.ts signInbound` | ✅ `pop.sign_agent_binding` |
| Acceptance sign / verify | ✅ `helpers.SignOfferAcceptance` / `VerifyOfferAcceptance` | ✅ `src/acceptance.ts signOfferAcceptance` / `verifyOfferAcceptance` | ✅ `core.sign_offer_acceptance_jcs` / `verify_offer_acceptance_jcs` (+`acceptance` aliases) |
| Offer verify ({verified, rejected}, unforgeable VerifiedOffer) | ✅ `core.Verifier.Sort` + brand | ✅ `core/verifier.ts Verifier.sort` + brand | ✅ `core.Verifier.sort` + token-gated brand |
| Key resolution — static | ✅ `helpers.NewStaticKeyResolver` | ❌ (raw injected function only) | ✅ `keyresolver.StaticKeyResolver` |
| Key resolution — well-known JWKS | ✅ `helpers.NewWellKnownKeyResolver` | ❌ | ❌ |
| Key resolution — WBA directory (revocation-aware) | ✅ `helpers.NewWBAKeyResolver` (+`Run` poller) | ❌ | ❌ |
| Endpoint resolution — well-known ramp.json | ✅ `helpers.NewWellKnownEndpointResolver` | ❌ | ❌ |
| Signed-URL fetch binding (3-way PoP against URL agent_id) | ✅ `helpers.VerifiedURL.CheckProofOfPossession` | ✅ `src/pop.ts verifyAgentBinding` | ✅ `pop.verify_agent_binding` |

## SERVER role (broker / exchange)

| Operation | go | ts | python |
|---|---|---|---|
| Server-verify middleware (all /ramp. procedures) | ✅ `connectserver.New{Exchange,Broker}ServiceHandler` + options | ⚠️ `hono rampVerify` is edge GET-PoP only (documented scope limit) | ❌ (intent unconfirmed — see decision ticket) |
| Multisig append / verify (+hop budget) | ✅ `helpers.AppendSignature` / `VerifyMultisigRequest[Resolved]`, `core.WithAppendSigner` | ❌ | ❌ |
| Codec (EmitUnpopulated JSON) | ✅ `connectserver.EmitUnpopulatedJSONCodec` / `WithEmitUnpopulated` | n/a (no Connect binding) | n/a |
| Reject / error mapping | ✅ `connectserver` reject mapping, `connect.ErrorDetailFrom`, `helpers.*Detail` | ❌ | ❌ |
| Replay window | ✅ `core.ReplayStore`, `core.MonotonicWindow` | ❌ | ❌ |
| Validation interceptor (protovalidate) | ✅ `connect.NewValidateInterceptor`, `helpers.Validate`/`ValidationRuleIDs` | ❌ (crossfield layer only) | ❌ (crossfield layer only) |
| Request-ID middleware | ✅ `core.RequestIDMiddleware` | ❌ | ❌ |

## EDGE role

| Operation | go | ts | python |
|---|---|---|---|
| Signed-URL sign | ✅ `helpers.SignURLEd25519` | n/a (edge verifies; Go signs) | ❌ |
| Signed-URL verify | ✅ `helpers.VerifyURLEd25519` | ✅ `src/verify.ts verifyEd25519SignedUrl` | ✅ `signedurl.verify_ed25519_signed_url` |
| GET-PoP verify | ✅ `VerifiedURL.CheckProofOfPossession` | ✅ `src/pop.ts verifyAgentBinding` (+`hono rampVerify` binding) | ✅ `pop.verify_agent_binding` |
| Thumbprint (RFC 7638) | ✅ `helpers.Thumbprint` | ✅ `src/thumbprint.ts` | ✅ `thumbprint.thumbprint` |
| HashURL (audit hash) | ✅ `helpers.HashURL` | ❌ | ❌ |

## SHARED

| Operation | go | ts | python |
|---|---|---|---|
| base64url codec | ⚠️ stdlib inline (no exported face; none needed) | ✅ `src/base64url.ts` (+`utf8Bytes`) | ✅ `b64` |
| JCS canonical offer payload | ✅ (unexported; `SignOffer`/`VerifyOffer` public) | ✅ `core.canonicalOfferPayload` | ✅ `core.canonical_offer_payload` |
| JCS canonical acceptance payload | ✅ (unexported; sign/verify public) | ❌ (with ov97t.13) | ✅ `core.jcs_acceptance_payload` |
| Wire→canonical offer (camel+EmitUnpopulated → snake) | n/a (Go emits, never inverts) | ❌ (TS edge consumes canonical input today) | ✅ `wire_canon.from_wire_offer` |
| Crossfield validation (stable rule-ids) | ✅ `helpers.ValidationRuleIDs` (protovalidate oracle) | ✅ `src/crossfield.ts crossFieldRuleIds` | ✅ `crossfield.cross_field_rule_ids` |
| Scopes normalize/apply/subset | ✅ `helpers.{Normalize,Apply}Scopes`, `ScopesSubset` | ❌ | ❌ |
| Money parse/format/canonicalize | ✅ `helpers.{Parse,Format,Canonicalize}Money` | ❌ | ❌ |
| Idempotency key mint/validate | ✅ `helpers.{New,Validate}IdempotencyKey` | ❌ | ❌ |
| Wire constants (headers, content types) | ✅ `helpers` constants | ❌ | ❌ |
| Window (created/expires source) | ✅ `core.Window`/`ClockWindow`/`MonotonicWindow` | ❌ (inline now+ttl) | ❌ (inline now+ttl) |

## Conformance-vector consumption (oracle: sdk/go/helpers/testdata)

| Vector | go | ts | python |
|---|---|---|---|
| thumbprint-vectors.json | ✅ emit+consume | ✅ | ✅ |
| signedurl-vectors.json | ✅ emit+consume | ✅ | ✅ |
| pop-vectors.json | ✅ emit+consume | ✅ | ✅ |
| sign-request-vectors.json | ✅ emit+consume | ❌ (no TS consumer — gap ticket) | ✅ |
| acceptance-vectors.json | ✅ emit+consume | ✅ `acceptance.parity.test.ts` (byte-identical) | ✅ |
| offer-verify-vectors.json | ✅ emit+consume | ✅ | ✅ |
| wire-canonical-vectors.json | ✅ emit+consume | ❌ (no TS from-wire face; not currently intended) | ✅ |
| conformance/corpus/crossfield.json | ✅ | ✅ | ✅ |

## Gap tickets

Filed in the app repo's beads tracker as children of the SDK-adoption epic
(each fill ticket requires a Go-oracle conformance vector where the operation
is byte-deterministic):

- TS outbound RFC 9421 request-sign face + sign-request-vectors parity consumer
  (`agentic-content-access-xbxk2`).
- TS + Python multisig append/verify faces (+ multisig chain vectors from the
  Go emitter) (`agentic-content-access-o3szv`).
- TS + Python key/endpoint resolver faces (static named export in TS, well-known
  JWKS, revocation-aware WBA, endpoint resolver) — IO-bound, integration-tested
  rather than vector-gated (`agentic-content-access-bsh8k`).
- TS + Python utility parity: scopes, money, idempotency key, HashURL, wire
  constants, injectable Window (`agentic-content-access-djeue`).
- DECISION: server-role intent for TS (full RPC server-verify beyond the edge
  GET-PoP binding) and Python (any server surface at all). Fill tickets for the
  SERVER column follow that decision, not this matrix
  (`agentic-content-access-qqkro`).

Already tracked elsewhere (not duplicated): TS acceptance sign/verify
(DONE — src/acceptance.ts), TS agentHash→agentId rename (ov97t.14), CloudFront RSA TS helper
(m8t96).
