# RAMP SDK — Go

Layered protocol libraries co-located with the contract (ADR-020). The SDK is
consumed off-commit from this repo; it imports the generated L0 wire types
directly with no `replace` directive.

| Layer | Package | What it is |
|---|---|---|
| **L0** | `gen/go/ramp/v1`, `gen/go/vocab/*` | generated wire types (consumed, never rebuilt) |
| **L1** | **`sdk/go/helpers`** | stateless protocol helpers — **this is what ships in RAMP-96** |
| L2 | `sdk/go/core` (transport-neutral: Verifier, {verified,rejected}, VerifiedOffer guard, signing RoundTripper, ReplayStore — zero Connect) · `sdk/go/connect` (Connect **client** binding: `NewClient` + client options + `ErrorDetailFrom`) · `sdk/go/connectserver` (Connect **server** binding: `NewExchangeServiceHandler` + server options + `AsConnectError` + reject→code) | transport-neutral core + Connect client/server bindings (state injected) |
| L3 | separate packages | framework adapters (convert, never replace) — later |

## L1 — `helpers`

Stateless, no IO (except the well-known fetch), no secret custody, no state. The
same code the Broker, Exchange, MCP, Edge, and external implementors build on.

```go
import "github.com/RAMP-Protocol/protocol/sdk/go/helpers"
```

**RFC 9421 request signing / verification** — the `Signer` interface signs the
SDK-built signature base, so a KMS/HSM signer never exposes its key:

```go
signer, _ := helpers.NewEd25519Signer("agent.v1", priv)
_ = helpers.SignRequest(ctx, req, body, signer,
    helpers.SignOptions{Created: created, Expires: expires})

// verify with the key injected (pure) ...
vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{})
// ... or resolve the key via a KeyResolver (well-known / static / custom):
vr, err = helpers.VerifyRequestResolved(ctx, req, body, resolver, helpers.VerifyOptions{})
```

**Offer authenticity** — verify a received offer before selecting on it (the gap
the SDK closes); the signature covers `pricing`, `terms`, and `expires_at`:

```go
err := helpers.VerifyOffer(offer, offer.GetSignature(), exchangePub)
```

**Signed delivery URLs + proof-of-possession** (ADR-013), byte-identical with the
edge worker:

```go
su, _ := helpers.SignURLEd25519(priv, "ex.v1", rawURL, agentThumbprint, expiry)
v, err := helpers.VerifyURLEd25519(su.URL, exchangePub, time.Now())
err = v.CheckProofOfPossession(presentedAgentPubKey) // bound-fetch enforcement
```

**Money** — exact decimal in/out, canonical decimal string on the wire:

```go
rate, _ := helpers.ParseMoney(offer.GetPricing().GetRate()) // shopspring/decimal
wire, _ := helpers.FormatMoney(rate.Mul(decimal.NewFromInt(qty)))
```

**Validation** — wraps protovalidate (the oracle), including cross-field CEL:

```go
if err := helpers.Validate(req); err != nil { /* helpers.ValidationRuleIDs(err) */ }
```

**Also:** RFC 7638 `Thumbprint`, ADR-019 `ErrorDetail` constructors +
`AsConnectError`/`ErrorDetailFrom`/`Reason`, `NewIdempotencyKey`, scope helpers.

## Guarantees

- **Relocation, not rewrite.** The RFC 9421 / 7638 crypto is byte-identical with
  the service-internal implementations it replaces (ADR-020 §8).
- **Cross-field CEL is pinned** to `conformance/corpus/crossfield.json`, generated
  by the same protovalidate oracle the rest of the conformance suite uses.
- Covered by the repo gate: `go build/vet/test ./...` via `scripts/ci-local.sh`.
