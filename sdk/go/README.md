# RAMP SDK — Go

Layered protocol libraries co-located with the contract (ADR-020). The SDK is
consumed off-commit from this repo; it imports the generated L0 wire types
directly with no `replace` directive.

| Layer | Package | What it is |
|---|---|---|
| **L0** | `gen/go/ramp/v1`, `gen/go/vocab/*` | generated wire types (consumed, never rebuilt) |
| **L1** | **`sdk/go/ramphelpers`** | stateless protocol helpers — **this is what ships in RAMP-96** |
| L2 | `sdk/go/ramp`, `sdk/go/rampconnect` | transport client + server interceptors (state injected) — next |
| L3 | separate packages | framework adapters (convert, never replace) — later |

## L1 — `ramphelpers`

Stateless, no IO (except the well-known fetch), no secret custody, no state. The
same code the Broker, Exchange, MCP, Edge, and external implementors build on.

```go
import "github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
```

**RFC 9421 request signing / verification** — the `Signer` interface signs the
SDK-built signature base, so a KMS/HSM signer never exposes its key:

```go
signer, _ := ramphelpers.NewEd25519Signer("agent.v1", priv)
_ = ramphelpers.SignRequest(ctx, req, body, signer,
    ramphelpers.SignOptions{Created: created, Expires: expires})

// verify with the key injected (pure) ...
vr, err := ramphelpers.VerifyRequest(req, body, pub, ramphelpers.VerifyOptions{})
// ... or resolve the key via a KeyResolver (well-known / static / custom):
vr, err = ramphelpers.VerifyRequestResolved(ctx, req, body, resolver, ramphelpers.VerifyOptions{})
```

**Offer authenticity** — verify a received offer before selecting on it (the gap
the SDK closes); the signature covers `pricing`, `terms`, and `expires_at`:

```go
err := ramphelpers.VerifyOffer(offer, offer.GetSignature(), exchangePub)
```

**Signed delivery URLs + proof-of-possession** (ADR-013), byte-identical with the
edge worker:

```go
su, _ := ramphelpers.SignURLEd25519(priv, "ex.v1", rawURL, agentThumbprint, expiry)
v, err := ramphelpers.VerifyURLEd25519(su.URL, exchangePub, time.Now())
err = v.CheckProofOfPossession(presentedAgentPubKey) // bound-fetch enforcement
```

**Money** — exact decimal in/out, canonical decimal string on the wire:

```go
rate, _ := ramphelpers.ParseMoney(offer.GetPricing().GetRate()) // shopspring/decimal
wire, _ := ramphelpers.FormatMoney(rate.Mul(decimal.NewFromInt(qty)))
```

**Validation** — wraps protovalidate (the oracle), including cross-field CEL:

```go
if err := ramphelpers.Validate(req); err != nil { /* ramphelpers.ValidationRuleIDs(err) */ }
```

**Also:** RFC 7638 `Thumbprint`, ADR-019 `ErrorDetail` constructors +
`AsConnectError`/`ErrorDetailFrom`/`Reason`, `NewIdempotencyKey`, scope helpers.

## Guarantees

- **Relocation, not rewrite.** The RFC 9421 / 7638 crypto is byte-identical with
  the service-internal implementations it replaces (ADR-020 §8).
- **Cross-field CEL is pinned** to `conformance/corpus/crossfield.json`, generated
  by the same protovalidate oracle the rest of the conformance suite uses.
- Covered by the repo gate: `go build/vet/test ./...` via `scripts/ci-local.sh`.
