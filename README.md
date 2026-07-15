# RAMP

Open transaction protocol for licensed AI content access.

Built on [IAB Tech Lab CoMP v1.0](https://github.com/IABTechLab/CoMP) and [RSL 1.0](https://www.journalismai.info/programmes/responsible-ai/rsl); extends both with discovery, transaction execution, and settlement infrastructure so an autonomous agent can negotiate access to a publisher's content under that publisher's licensing terms, pay through an exchange, and produce a cryptographically auditable record of the transaction.

📖 **Spec & docs:** [ramp-protocol.org](https://ramp-protocol.org) — start with the [proto reference](https://ramp-protocol.org/reference/proto-ramp/) · 🧩 **Reference implementation:** [RAMP-Protocol/reference-implementation](https://github.com/RAMP-Protocol/reference-implementation)

> **v1.0.0 — pre-1.0 clean-cut.** This is the initial public release. The wire
> format was finalized in a single clean pass with **no backward-compatibility
> guarantees** to any pre-release draft — there are no prior external clients to
> support. The rationale behind the major design decisions is recorded in
> [`docs/design-history.md`](docs/design-history.md).

## What's in this repo

```
proto/          Protocol buffer source — the wire format
  ramp/v1/      RAMP messages and services
  ramp/admin/v1/  AdminService — the Exchange operator/config plane
  comp/v1/      IAB CoMP v1.0 (1:1 mapping; included for reference)
  buf.yaml      Buf module config

gen/          Generated wire types (L0) — never hand-edited
  go/         Go types + Connect-Go client/server (native protobuf)
  ts/         TypeScript Zod schemas + vocab constants
  python/     Pydantic v2 models + vocab constants

sdk/          Protocol SDK (L1/L2) — hand-written behavioral libraries, one per language
  go/         helpers · resolvers · core · connect · connectserver
  python/     ramp_sdk
  ts/         src · resolvers · core · hono
  parity/     symbol-map.json — the cross-language API-surface parity source

cmd/          Build tooling (Go) — protoc-gen-rampvocab (vocabulary codegen plugin)
website/      Documentation site (Astro Starlight)
amplify.yml   AWS Amplify build configuration for the website
```

## Reference implementation

A working multi-language stack — Exchange (Go), Broker (Go), Edge (TypeScript), and an MCP shim (Python) — lives at [`RAMP-Protocol/reference-implementation`](https://github.com/RAMP-Protocol/reference-implementation). It implements the protocol end-to-end against a deployed AWS demo at `*.demo.ramp-protocol.org`.

## Wire types (generated)

All three languages are generated from `proto/`: Go is native protobuf + Connect via
`buf generate` (it is the server/runtime); the Python and TypeScript **types exports**
— Pydantic models and Zod schemas — are generated from the same proto via JSON Schema
by `scripts/gen-sdk-types.sh` (the two real consumers, the Python MCP shim and the
TypeScript edge worker, cannot use protobuf natively). All three carry **registered
vocabulary constants** per axis (`pricingunits`, `quotametrics`, `functiontokens`,
`geographytokens`, `usertypes`) so consumers use typed constants and an
`IsRegistered`/`isRegistered`/`is_registered` membership check instead of magic
strings. The vocab is emitted from the single `(ramp.v1.vocab)` source in one pass, so
the three languages cannot drift from each other.

### Go

```go
import (
    rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
    "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
    "github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
)
```

### TypeScript

Zod schemas for every message are generated under [`gen/ts/wire/schemas.ts`](gen/ts/wire/schemas.ts) (validated message types; the edge worker uses them for request validation), with vocabulary constants under [`gen/ts/vocab/`](gen/ts/vocab); the [reference implementation](https://github.com/RAMP-Protocol/reference-implementation) shows them in use.

```typescript
import { OfferSchema } from "@ramp-protocol/sdk/wire/schemas";
import { pricingunits } from "@ramp-protocol/sdk/vocab/pricingunits";
```

### Python

Pydantic v2 models for every message (extending the hand-written `wire.base.WireModel` seam) plus vocabulary constants are generated under [`gen/python/`](gen/python) (`pip install .` from that directory; see its [README](gen/python/README.md)).

```python
from wire.models import Offer, Pricing
from vocab import pricingunits
```

## Protocol SDK

Beyond the generated wire types, the repo ships a hand-written **protocol SDK** in all
three languages under [`sdk/`](sdk) — the behavioral layer an agent, broker, exchange,
or edge verifier builds on: RFC 9421 request signing/verification, offer & acceptance
signatures, signed-URL delivery + proof-of-possession, key/endpoint resolution,
window-active key selection, an SSRF-guarded fetch client, and typed `ErrorDetail`s.
Full per-function documentation is still to come; today the source plus the parity
matrix are the reference.

The SDK is **layered the same way in every language** — full detail in
[`sdk/go/README.md`](sdk/go/README.md):

| Layer | What it is | Go | Python | TypeScript |
|---|---|---|---|---|
| **L0** | generated wire types (consumed, never rebuilt) | `gen/go/…` | `wire.models` | `wire/schemas` |
| **L1** | stateless, **IO-free** trust core — crypto sign/verify, canonicalization, money, scopes, thumbprint | `sdk/go/helpers` | `ramp_sdk` (`httpsig`, `signedurl`, `pop`, `money`, …) | `sdk/ts/src` |
| **L2 · I/O** | the only tier that dials the network — key/endpoint/offer-key resolvers behind one SSRF-guarded client | `sdk/go/resolvers` | `ramp_sdk.resolvers` | `sdk/ts/resolvers` |
| **L2 · transport** | transport-neutral composition + Connect bindings | `sdk/go/core` · `connect` · `connectserver` | `ramp_sdk.core` · `server_verify` | `sdk/ts/core` · `hono` |

Go is the reference/oracle; Python and TypeScript mirror it face-for-face. The exact
public surface per language — every symbol and its cross-language counterpart, the
documented divergences, and the conformance-vector replay coverage — is tracked in the
**generated, CI-drift-gated** [SDK parity matrix](docs/sdk-parity-matrix.md). The
design rationale (why the trust core is dependency-free, the SSRF transport model,
naming conventions) is recorded in [`docs/design-history.md`](docs/design-history.md).

> The SDK is consumed off-commit from this repo (no separate package release yet); it
> imports the generated L0 wire types directly, with no `replace` directive.

## License

Code (everything under `proto/`, `gen/`, and `cmd/`) is licensed under the [Apache License 2.0](LICENSE). Documentation (the website source under `website/` and the rendered spec) is licensed under [Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)](https://creativecommons.org/licenses/by-nd/4.0/) — that license is declared in the website footer.
