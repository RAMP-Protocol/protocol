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
proto/        Protocol buffer source — the wire format
  ramp/v1/    RAMP messages and services
  comp/v1/    IAB CoMP v1.0 (1:1 mapping; included for reference)
  buf.yaml    Buf module config

gen/          Generated SDKs
  go/         Go types + Connect-Go client/server
  ts/         TypeScript types (@bufbuild/protobuf + @connectrpc/connect)

cmd/          Build tooling (Go) — protoc-gen-rampvocab (vocabulary codegen plugin)
website/      Documentation site (Astro Starlight)
amplify.yml   AWS Amplify build configuration for the website
```

## Reference implementation

A working multi-language stack — Exchange (Go), Broker (Go), Edge (TypeScript), and an MCP shim (Python) — lives at [`RAMP-Protocol/reference-implementation`](https://github.com/RAMP-Protocol/reference-implementation). It implements the protocol end-to-end against a deployed AWS demo at `*.demo.ramp-protocol.org`.

## SDKs

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

## License

Code (everything under `proto/`, `gen/`, and `cmd/`) is licensed under the [Apache License 2.0](LICENSE). Documentation (the website source under `website/` and the rendered spec) is licensed under [Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)](https://creativecommons.org/licenses/by-nd/4.0/) — that license is declared in the website footer.
