# RAMP

Open transaction protocol for licensed AI content access.

Built on [IAB Tech Lab CoMP v1.0](https://github.com/IABTechLab/CoMP) and [RSL 1.0](https://www.journalismai.info/programmes/responsible-ai/rsl); extends both with discovery, transaction execution, and settlement infrastructure so an autonomous agent can negotiate access to a publisher's content under that publisher's licensing terms, pay through an exchange, and produce a cryptographically auditable record of the transaction.

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

### Go

```go
import (
    rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
    "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"
)
```

> Note: the generated Go module path currently uses `github.com/postindustria-tech/ramp-protocol/gen/go`. Update if you fork or rehost.

### TypeScript

```ts
import { ExchangeService } from "@postindustria-tech/ramp-protocol";
```

## License

Code (everything under `proto/`, `gen/`, and `cmd/`) is licensed under the [Apache License 2.0](LICENSE). Documentation (the website source under `website/` and the rendered spec) is licensed under [Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)](https://creativecommons.org/licenses/by-nd/4.0/) — that license is declared in the website footer.
