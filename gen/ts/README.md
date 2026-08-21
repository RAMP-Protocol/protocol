# RAMP TypeScript types export

A **types export**, not a full SDK: Zod schemas for every RAMP message + registered
vocabulary constants. Generated from `proto/` via JSON Schema by
`scripts/gen-sdk-types.sh` — do not edit by hand.

Contents:
- `wire/schemas.ts` — a Zod schema per message (`OfferSchema`, `PricingSchema`, …),
  carrying **shape + per-field validation** (string patterns, length/item bounds,
  closed `not_in:[0]` enum discriminators). Cross-field rules are **not** here — they
  are enforced server-side by the Exchange/Broker.
- `wire/base.ts` — the wire policy, and the seam every schema routes through.
  **Hand-written, not generated.** It holds `wire()`, which sets the unknown-field policy
  (default: strip, so a field from a newer protocol version is accepted and dropped), and
  **`parseWire()`**, which is how a message should be parsed. Two things are true of the
  RAMP wire that a schema cannot express, and both live there: a `null` means the field
  has no value — proto-JSON's own rule, so it applies wherever the schema does not require
  one, and a RAMP Exchange serves those nulls because `EmitUnpopulated` renders an unset
  field rather than omitting it — and a lowerCamelCase answer is refused at every depth
  rather than parsed into a message with every multiword field missing.
- `wire/names.ts` — the rule that recovers a proto field name from protojson's
  lowerCamelCase spelling of it. Shared, so the refusal above and any reader of Connect's
  `debug` projection answer alike.
- `vocab/*.ts` — registered vocabulary constants per axis (`pricingunits`, …) with
  `isRegistered()`.

```typescript
import { parseWire } from "@ramp-protocol/sdk/wire/base";
import { OfferSchema } from "@ramp-protocol/sdk/wire/schemas";
import { pricingunits } from "@ramp-protocol/sdk/vocab/pricingunits";

// shape + per-field validation, under the wire policy
const result = parseWire(OfferSchema, incomingJson);
```

`OfferSchema.safeParse` still works and is the right call for a message you built
yourself. It is NOT the right call for an answer off the wire: a conformant server sends
`"ext": null` for an unset message, and `"reset_at": null` for an unset timestamp, both of
which the schema alone rejects, and a server that
registered no snake_case codec sends the camelCase alias, which the schema alone accepts
and silently strips. `parseWire` is where both of those are decided.

Money is a decimal **string** on the wire (e.g. `"19.99"`), never a float. Requires
`zod` as a peer dependency. Licensed under Apache-2.0.
