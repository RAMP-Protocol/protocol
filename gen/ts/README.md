# RAMP TypeScript types export

A **types export**, not a full SDK: Zod schemas for every RAMP message + registered
vocabulary constants. Generated from `proto/` via JSON Schema by
`scripts/gen-sdk-types.sh` — do not edit by hand.

Contents:
- `wire/schemas.ts` — a Zod schema per message (`OfferSchema`, `PricingSchema`, …),
  carrying **shape + per-field validation** (string patterns, length/item bounds,
  closed `not_in:[0]` enum discriminators). Cross-field rules are **not** here — they
  are enforced server-side by the Exchange/Broker.
- `wire/base.ts` — **`wire()`**, the single seam that sets the unknown-field policy for
  every schema (default: strip unknown keys, so a field from a newer protocol version
  is accepted and dropped). **Hand-written, not generated.**
- `vocab/*.ts` — registered vocabulary constants per axis (`pricingunits`, …) with
  `isRegistered()`.

```typescript
import { OfferSchema } from "@ramp-protocol/sdk/wire/schemas";
import { pricingunits } from "@ramp-protocol/sdk/vocab/pricingunits";

const result = OfferSchema.safeParse(incomingJson); // shape + per-field validation
```

Money is a decimal **string** on the wire (e.g. `"19.99"`), never a float. Requires
`zod` as a peer dependency. Licensed under Apache-2.0.
