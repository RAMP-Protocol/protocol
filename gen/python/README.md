# RAMP — generated Python types export

Generated from [`proto/`](../../proto) via JSON Schema. **Do not edit by hand** —
regenerate with `scripts/gen-sdk-types.sh` and commit the result.

This is a **types export**, not a full SDK: Pydantic models + registered vocabulary
constants. Transport (Connect), request signing (RFC 9421), and key management are a
separate, hand-written SDK layer.

Contents:
- `ramp/models.py` — Pydantic v2 models for every RAMP message (`License`, `Pricing`,
  `LicenseTerm`, `Offer`, …). They carry **shape + per-field validation**: enums (with
  `UNSPECIFIED` excluded where it's a required discriminator), string patterns, length
  and item bounds. **Cross-field rules are NOT here** — they are enforced
  server-side by the Exchange/Broker (Go protovalidate); this is the correct trust
  boundary.
- `vocab/` — registered vocabulary constants per axis (`pricingunits`, `quotametrics`,
  `functiontokens`, `geographytokens`, `usertypes`): typed constants, an `ALL` tuple,
  and `is_registered()`.

```python
from ramp.models import LicenseTerm, Pricing
from vocab import pricingunits

# FastAPI / FastMCP: use the model directly as a request/response type.
term = LicenseTerm.model_validate(incoming_json)   # raises on shape/per-field violations
assert pricingunits.is_registered("tokens")
```

Install (from this directory): `pip install .`
