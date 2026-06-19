# RAMP — generated Python SDK

Generated from [`proto/`](../../proto) by `buf generate`. **Do not edit by hand** —
regenerate with `cd proto && buf generate` and commit the result (the CI drift gate
enforces this).

Contents:
- `ramp/v1/`, `comp/v1/` — protobuf messages/enums (`*_pb2.py`) and type stubs (`*_pb2.pyi`).
- `ramp/v1/ramp_connect.py` — Connect service client/handler stubs.
- `vocab/` — registered vocabulary constants per axis (`pricingunits`, `quotametrics`,
  `functiontokens`, `geographytokens`, `usertypes`), each with typed constants, an
  `ALL` tuple, and `is_registered()`. Authored solely from the `(ramp.v1.vocab)` /
  `(ramp.v1.vocab_enum)` proto options — the same single source as the Go and TS SDKs.

```python
from ramp.v1 import ramp_pb2
from vocab import pricingunits

offer = ramp_pb2.Offer()
assert pricingunits.is_registered("tokens")        # registered bare token
assert not pricingunits.is_registered("acme:foo")  # vendor:namespaced → not a registered token
```

Install (from this directory): `pip install .` — add the `connect` extra for service
stubs (`pip install ".[connect]"`) or `validation` for runtime protovalidate checks.
