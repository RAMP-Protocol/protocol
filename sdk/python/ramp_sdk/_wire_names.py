"""Recovering a proto field name from protojson's lowerCamelCase spelling of it.

The RAMP wire is snake_case proto-JSON everywhere — the proto field names, the corpus,
the generated clients — and the camelCase json_name alias is out of contract. Two places
still have to reason about that alias, which is why this rule is shared rather than
written twice:

* Connect's error-detail ``debug`` projection IS lowerCamelCase and cannot be made
  otherwise. connect-go renders it with its own protojson codec at default options,
  inside a method on an unexported type, so the snake_case codec a RAMP deployment
  registers reaches the response body and not the error beside it. That projection is
  normalized before parsing.
* A response body from a server that did not register a snake_case codec is
  lowerCamelCase throughout. That one is REFUSED rather than normalized: it is out of
  contract, and the point of naming it is to fail loudly instead of parsing into a
  message with every multiword field silently missing.

The rewrite is textual. It is sound only while protojson's spelling inverts back to every
field's name — it would not for a field like ``field_2``, whose json_name is ``field2`` —
which the conformance suite asserts for the whole contract.
"""

from __future__ import annotations


def snake_from_json_name(name: str) -> str:
    """Recover a proto field name from protojson's lowerCamelCase spelling of it."""
    out: list[str] = []
    for ch in name:
        if ch.isupper():
            out.append("_")
            out.append(ch.lower())
        else:
            out.append(ch)
    return "".join(out)
