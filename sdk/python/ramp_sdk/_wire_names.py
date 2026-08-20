"""Recovering a proto field name from protojson's lowerCamelCase spelling of it.

Re-export, not a second copy. The rule lives in :mod:`wire.names`, beside the generated
models, because the schema seam itself depends on it — ``wire.base`` refuses an answer
spelled in the ``json_name`` alias, and a rule the seam needs cannot live in a tier above
the seam. It is re-exported here so the SDK's own reader of the alias — the Connect
error-detail ``debug`` projection, which IS lowerCamelCase and cannot be made otherwise —
reaches the same implementation rather than transcribing it.

One rule, two callers, opposite verdicts, which is the reason it is worth sharing:
``errordetail`` NORMALIZES the alias (Connect emits it there and no server codec replaces
it), while the schema seam REFUSES it (a whole response body in the alias means the peer
is not speaking the contract).

See :mod:`wire.names` for the rule itself and why the boundary test is ASCII-only.
"""

from __future__ import annotations

from wire.names import snake_from_json_name

__all__ = ["snake_from_json_name"]
