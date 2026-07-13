"""ADR-019 ErrorDetail reader (the READ half of the error contract).

RAMP's failure envelope is a typed ``ErrorDetail`` attached to the transport
error: the Connect/gRPC ``Code`` is the coarse class, the ``ErrorDetail`` oneof
carries the precise machine-readable reason. Clients branch on the typed reason,
never on the human ``message`` string.

The mcp shim is a CONSUMER of Connect error envelopes emitted by the Broker /
Exchange, so it needs the READ direction: extract the ``ErrorDetail`` (domain,
message, metadata, and the typed reason if present) from an error and branch on
the reason enum. This is the Python peer of the Go client binding's
``ErrorDetailFrom`` + the transport-neutral ``helpers.Reason`` accessor
(sdk/go/connect + sdk/go/helpers).

Reader-only by design: the EMIT/attach half (build an ``ErrorDetail`` and stamp it
onto a ``*connect.Error``) lives server-side in the Go ``connectserver`` binding,
which is where RAMP services classify and emit errors. No Python service currently
emits ``ErrorDetail``, so a Python builder would have no consumer; the byte-parity
that matters here is the decode, gated by ``error-detail-vectors.json``.

The ``ErrorDetail`` wire form is canonical proto-JSON (snake_case field names,
enums as NAME strings) — the exact shape the generated ``wire.models.ErrorDetail``
Pydantic model parses. Binary protobuf is deliberately NOT used: it is not a
cross-language primitive (protobuf's own caveat), so the shared wire the three
SDKs agree on is proto-JSON.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from wire.models import ErrorDetail

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from enum import Enum

# The fully-qualified proto name Connect stamps on an ErrorDetail transport detail.
ERROR_DETAIL_TYPE = "ramp.v1.ErrorDetail"

# The ErrorDetail ``reason`` oneof members, in proto field-number order (the same
# order the Go helpers.Reason accessor walks). Exactly one is populated when a
# typed reason is present; all are ``None`` for a generic transport-class failure.
REASON_FIELDS: tuple[str, ...] = (
    "transaction_denial",
    "catalog_rejection",
    "registration_failure",
    "dispute_failure",
    "domain_verification_failure",
    "retrieval_auth_failure",
    "usage_report_rejection",
)


def parse_error_detail(payload: Mapping[str, Any]) -> ErrorDetail:
    """Parse a canonical proto-JSON ErrorDetail object into the generated model.

    ``payload`` is the proto-JSON object (snake_case keys, enums as NAME strings).
    This is the low-level decode the corpus replay exercises and the building block
    of :func:`error_detail_from`.
    """
    return ErrorDetail.model_validate(payload)


def reason(detail: ErrorDetail) -> Enum | None:
    """Return the active typed reason enum, or ``None`` when no reason is set.

    Mirrors the Go ``helpers.Reason`` accessor: it returns the enum member (e.g. a
    ``DenialReason`` / ``RetrievalAuthFailureReason``) for the populated oneof block
    so callers branch on the type + value, never on a string.
    """
    for field in REASON_FIELDS:
        block = getattr(detail, field, None)
        if block is not None:
            return cast("Enum", block.reason)
    return None


def error_detail_from(err: Mapping[str, Any] | Iterable[Any]) -> ErrorDetail | None:
    """Extract the first RAMP ErrorDetail from a Connect error (or its details).

    ``err`` is either a Connect error object (a mapping carrying a ``details``
    array) or the details iterable itself. Each detail entry is the Connect wire
    form ``{"type": "ramp.v1.ErrorDetail", ...}``; the ErrorDetail proto-JSON is
    read from the entry's ``debug`` projection (Connect includes it for JSON
    clients) or from a ``value`` already decoded to an object. Returns ``None`` when
    ``err`` carries no ErrorDetail — the Python analog of the Go ``(detail, false)``.

    The opaque binary ``value`` of a detail is intentionally NOT decoded here: the
    JSON SDKs have no protobuf binary codec, so they consume the proto-JSON form.
    """
    details = err.get("details", ()) if isinstance(err, dict) else err
    for entry in details:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != ERROR_DETAIL_TYPE:
            continue
        payload = entry.get("debug")
        if payload is None and isinstance(entry.get("value"), dict):
            payload = entry["value"]
        if isinstance(payload, dict):
            return parse_error_detail(payload)
    return None
