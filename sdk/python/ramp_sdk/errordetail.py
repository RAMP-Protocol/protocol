"""ADR-019 ErrorDetail reader + typed detail builders (both halves of the contract).

RAMP's failure envelope is a typed ``ErrorDetail`` attached to the transport
error: the Connect/gRPC ``Code`` is the coarse class, the ``ErrorDetail`` oneof
carries the precise machine-readable reason. Clients branch on the typed reason,
never on the human ``message`` string.

READ half — the mcp shim is a CONSUMER of Connect error envelopes emitted by the
Broker / Exchange, so it needs to extract the ``ErrorDetail`` (domain, message,
metadata, and the typed reason if present) from an error and branch on the reason
enum. That is the Python peer of the Go client binding's ``ErrorDetailFrom`` + the
transport-neutral ``helpers.Reason`` accessor (sdk/go/connect + sdk/go/helpers).

WRITE half — the seven typed ``*_detail`` builders below are the Python peers of the
Go ``helpers.*Detail`` constructors (sdk/go/helpers/errordetail.go). Each builds an
``ErrorDetail`` carrying exactly one typed reason oneof block from
``(domain, message, reason)``, mirroring Go one-for-one: the builder sets ONLY the
reason block and omits the reason message's extra sub-fields (``offer_id``,
``rejected_paths``, …) — a caller that needs them, or metadata, mutates the returned
model post-construction, exactly as the Go emitter does. A Python service
now emits the same typed envelope a Go service does; byte-parity of both halves is
gated by ``error-detail-vectors.json``, replayed in Go + Python + TS.

Serialization is delegated to the generated model: ``WireModel.model_dump`` forces
``exclude_none=True`` (proto3 omit-unpopulated) and ``mode="json"`` renders each enum
as its NAME string — the builders never hand-roll field names or enum strings.

The ``ErrorDetail`` wire form is canonical proto-JSON (snake_case field names,
enums as NAME strings) — the exact shape the generated ``wire.models.ErrorDetail``
Pydantic model parses. Binary protobuf is deliberately NOT used: it is not a
cross-language primitive (protobuf's own caveat), so the shared wire the three
SDKs agree on is proto-JSON.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from wire.models import (
    CatalogRejectionReason,
    DenialReason,
    DisputeFailureReason,
    DomainVerificationFailureReason,
    ErrorDetail,
    RegistrationFailureReason,
    RetrievalAuthFailureReason,
    UsageReportRejectionReason,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
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


def _reason_detail(
    domain: str,
    message: str,
    reason_field: str,
    reason: Enum,
    extra: dict[str, Any] | None = None,
) -> ErrorDetail:
    """Build an ErrorDetail carrying exactly one typed reason oneof block.

    The single place the WRITE half constructs the generated model — the analogue of
    Go's private ``base()`` plus a oneof assignment. Construction goes through
    ``ErrorDetail.model_validate`` (the same generated-model surface the READ half's
    :func:`parse_error_detail` uses), so the generated schema owns field names, enum
    coercion, and — via :meth:`WireModel.model_dump` — the canonical proto-JSON.

    ``extra`` merges additional members into the reason block; only
    :func:`registration_failure_detail` passes it, for the per-member detail its
    reason is useless without. Every other reason message's sub-fields
    (``offer_id``, ``restriction_mismatches``, ``rejected_paths``, …) and
    ``metadata`` stay omitted, mirroring the Go builders — a caller that needs them
    mutates the returned model post-construction.
    """
    block: dict[str, Any] = {"reason": reason}
    if extra:
        block.update(extra)
    return ErrorDetail.model_validate({"domain": domain, "message": message, reason_field: block})


def transaction_denial_detail(domain: str, message: str, reason: DenialReason) -> ErrorDetail:
    """Build an ErrorDetail carrying a typed DenialReason (ExecuteTransaction denial).

    Python peer of Go ``helpers.TransactionDenialDetail``.
    """
    return _reason_detail(domain, message, "transaction_denial", reason)


def retrieval_auth_failure_detail(
    domain: str, message: str, reason: RetrievalAuthFailureReason
) -> ErrorDetail:
    """Build an ErrorDetail carrying a typed RetrievalAuthFailureReason.

    Python peer of Go ``helpers.RetrievalAuthFailureDetail`` (signed-URL /
    proof-of-possession check failed).
    """
    return _reason_detail(domain, message, "retrieval_auth_failure", reason)


def catalog_rejection_detail(
    domain: str, message: str, reason: CatalogRejectionReason
) -> ErrorDetail:
    """Build an ErrorDetail carrying a typed CatalogRejectionReason.

    Python peer of Go ``helpers.CatalogRejectionDetail``.
    """
    return _reason_detail(domain, message, "catalog_rejection", reason)


def registration_failure_detail(
    domain: str,
    message: str,
    reason: RegistrationFailureReason,
    field_errors: Sequence[Mapping[str, str]] | None = None,
) -> ErrorDetail:
    """Build an ErrorDetail carrying a typed RegistrationFailureReason.

    Python peer of Go ``helpers.RegistrationFailureDetail`` (agent/provider
    registration refused).

    ``field_errors`` carries the offending ``registration_data`` members when the
    reason is ``REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA`` — each a
    ``{"path", "error"}`` mapping, ``path`` an RFC 6901 JSON Pointer relative to
    ``registration_data`` (``""`` addresses the whole object). It is optional
    rather than positional so the six reasons that carry no per-member detail keep
    the three-argument call, matching Go's variadic. Passing it with any other
    reason is a caller error — the field's contract says the list is empty then.
    """
    extra = None
    if field_errors:
        # An empty path is "the whole object", and canonical proto-JSON omits an
        # empty scalar — so the wire form of a root-pointer entry carries no `path`
        # key at all. The generated model defaults `path` to "" rather than None,
        # and model_dump only drops None, so passing "" through would emit a member
        # Go omits. Map empty -> None here (this repo's proto3 "unpopulated"), which
        # is the exact inverse of the read side normalizing absent -> "".
        extra = {
            "field_errors": [
                {"path": fe.get("path") or None, "error": fe["error"]} for fe in field_errors
            ]
        }
    return _reason_detail(domain, message, "registration_failure", reason, extra)


def dispute_failure_detail(domain: str, message: str, reason: DisputeFailureReason) -> ErrorDetail:
    """Build an ErrorDetail carrying a typed DisputeFailureReason.

    Python peer of Go ``helpers.DisputeFailureDetail`` (DisputeTransaction filing
    refused).
    """
    return _reason_detail(domain, message, "dispute_failure", reason)


def domain_verification_failure_detail(
    domain: str, message: str, reason: DomainVerificationFailureReason
) -> ErrorDetail:
    """Build an ErrorDetail carrying a typed DomainVerificationFailureReason.

    Python peer of Go ``helpers.DomainVerificationFailureDetail`` (domain
    verification failed).
    """
    return _reason_detail(domain, message, "domain_verification_failure", reason)


def usage_report_rejection_detail(
    domain: str, message: str, reason: UsageReportRejectionReason
) -> ErrorDetail:
    """Build an ErrorDetail carrying a typed UsageReportRejectionReason.

    Python peer of Go ``helpers.UsageReportRejectionDetail`` (ReportUsage filing
    rejected).
    """
    return _reason_detail(domain, message, "usage_report_rejection", reason)
