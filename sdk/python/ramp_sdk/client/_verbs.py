"""The six verbs, split into the part that has no IO and the part that reads an answer.

Both faces — the async client and the sync facade — share every line here. What differs
between them is which httpx client carries the bytes, and nothing else; keeping the
protocol in one place is what stops the two drifting into two dialects of the same client.

Each verb is a ``plan_*`` (stamp, check, route, sign — everything up to the send) and a
``finish_*`` (read the answer). The plan is what a face awaits around; the finish is what
it hands back.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from wire.models import (
    DiscoveryRequest,
    DiscoveryResponse,
    DisputeRequest,
    DisputeResponse,
    GetAccountStatusRequest,
    GetAccountStatusResponse,
    PushResourcesRequest,
    PushResourcesResponse,
    RefreshCatalogRequest,
    RefreshCatalogResponse,
    RegisterRequest,
    RegisterResponse,
    RegistrationFailureReason,
    RemoveResourcesRequest,
    RemoveResourcesResponse,
    ResourceQuery,
    ResourceResponse,
    TransactionRequest,
    TransactionResponse,
    UsageReport,
    UsageReportResponse,
)

from ramp_sdk.core import (
    ACCEPTANCE_SIGNATURE_ALGORITHM,
    DiscoveryResult,
    Mode,
    OfferGroupResult,
    VerifiedOffer,
    Verifier,
)
from ramp_sdk.errordetail import registration_failure_detail
from ramp_sdk.idempotency import generate_idempotency_key
from ramp_sdk.regschema import check_registration_data
from ramp_sdk.resolvers import (
    ExchangeNotPermittedError,
    ManifestNotExchangeError,
    WellKnownRequirementsReader,
    guarded_client,
)
from ramp_sdk.window import Window
from ramp_sdk.wire import ProtocolVersion
from ramp_sdk.wire_canon import from_wire_offer

from ._call import (
    DEFAULT_CALL_TIMEOUT_SEC,
    DEFAULT_MAX_RPC_READ_BYTES,
    Validation,
    decode,
    decode_with_raw,
    prepare,
    rpc_url,
    validate_request,
)
from .._hostref import _redact_userinfo as redact_userinfo
from ..hosts import is_bare_domain
from .errors import CallError, CallErrorKind, malformed, not_sent
from .route import (
    EndpointResolver,
    RegistrationRequirementsReader,
    vet_exchange_endpoint,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx

    from ramp_sdk.signing_transport import SigningTransport
    from ramp_sdk.window import Window

EXCHANGE_SERVICE = "ramp.v1.ExchangeService"
BROKER_SERVICE = "ramp.v1.BrokerService"
CATALOG_SERVICE = "ramp.v1.CatalogService"


@dataclass
class ClientConfig:
    """Everything a client is built from. Every field is injected; the client owns none."""

    base_url: str
    #: The RFC 9421 request signer. Custody stays with the application.
    signer: SigningTransport | None = None
    #: The agent's own identity, forwarded on discovery and required on a purchase: both
    #: reference services resolve the calling agent from it and refuse a request that
    #: names none.
    requester: dict[str, Any] | None = None
    #: The fail-closed offer Verifier. Defaults to STRICT with nothing resolvable, so an
    #: unconfigured client rejects every offer rather than surfacing it unchecked.
    verifier: Verifier | None = None
    #: Whether an outbound request is checked against its generated model first.
    #: Orthogonal to offer verification: this one is about the message going out.
    validation: Validation = "strict"
    #: Turns an offer's exchange domain into that Exchange's own advertised origin. Never
    #: configuration — a usage report and a dispute go where the signed offer says.
    endpoint_resolver: EndpointResolver | None = None
    #: Reports what one Exchange asks of a registration — the terms revision submitting
    #: one accepts, and the schema its registration_data must match. The reader it takes
    #: holds no document cache, and that is the point rather than an implementation
    #: detail: the contract requires a registering client to read the terms digest from a
    #: FRESHLY fetched manifest, so an implementation serving it from a cache breaks the
    #: rule the field exists to record. There is deliberately no slot for a digest or a
    #: schema directly — a caller managing its own requirements sets ``terms_digest`` on
    #: the request, which suppresses the read and says so on the message the signature
    #: covers.
    registration_requirements: RegistrationRequirementsReader | None = None
    #: The RFC 9421 freshness window stamped on every outbound REQUEST signature.
    #:
    #: Named here as well as on the signer so the knob sits at the same tier it does in
    #: Go and TypeScript. A deployment with its own freshness policy sets it; so does one
    #: whose peer screens replays on (key id, signature), since timestamps have
    #: one-second resolution and two identical requests inside a second otherwise sign to
    #: the same bytes — ``monotonic_window`` keeps each signature unique for exactly
    #: that, and must be ONE INSTANCE PER CLIENT rather than one per call.
    sign_window: Window | None = None
    #: Mints the X-Request-ID correlation value. ``None`` sends no header.
    request_id: Callable[[], str] | None = None
    #: The freshness window stamped on a delivery-fetch proof.
    proof_window: Window | None = None
    max_rpc_read_bytes: int = DEFAULT_MAX_RPC_READ_BYTES
    call_timeout_sec: float = DEFAULT_CALL_TIMEOUT_SEC
    content_timeout_sec: float | None = None
    max_content_bytes: int | None = None

    def resolved_verifier(self) -> Verifier:
        if self.verifier is not None:
            return self.verifier
        return _NULL_VERIFIER


def _with_requirements_reader(
    config: ClientConfig,
) -> tuple[ClientConfig, httpx.Client | None]:
    """Fill in the default requirements reader ONCE, and report the transport that
    came with it.

    Both client facades call this from their constructor, which is the tier Go resolves
    the same default at. Per CALL it would build an SSRF-guarded httpx client for every
    registration and close none of them; per CLIENT it is one pooled transport with an
    owner that can close it.

    The caller's config is never mutated — a caller may hold it, reuse it across
    clients, or read it back — so the filled-in reader rides on a copy. The second
    return is the transport this client OWNS: ``None`` when the caller injected a
    reader, because then the transport inside it is theirs.
    """
    if config.registration_requirements is not None:
        return config, None
    http = guarded_client()
    return replace(config, registration_requirements=WellKnownRequirementsReader(http=http)), http


class _NullOfferKeyResolver:
    """Resolves nothing. Under STRICT that rejects every offer, with a reason — the
    fail-closed default for a client given no key source."""

    def resolve(self, exchange: str) -> bytes | None:  # noqa: ARG002
        return None


_NULL_VERIFIER = Verifier(
    mode=Mode.STRICT, resolver=_NullOfferKeyResolver(), now=lambda: 0
)


@dataclass(frozen=True)
class Plan:
    """One request, ready to send."""

    op: str
    url: str
    body: bytes
    headers: dict[str, str]
    timeout: float
    max_bytes: int
    #: Whether this leg dials a host another party named — an offer-derived Exchange —
    #: and so goes over the address-guarded transport. Mirrors the Go client, which keeps
    #: a second guarded client for exactly these two verbs.
    guarded: bool = False
    #: The message as sent, kept so the finish step can read the query back (the flat
    #: fallback's attribution needs the URIs the caller asked about).
    sent: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


def plan_discover(cfg: ClientConfig, query: dict[str, Any]) -> Plan:
    """Assemble DiscoverResources.

    The query is CLONED before ``ver`` and the requester are filled in, so the message the
    caller built stays untouched — it crossed a module boundary as an argument, not as a
    buffer. Both are filled only when EMPTY: a value the caller set is theirs.

    ``exchange`` is NOT among them: the caller MUST set it to the bare host of the
    Exchange being queried, because the contract requires every addressed request to name
    its recipient. It is left to the caller rather than derived from the base URL on
    purpose — the point of the field is to state whom the SENDER meant, and a value the
    transport filled in from the address it was already dialling would restate the dial
    target instead of checking it.
    """
    op = "discover"
    sent = _stamp_discovery(op, query, cfg.requester)
    validate_request(op, sent, ResourceQuery, cfg.validation)
    return _plan(cfg, _Route(op, cfg.base_url, EXCHANGE_SERVICE, "DiscoverResources"), sent)


def finish_discover(cfg: ClientConfig, plan: Plan, status: int, body: str) -> DiscoveryResult:
    msg, raw = decode_with_raw(plan.op, status, body, ResourceResponse)
    return DiscoveryResult(
        # The offers are read from the RAW answer, not the parsed one. A model parse is
        # the GATE — it proves the answer well formed and its field names canonical — but
        # it also NORMALIZES: Pydantic fills every declared default, which adds keys the
        # signer never covered and would make a genuine offer fail verification. A
        # signature covers what the responder sent.
        groups=_discovered_groups(cfg.resolved_verifier(), plan.sent, raw),
        exchange=msg.exchange or "",
        # From the PARSED answer, unlike the offers above, with one member excepted.
        #
        # Nothing here is signed, so the reason the offers are read raw does not reach this
        # field, and the oracle settles what should: Go hands back the decoded message, so a
        # string-spelled int32 arrives as a number and a member the schema does not declare
        # is gone. TypeScript's parse does the same two things. A Python that answered from
        # the wire was the odd one of the three — it handed back "300" where the other two
        # said 300, and kept a vendor key they both dropped.
        #
        # reset_at is the exception because it is the one member the parse cannot return
        # unchanged: Pydantic reads it into a datetime and re-renders it, and that round trip
        # is not the identity — ".123Z" comes back ".123000Z", nanosecond precision is
        # truncated, "+00:00" becomes "Z". TypeScript validates it as a plain string and
        # hands back what it was given, so the peer's own spelling is what the two agree on.
        rate_limit=_rate_limit(msg.rate_limit, raw.get("rate_limit")),
    )


def _discovered_groups(
    verifier: Verifier, query: dict[str, Any], raw: dict[str, Any]
) -> list[OfferGroupResult]:
    """Fold a ResourceResponse's two offer representations into the per-URI form.

    The message carries a grouped list AND a flat one, and the contract says a responder
    populating groups SHOULD leave the flat list empty "to avoid ambiguity" — but a real
    Exchange populates both, the flat list mirroring the grouped offers as a single-URI
    convenience. So the two are read as ALTERNATIVES, never concatenated: concatenating
    would double every offer against such a server, and deduplicating would silently
    accept a responder whose two lists disagree, which is precisely the ambiguity the
    contract forbids.

    Groups win when present. The flat fallback becomes a single group; it carries no URI
    of its own, so it takes the query's only URI when the query named exactly one, and
    none otherwise — the SDK does not invent an attribution the wire did not make.
    """
    groups = raw.get("offer_groups")
    if isinstance(groups, list) and groups:
        return verifier.sort_groups([_canonicalize_group(g) for g in groups])
    flat = raw.get("offers")
    if not isinstance(flat, list) or not flat:
        return []
    uris = query.get("uris")
    uri = uris[0] if isinstance(uris, list) and len(uris) == 1 and isinstance(uris[0], str) else ""
    return [OfferGroupResult(uri=uri, result=verifier.sort(_canonicalize(flat)))]


def _canonicalize(offers: list[Any]) -> list[Any]:
    """Invert the wire emission of each offer before it is verified.

    A RAMP Exchange serves proto-JSON with EmitUnpopulated, so a wire offer carries
    zero-valued scalars, empty repeateds, null messages and ``*_UNSPECIFIED`` enums that
    the SIGNED form does not — the signature covers the omit-unpopulated rendering.
    Verifying the wire object as-is would fail every genuine offer, which is a fail-closed
    direction but the wrong answer. ``from_wire_offer`` is the schema-aware inversion,
    byte-parity-pinned against the Go oracle; a field newer than its pinned model is kept
    verbatim, so an offer this SDK cannot reconstruct still verifies FALSE rather than
    being waved through.

    The verified value is therefore the CANONICAL offer, which is what execute reflects
    back: the Exchange verifies the presented bytes and re-renders them canonically either
    way, so reflecting the canonical form is the same statement with none of the wire
    emission's noise.
    """
    return [from_wire_offer(o) if isinstance(o, dict) else o for o in offers]


def _canonicalize_group(group: Any) -> Any:
    """Apply the inversion to one group's offers, leaving its URI and typed reasons
    untouched."""
    if not isinstance(group, dict):
        return group
    offers = group.get("offers")
    if not isinstance(offers, list):
        return group
    return {**group, "offers": _canonicalize(offers)}


# ---------------------------------------------------------------------------
# resolve (Broker)
# ---------------------------------------------------------------------------


def plan_resolve(cfg: ClientConfig, request: dict[str, Any]) -> Plan:
    """Assemble the Broker's Resolve.

    It carries no idempotency key. Pure discovery buys nothing and changes nothing, so
    there is nothing for a server to deduplicate — the request message has no such field.
    """
    op = "resolve"
    sent = _stamp_discovery(op, request, cfg.requester)
    # Refused locally rather than sent: a Broker resolves the calling agent from the
    # requester and declines a request that names none, so this is a verdict the client
    # already knows, and naming the remedy beats relaying "requester required" from a
    # round trip away. execute refuses the same way.
    if sent.get("requester") is None:
        raise malformed(op, "no requester configured; a Broker resolves who is asking")
    validate_request(op, sent, DiscoveryRequest, cfg.validation)
    return _plan(cfg, _Route(op, cfg.base_url, BROKER_SERVICE, "Resolve"), sent)


def finish_resolve(cfg: ClientConfig, plan: Plan, status: int, body: str) -> DiscoveryResult:
    """Read the Broker's answer.

    Every returned offer is verified through the SAME fail-closed Verifier discover uses —
    not a second verification path. Broker-relayed offers are precisely the case that rule
    exists for: the Broker forwards offers it did not mint, and an unverified relay can
    steer an agent's selection with doctored terms that only fail later, at the purchase.

    A resolve that finds nothing is a SUCCESSFUL answer carrying a typed reason, not a
    failure.
    """
    msg, raw = decode_with_raw(plan.op, status, body, DiscoveryResponse)
    groups = raw.get("offer_groups")
    return DiscoveryResult(
        groups=cfg.resolved_verifier().sort_groups(
            [_canonicalize_group(g) for g in groups] if isinstance(groups, list) else []
        ),
        absence_reason=msg.absence_reason.value if msg.absence_reason is not None else None,
        # A DiscoveryResponse names no single Exchange and carries no rate-limit signal —
        # each offer carries its own issuing domain instead.
        exchange="",
    )


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


def plan_execute(
    cfg: ClientConfig, offer: VerifiedOffer, idempotency_key: str | None
) -> Plan:
    """Assemble ExecuteTransaction for a VERIFIED offer.

    It accepts ONLY a VerifiedOffer — the construction token is module-private to the
    core, so a rejected offer or a raw parsed one cannot be passed. A per-call idempotency
    key is minted fresh unless one is pinned. It builds the whole TransactionRequest, so
    it also stamps ``ver`` from ProtocolVersion — the caller neither supplies nor
    overrides it.
    """
    op = "execute"
    if cfg.requester is None:
        raise malformed(
            op, "no requester configured; an Exchange resolves who is buying from it"
        )
    if cfg.signer is None:
        # NOT_SIGNABLE, matching what fetch answers for the same missing holder: a caller
        # branching on the kind sees one condition under one class, whichever verb met it
        # first.
        raise CallError(
            CallErrorKind.NOT_SIGNABLE,
            op,
            cause=(
                "no signer configured; a purchase carries a detached acceptance signed "
                "with the agent's own key — the same key the request is signed with"
            ),
        )
    wire = offer.offer if isinstance(offer.offer, dict) else {}
    offer_sig = wire.get("signature")
    # An acceptance floating free of a concrete offer is meaningless, and an unsigned
    # offer is reachable here: Mode.OFF and RejectedOffer.unsafe() both mint a
    # VerifiedOffer without a signature check.
    if not isinstance(offer_sig, str) or offer_sig == "":
        raise malformed(op, "cannot accept an unsigned offer")
    key = idempotency_key or generate_idempotency_key()
    # The acceptance covers the offer, the requester and the idempotency key, so a retry
    # that pins the same key reproduces byte-identical acceptance bytes. That is the
    # deliberate-replay semantic, not an accident.
    requester_id = _str_field(cfg.requester, "id")
    requester_domain = _str_field(cfg.requester, "domain")
    exchange = _str_field(wire, "exchange")
    request_items = [(offer_sig, exchange)]
    request_acceptance: dict[str, Any] | None = None
    try:
        signature, _algorithm = cfg.signer.sign_offer_acceptance(
            offer_sig=offer_sig,
            requester_id=requester_id,
            requester_domain=requester_domain,
            idempotency_key=key,
        )
        if exchange != "":
            request_signature, _request_algorithm = cfg.signer.sign_request_acceptance(
                items=request_items,
                requester_id=requester_id,
                requester_domain=requester_domain,
                idempotency_key=key,
            )
            request_acceptance = {
                "payload": {
                    "items": [{"offer_sig": offer_sig, "exchange": exchange}],
                    "requester_id": requester_id,
                    "requester_domain": requester_domain,
                    "idempotency_key": key,
                },
                "signature": request_signature,
                "signature_algorithm": ACCEPTANCE_SIGNATURE_ALGORITHM,
            }
    except Exception as exc:  # custody can fail any way it likes
        raise CallError(CallErrorKind.NOT_SIGNABLE, op, cause=exc) from exc
    # Items-only wire shape: a single offer is the degenerate 1-element items list, each
    # item reflecting its signed Offer back exactly as received at discovery. The
    # authoritative identity is the reflected offer; the optional top-level offer_id
    # correlation scalar is left unset.
    sent: dict[str, Any] = {
        "ver": ProtocolVersion,
        "idempotency_key": key,
        "requester": cfg.requester,
        "items": [
            {
                "offer": wire,
                "agent_acceptance": {
                    "signature": signature,
                    "signature_algorithm": ACCEPTANCE_SIGNATURE_ALGORITHM,
                },
            }
        ],
    }
    if request_acceptance is not None:
        sent["agent_request_acceptance"] = request_acceptance
    validate_request(op, sent, TransactionRequest, cfg.validation)
    return _plan(cfg, _Route(op, cfg.base_url, EXCHANGE_SERVICE, "ExecuteTransaction"), sent)


def finish_execute(plan: Plan, status: int, body: str) -> TransactionResponse:
    return decode(plan.op, status, body, TransactionResponse)  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# reportUsage and dispute — the offer-derived leg
# ---------------------------------------------------------------------------


def plan_report_usage(
    cfg: ClientConfig, report: dict[str, Any], idempotency_key: str | None
) -> Plan:
    """Assemble a usage report for the Exchange that ISSUED the offer — never through a
    Broker, and never to an address from configuration.

    The destination comes off the report itself: ``exchange`` carries the offer's signed
    exchange domain, and the endpoint is then resolved from that Exchange's own well-known
    manifest. Reading it off the message rather than taking it as an argument is what
    makes the rule structural — there is no parameter a configured origin could be passed
    as, so it cannot become the default by anyone's convenience.

    The report is CLONED before ``ver`` and the idempotency key are stamped. The key
    identifies the REPORT, not the attempt: a fresh one is minted only when the caller
    supplied none, because an application that mints its own key for its own dedup would
    otherwise have it silently discarded and see every retry counted as a second report.
    """
    return _plan_offer_derived(
        cfg,
        _OfferDerived("report usage", UsageReport, "ReportUsage"),
        report,
        idempotency_key,
    )


def finish_report_usage(plan: Plan, status: int, body: str) -> UsageReportResponse:
    return decode(plan.op, status, body, UsageReportResponse)  # type: ignore[no-any-return]


def plan_dispute(
    cfg: ClientConfig, request: dict[str, Any], idempotency_key: str | None
) -> Plan:
    """Assemble a dispute for the issuing Exchange, over the same vetted routing a usage
    report takes.

    The dispute chain is a structural invariant: an agent must have filed a usage report
    and received a report_id before it can dispute, so ``report_id`` and
    ``transaction_id`` both name links the Exchange already holds.
    """
    return _plan_offer_derived(
        cfg,
        _OfferDerived("dispute", DisputeRequest, "DisputeTransaction"),
        request,
        idempotency_key,
    )


def finish_dispute(plan: Plan, status: int, body: str) -> DisputeResponse:
    return decode(plan.op, status, body, DisputeResponse)  # type: ignore[no-any-return]


@dataclass(frozen=True)
class _OfferDerived:
    """One offer-derived verb: its name, its request model, and its RPC method."""

    op: str
    model: Any
    method: str


def _plan_offer_derived(
    cfg: ClientConfig,
    verb: _OfferDerived,
    message: dict[str, Any],
    idempotency_key: str | None,
) -> Plan:
    # Discovery and execute keep the plain transport, because their address is the
    # operator's own configuration. The same split the Go client makes.
    sent = _stamp_envelope(verb.op, message, idempotency_key)
    return _plan_routed_keyless(cfg, _Routed(verb.op, verb.model, verb.method), sent)


# ---------------------------------------------------------------------------
# account setup: register / get account status
#
# They route like a usage report, not like discovery. An account is per-Exchange,
# and which Exchange is the agent's choice PER CALL: a target routinely arrives at
# runtime — a denial names where to register — rather than from configuration.
#
# Neither message carries an idempotency key, so neither verb takes one.
# ---------------------------------------------------------------------------

#: The ErrorDetail domain for a refusal THIS CLIENT computed, before anything was sent.
#: It names the failing surface, which here is the client's own tier: the Exchange never
#: saw the request, so naming it would attribute a local verdict to a party that reached
#: none. The naming rule the value follows — a Service suffix for an RPC service that
#: exists in the contract, a bare noun for a tier that does not — is recorded on the Go
#: oracle's ``edgeErrorDomain``, beside ``_EDGE_ERROR_DOMAIN``'s twin.
_CLIENT_ERROR_DOMAIN = "ramp.v1.Client"


def plan_register(cfg: ClientConfig, request: dict[str, Any]) -> Plan:
    """Assemble a registration for the Exchange the request names.

    The caller's identity is the request SIGNATURE. Nothing in the message says who is
    registering, and the business payload is not an identity claim.

    Four bounds on ``registration_data`` are checked before anything is signed, in the
    order the contract fixes, because a limit that exists to stop work belongs before the
    work it would stop — including before the manifest read.

    ``terms_digest`` is filled only when the caller left it ABSENT, from a freshly fetched
    manifest, and the payload is pre-checked against the schema that manifest publishes. A
    caller that sets the field is managing its own requirements and gets neither.

    A schema this SDK refuses never becomes a local veto: refusing locally and declining
    to send would turn a rule about reading a third party's document into a denial of
    service against the caller's own user, so an unusable schema is skipped and the
    Exchange decides.
    """
    op = "register"
    sent = _stamp_ver(op, request)
    _require_recipient(op, _str_field(sent, "exchange"))
    data = sent.get("registration_data")
    verdict = check_registration_data(data if isinstance(data, dict) else None)
    if verdict != "accepted":
        raise malformed(op, f"registration_data: {verdict}")
    if sent.get("terms_digest") is None:
        _apply_registration_requirements(cfg, op, sent)
    return _plan_routed_keyless(cfg, _Routed(op, RegisterRequest, "Register"), sent)


def finish_register(plan: Plan, status: int, body: str) -> RegisterResponse:
    return decode(plan.op, status, body, RegisterResponse)  # type: ignore[no-any-return]


def plan_get_account_status(cfg: ClientConfig, request: dict[str, Any]) -> Plan:
    """Assemble a status read for the Exchange the request names.

    The request carries no field identifying the caller — the Exchange resolves the
    account from the verified signature — so ``exchange`` is the only thing that says
    which account is being asked about.

    A caveat worth knowing before calling this in a loop. The request has no varying
    field, so two calls to the same Exchange inside one wall-clock second sign IDENTICAL
    bytes, and a peer screening replays on (key id, signature) refuses the second. This
    verb does not choose the freshness window for you, because a window is one instance
    per client rather than per call: set ``ClientConfig.sign_window`` to a
    ``monotonic_window`` when repeat calls are expected.
    """
    op = "get account status"
    sent = _stamp_ver(op, request)
    _require_recipient(op, _str_field(sent, "exchange"))
    return _plan_routed_keyless(
        cfg, _Routed(op, GetAccountStatusRequest, "GetAccountStatus"), sent
    )


def finish_get_account_status(plan: Plan, status: int, body: str) -> GetAccountStatusResponse:
    return decode(plan.op, status, body, GetAccountStatusResponse)  # type: ignore[no-any-return]


def _apply_registration_requirements(cfg: ClientConfig, op: str, sent: dict[str, Any]) -> None:
    """Read what the Exchange asks of a registration and apply it to the request.

    A failed READ refuses the registration rather than sending without a digest. Guessing
    here is not the cautious option: an Exchange that publishes a digest refuses a
    registration that omits one, so sending anyway trades a local failure the caller can
    act on for a remote one it cannot.
    """
    # Both client facades fill this in at construction, so the fallback is only for a
    # caller driving the plan functions directly. It builds a transport per call, which
    # is why the clients do not go through it.
    reader = cfg.registration_requirements
    if reader is None:
        reader = WellKnownRequirementsReader()
    exchange = _str_field(sent, "exchange")
    try:
        reqs = reader.resolve_registration_requirements(exchange)
    except (ExchangeNotPermittedError, ManifestNotExchangeError) as exc:
        # A value this deployment or the Exchange refused is FINAL; anything else is a
        # transport failure worth retrying. The same split the routing tier makes, so a
        # caller branches on one taxonomy whichever check declined.
        raise not_sent(op, str(exc)) from exc
    except CallError:
        raise
    except Exception as exc:  # noqa: BLE001 - classified, then re-raised as one shape
        raise CallError(kind=CallErrorKind.UNREACHABLE, op=op, cause=exc) from exc
    if reqs.terms_digest is not None:
        sent["terms_digest"] = reqs.terms_digest
    # A None validator means "nothing to enforce", which is the behaviour the contract
    # requires both when the Exchange publishes no schema and when it publishes one this
    # SDK refused. One branch, deliberately.
    data = sent.get("registration_data")
    fails = reqs.schema.validate(data if isinstance(data, dict) else None) if reqs.schema else []
    if fails:
        # An empty path addresses the whole object, which is how a missing required
        # member and every other whole-object failure is reported. Rendering a bare
        # ": ..." there would read as a member with no name.
        named = "; ".join(
            f"{p}: {f.get('error', '')}" if (p := f.get("path", "")) else f.get("error", "")
            for f in fails
        )
        # The failures travel as a typed detail, not only as prose. An Exchange attaches
        # this same list when it refuses the same payload, so a consumer that renders one
        # refusal renders both, and nothing has to parse the members back out of a
        # sentence.
        raise CallError(
            kind=CallErrorKind.MALFORMED,
            op=op,
            cause=f"registration_data does not match the schema {exchange} publishes: {named}",
            detail=registration_failure_detail(
                _CLIENT_ERROR_DOMAIN,
                "registration_data does not match the published data_schema",
                RegistrationFailureReason.REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
                fails,
            ),
        )


@dataclass(frozen=True)
class _Routed:
    """One manifest-routed verb that carries no idempotency key: its name, its request
    model, and its RPC method."""

    op: str
    model: Any
    method: str


def _plan_routed_keyless(cfg: ClientConfig, verb: _Routed, sent: dict[str, Any]) -> Plan:
    """The routing half every manifest-addressed verb shares, with the envelope already
    stamped by the caller.

    It exists so the order — address, then schema, then the guarded leg — is written
    once. The address is vetted BEFORE the schema: an unroutable recipient is a refusal to
    send, which is a different verdict from a message the server would reject, and the
    caller acts on them differently.
    """
    op = verb.op
    endpoint = vet_exchange_endpoint(cfg.endpoint_resolver, _str_field(sent, "exchange"), op)
    validate_request(op, sent, verb.model, cfg.validation)
    # The manifest-derived leg, so the guarded transport: the caller named a domain, the
    # manifest it serves named this endpoint, and a signed call now goes there.
    return _plan(cfg, _Route(op, endpoint, EXCHANGE_SERVICE, verb.method), sent, guarded=True)


# ---------------------------------------------------------------------------
# catalog: push / remove / refresh
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CatalogVerb:
    """One catalog verb: its name, its request model, and its RPC method."""

    op: str
    model: Any
    method: str


_PUSH_RESOURCES = _CatalogVerb("push resources", PushResourcesRequest, "PushResources")
_REMOVE_RESOURCES = _CatalogVerb("remove resources", RemoveResourcesRequest, "RemoveResources")
_REFRESH_CATALOG = _CatalogVerb("refresh catalog", RefreshCatalogRequest, "RefreshCatalog")


def plan_push_resources(cfg: ClientConfig, request: dict[str, Any]) -> Plan:
    """Assemble PushResources. See :func:`_plan_catalog` for the envelope rule."""
    return _plan_catalog(cfg, _PUSH_RESOURCES, request)


def finish_push_resources(plan: Plan, status: int, body: str) -> PushResourcesResponse:
    return decode(plan.op, status, body, PushResourcesResponse)


def plan_remove_resources(cfg: ClientConfig, request: dict[str, Any]) -> Plan:
    """Assemble RemoveResources. See :func:`_plan_catalog` for the envelope rule."""
    return _plan_catalog(cfg, _REMOVE_RESOURCES, request)


def finish_remove_resources(plan: Plan, status: int, body: str) -> RemoveResourcesResponse:
    return decode(plan.op, status, body, RemoveResourcesResponse)


def plan_refresh_catalog(cfg: ClientConfig, request: dict[str, Any]) -> Plan:
    """Assemble RefreshCatalog. See :func:`_plan_catalog` for the envelope rule."""
    return _plan_catalog(cfg, _REFRESH_CATALOG, request)


def finish_refresh_catalog(plan: Plan, status: int, body: str) -> RefreshCatalogResponse:
    return decode(plan.op, status, body, RefreshCatalogResponse)


def _plan_catalog(cfg: ClientConfig, verb: _CatalogVerb, message: dict[str, Any]) -> Plan:
    """The one shape all three catalog verbs share.

    The request is CLONED before ``ver`` is stamped (fill-when-empty; the caller's value
    is theirs); no idempotency key is stamped, because the messages carry none — a catalog
    push is an upsert and naturally idempotent, so a key there would be ceremony.
    ``exchange`` is the caller's to set, the bare domain of the Exchange the call is meant
    for; a request that names none, or names something that is not a bare domain, is refused
    before anything is signed or sent — a refusal to send, the verdict a report with no
    routable recipient gets, not a malformed message.

    The publisher chose the Exchange, so the origin is configuration and the leg runs on
    the plain transport — the posture of the home Exchange, not of the offer-derived leg.
    """
    op = verb.op
    sent = _stamp_ver(op, message)
    _require_recipient(op, _str_field(sent, "exchange"))
    validate_request(op, sent, verb.model, cfg.validation)
    return _plan(cfg, _Route(op, cfg.base_url, CATALOG_SERVICE, verb.method), sent)


def _stamp_ver(op: str, message: dict[str, Any]) -> dict[str, Any]:
    sent = _clone(op, message)
    if _str_field(sent, "ver") == "":
        sent["ver"] = ProtocolVersion
    return sent


def _require_recipient(op: str, exchange: str) -> None:
    """Refuse a catalog request whose recipient is missing or not a bare domain.

    The predicate is :func:`is_bare_domain`, the SHAPE rule, not the routing rule
    :func:`is_bare_host`. Nothing dials this value — a catalog client is built against an
    address the publisher configured — so the only question it answers is whether the
    value is the form the contract admits, which is the protovalidate pattern ``exchange``
    carries and the same rule the Exchange's own audience check applies on arrival. The
    routing predicate is deliberately wider: an underscore, a trailing root dot and a
    bracketed IPv6 literal are all usable hosts and none of them is a value this field may
    hold, so vetting with it would sign and send a request the recipient can only refuse.

    The refused value is redacted before it is named. A reference carrying userinfo is a
    verdict rather than a parse failure, so it would otherwise reach the message below
    verbatim; the routing check next door redacts for the same reason, and a tier that
    echoes is the drift ``_redact_userinfo`` exists to prevent.
    """
    if exchange == "":
        raise not_sent(op, "request names no recipient; set exchange to the Exchange's bare domain")
    if not is_bare_domain(exchange):
        raise not_sent(op, f"exchange {redact_userinfo(exchange)!r} is not a bare domain")


# ---------------------------------------------------------------------------
# Envelope stamping
# ---------------------------------------------------------------------------


def _stamp_discovery(
    op: str, message: dict[str, Any], requester: dict[str, Any] | None
) -> dict[str, Any]:
    """Fill the envelope a DISCOVERY call carries, which is the mutating envelope minus
    the idempotency key: pure discovery buys nothing and changes nothing, so there is no
    action for a key to identify.

    Both fills are only-when-empty. The caller's own value always wins — the message
    crossed a module boundary as an argument, not as a buffer to fill in — and the
    requester is filled because both reference services resolve the calling agent from it
    and refuse a request that names none, while the client already holds that identity.
    """
    sent = _clone(op, message)
    if not sent.get("ver"):
        sent["ver"] = ProtocolVersion
    if sent.get("requester") is None and requester is not None:
        sent["requester"] = requester
    return sent


def _stamp_envelope(
    op: str, message: dict[str, Any], idempotency_key: str | None
) -> dict[str, Any]:
    """Fill the two envelope fields the protocol requires on a state-mutating call,
    WITHOUT overwriting what the caller already set.

    Fill-when-empty is the whole rule. ``ver`` has a single owner, so the SDK supplies it
    rather than making every caller reach for the constant. The idempotency key is
    REQUIRED and identifies the action rather than the attempt, so a value the caller put
    there is theirs — discarding it would turn each of their retries into a fresh action,
    which is the double-counting the field exists to prevent. A pinned key overrides both.
    """
    sent = _clone(op, message)
    if not sent.get("ver"):
        sent["ver"] = ProtocolVersion
    on_message = sent.get("idempotency_key")
    sent["idempotency_key"] = (
        idempotency_key
        or (on_message if isinstance(on_message, str) and on_message else None)
        or generate_idempotency_key()
    )
    return sent


def _rate_limit(parsed: Any, wire: Any) -> dict[str, Any] | None:
    """The decoded rate-limit standing, spelling reset_at the way the peer did.

    Every other member comes from the parse, which is what the other two SDKs answer with:
    an int32 the peer spelled as a string arrives as a number, and a member the schema does
    not declare is gone. reset_at is taken from the wire because it is the only one the
    parse cannot hand back unchanged.

    The wire value is only used when it is a string, which the parse has already proved
    well formed — a shape that disagrees with its own parsed twin does not get to decide
    what this field says.
    """
    if parsed is None:
        return None
    standing: dict[str, Any] = parsed.model_dump(mode="json")
    sent = wire.get("reset_at") if isinstance(wire, dict) else None
    if isinstance(sent, str):
        standing["reset_at"] = sent
    return standing


def _clone(op: str, message: dict[str, Any]) -> dict[str, Any]:
    """Copy a caller's message so the SDK can stamp its envelope without touching what the
    caller still holds. A deep copy, because the envelope fields are top-level but a
    caller re-using a nested object across calls must not see it change either."""
    try:
        return copy.deepcopy(dict(message))
    except Exception as exc:  # a message that cannot be copied cannot be sent
        raise malformed(op, exc) from exc


@dataclass(frozen=True)
class _Route:
    """Where one call goes, and what it is called in a failure."""

    op: str
    base_url: str
    service: str
    method: str


def _plan(
    cfg: ClientConfig, route: _Route, sent: dict[str, Any], *, guarded: bool = False
) -> Plan:
    op = route.op
    url = rpc_url(route.base_url, route.service, route.method)
    body, headers = prepare(
        op,
        url,
        sent,
        signer=cfg.signer,
        request_id=cfg.request_id,
        sign_window=cfg.sign_window,
    )
    return Plan(
        op=op,
        url=url,
        body=body,
        headers=headers,
        timeout=cfg.call_timeout_sec,
        max_bytes=cfg.max_rpc_read_bytes,
        guarded=guarded,
        sent=sent,
    )



def _str_field(record: dict[str, Any] | None, key: str) -> str:
    if record is None:
        return ""
    value = record.get(key)
    return value if isinstance(value, str) else ""
