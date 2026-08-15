"""sdk/python/ramp_sdk/core — the transport-neutral L2 core.

Mirror of sdk/go/core, translated to idiomatic Python. It imposes NOTHING beyond
Python's stdlib + cryptography: NO framework (no httpx, no FastAPI/Starlette). The
framework bindings (ramp_sdk.signing_transport) depend one-directionally on this core,
never the reverse. The core is stateless — the key resolver and clock are injected.

It carries three things:

  * the offer Verifier that splits received offers into {verified, rejected} by
    ed25519-verifying the canonical offer signature. Since the JCS switch the signed payload is RFC 8785 JCS over the canonical proto-JSON of the
    offer with signature/signature_algorithm cleared::

        signed_payload = JCS(protojson(offer with sig+alg cleared))

    so the core reproduces the exact signed bytes without a protobuf binary codec;

  * the unforgeable VerifiedOffer guard (a frozen dataclass whose construction
    requires a module-private token, the Python analogue of the Go unexported
    field) + the .unsafe() escape on a RejectedOffer;

  * the JCS acceptance canonicalizer + sign/verify, re-pinned off the old L1
    proto-binary form onto the SAME JCS(protojson(...)) canonicalization the offer
    signature uses.

Never hand-roll canonicalization — the core composes the vetted ``rfc8785`` JCS
library and ``cryptography``.
"""

from __future__ import annotations

import base64
import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import rfc8785

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# OFFER_SIGNATURE_ALGORITHM / ACCEPTANCE_SIGNATURE_ALGORITHM — the JWS alg advertised
# on signed offers/acceptances. Always EdDSA for Ed25519 (mirror the Go constants).
OFFER_SIGNATURE_ALGORITHM = "EdDSA"
ACCEPTANCE_SIGNATURE_ALGORITHM = "EdDSA"


class Mode(enum.Enum):
    """Offer-verification strictness.

    STRICT (the default) is fail-closed: an offer that does not verify against the
    exchange's offer-signing key lands in ``rejected`` and cannot reach execute. OFF
    is the single, loud, named opt-out — it surfaces every offer as verified WITHOUT
    checking a signature.
    """

    STRICT = "strict"
    OFF = "off"


class OfferKeyResolver:
    """Resolve an exchange identity to its raw 32-byte Ed25519 offer-signing key.

    Injected — the core owns no key state. ``resolve`` returns None when no key is
    known for the exchange (→ fail-closed reject under STRICT). This is the offer
    face of the same resolver seam the request-signature face resolves through.
    """

    def resolve(self, exchange: str) -> bytes | None:  # pragma: no cover - protocol
        raise NotImplementedError


class StaticOfferKeyResolver(OfferKeyResolver):
    """Serve offer-signing keys from an in-memory map — for preloaded sets and tests."""

    def __init__(self, keys: dict[str, bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = dict(keys or {})

    def resolve(self, exchange: str) -> bytes | None:
        return self._keys.get(exchange)


# _VERIFIED_TOKEN is the module-private construction token. A VerifiedOffer can only
# be minted by passing it, and it never leaves this module, so an application cannot
# forge a VerifiedOffer with a composite literal — the Python analogue of the Go
# unexported-field guard.
_VERIFIED_TOKEN = object()


@dataclass(frozen=True)
class VerifiedOffer:
    """An offer that passed the core's fail-closed verification — or was surfaced
    under mode OFF / RejectedOffer.unsafe().

    Construction requires the module-private ``_token``; ``__post_init__`` rejects
    any other value, so only this module's verify path (or .unsafe()) can mint one.
    Reading ``offer`` is fine; only MINTING is gated.
    """

    offer: Any
    _token: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _VERIFIED_TOKEN:
            raise TypeError(
                "VerifiedOffer cannot be constructed directly; it is minted only by "
                "the core Verifier or RejectedOffer.unsafe()",
            )


@dataclass(frozen=True)
class RejectedOffer:
    """An offer the Verifier could NOT accept: the wrapped offer + the reason.

    VISIBLE (the app learns which offers failed and why) but not directly
    executable. Acting on it requires the explicit ``.unsafe()`` escape.
    """

    offer: Any
    reason: str

    def unsafe(self) -> VerifiedOffer:
        """The single, audit-visible escape hatch: mint an executable VerifiedOffer."""
        return VerifiedOffer(self.offer, _VERIFIED_TOKEN)


@dataclass(frozen=True)
class Result:
    """The fail-closed {verified, rejected} contract (mirror sdk/go core.Result)."""

    verified: list[VerifiedOffer] = field(default_factory=list)
    rejected: list[RejectedOffer] = field(default_factory=list)


def _mint_verified(offer: Any) -> VerifiedOffer:
    return VerifiedOffer(offer, _VERIFIED_TOKEN)


def canonical_offer_payload(offer: dict[str, Any]) -> bytes:
    """Reproduce the offer's signed bytes: clear signature + signature_algorithm from
    the canonical proto-JSON, then apply RFC 8785 JCS.

    MUST stay byte-identical to the Go oracle (helpers.CanonicalOfferBytes). The
    offer is already canonical proto-JSON (snake_case, enums-as-names,
    omit-unpopulated) — the core only clears the two signature keys and re-JCS-es.
    """
    stripped = {k: v for k, v in offer.items() if k not in ("signature", "signature_algorithm")}
    return rfc8785.dumps(stripped)


def sign_offer_jcs(*, seed: bytes, offer: dict[str, Any]) -> tuple[str, str]:
    """Sign an offer's canonical payload; return ``(hex_signature, "EdDSA")``.

    REUSES :func:`canonical_offer_payload` (the verify-side byte source of truth) —
    JCS over the offer with signature/signature_algorithm cleared — never a
    re-derived canonicalization. Ed25519 is deterministic (RFC 8032), so the hex
    signature is byte-identical to the Go oracle (``helpers.SignOffer``). The offer
    must already be canonical proto-JSON (snake_case, enums-as-names,
    omit-unpopulated), as the verify face requires.
    """
    payload = canonical_offer_payload(offer)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.sign(payload).hex(), OFFER_SIGNATURE_ALGORITHM


class Verifier:
    """Per-offer authenticity + freshness check over JCS(protojson(offer)), keyed
    through the injected resolver.

    PURE apart from the resolver IO — no state, no clock beyond the injected ``now``
    (unix seconds). Transport-neutral: any consumer composes it directly.
    """

    def __init__(
        self,
        *,
        mode: Mode,
        resolver: OfferKeyResolver,
        now: Callable[[], int],
    ) -> None:
        self._mode = mode
        self._resolver = resolver
        self._now = now

    def sort(self, offers: Sequence[Any]) -> Result:
        """Split offers into verified and rejected per the configured mode.

        Under OFF every offer is surfaced verified with no check. Under STRICT each
        offer is verified against its resolved exchange key and its expiry — a
        failure of either lands it in ``rejected`` with the reason.
        """
        verified: list[VerifiedOffer] = []
        rejected: list[RejectedOffer] = []
        for offer in offers:
            if self._mode is Mode.OFF:
                verified.append(_mint_verified(offer))
                continue
            reason = self._check(offer)
            if reason is None:
                verified.append(_mint_verified(offer))
            else:
                rejected.append(RejectedOffer(offer, reason))
        return Result(verified=verified, rejected=rejected)

    def _check(self, offer: Any) -> str | None:
        if not isinstance(offer, dict):
            return "offer is not an object"
        exchange = offer.get("exchange")
        exchange_str = exchange if isinstance(exchange, str) else ""
        pub = self._resolver.resolve(exchange_str)
        if pub is None:
            return f"no offer-signing key for exchange {exchange_str!r}"

        sig_hex = offer.get("signature")
        if not isinstance(sig_hex, str):
            return "offer signature is missing"
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            return "offer signature is not valid hex"

        payload = canonical_offer_payload(offer)
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)
        except (InvalidSignature, ValueError):
            return "offer signature invalid"

        if self._expired(offer):
            return "offer expires_at is in the past"
        return None

    def _expired(self, offer: dict[str, Any]) -> bool:
        # Fail-closed, mirroring the Go oracle (core.Verifier.expired): an offer
        # with no expires_at, or one whose expires_at cannot be parsed, is EXPIRED
        # — RAMP offers are minted now+TTL, so a missing/broken bound is malformed
        # bearer state, never an eternal grant.
        expires_at = offer.get("expires_at")
        if not isinstance(expires_at, str):
            return True
        try:
            # Python 3.11+ fromisoformat parses the trailing "Z" (UTC) directly.
            when = datetime.fromisoformat(expires_at)
        except ValueError:
            return True
        if when.tzinfo is None:
            # An offset-less RFC 3339 instant is UTC on the wire (protobuf
            # Timestamp.AsTime() is always UTC); naive .timestamp() would read
            # it as host-LOCAL time — invisible on UTC CI, wrong elsewhere.
            when = when.replace(tzinfo=UTC)
        return when.timestamp() < self._now()


# ---------------------------------------------------------------------------
# Acceptance signing, re-pinned to JCS (supersedes the L1 proto-binary form).
# ---------------------------------------------------------------------------


def jcs_acceptance_payload(
    *,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> bytes:
    """Canonical acceptance bytes = JCS(protojson(AgentAcceptancePayload)).

    The same JCS(protojson(...)) canonicalization the offer signature uses. proto-JSON
    OMITS unpopulated fields, so EVERY empty string field is absent from the object
    before JCS — not just ``requester_domain``. The Go oracle gets that structurally
    from ``EmitUnpopulated=false``; this object is hand-built, so the omission is
    applied once over the whole record rather than per key. A per-key guard is how the
    rule went missing for ``requester_id`` — wire-valid, since ``Requester.id`` carries
    no ``min_len`` — which signed bytes Go never produces. The filter tests for the
    empty STRING, which covers every member ``AgentAcceptancePayload`` has (the field-set
    guard in the Go suite pins that list), so a string field added to the message cannot
    arrive without its omission. A non-string field would need its own zero-value test.
    Fail-closed on an empty ``offer_sig`` (mirror Go CanonicalAcceptanceBytes): an
    empty anchor would let the acceptance float free of any concrete offer.
    """
    if offer_sig == "":
        raise ValueError("cannot accept an unsigned offer (empty offer signature)")
    payload: dict[str, str] = {
        "offer_sig": offer_sig,
        "requester_id": requester_id,
        "requester_domain": requester_domain,
        "idempotency_key": idempotency_key,
    }
    return rfc8785.dumps({k: v for k, v in payload.items() if v != ""})


def sign_offer_acceptance_jcs(
    *,
    seed: bytes,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> tuple[str, str]:
    """Sign the JCS acceptance payload; return ``(hex_signature, "EdDSA")``."""
    payload = jcs_acceptance_payload(
        offer_sig=offer_sig,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
    )
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.sign(payload).hex(), ACCEPTANCE_SIGNATURE_ALGORITHM


def verify_offer_acceptance_jcs(
    *,
    pubkey_b64: str,
    signature_hex: str,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> bool:
    """Verify a hex acceptance signature over the JCS payload with a std-base64 key."""
    payload = jcs_acceptance_payload(
        offer_sig=offer_sig,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
    )
    pub = base64.b64decode(pubkey_b64)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signature_hex), payload)
    except (InvalidSignature, ValueError):
        return False
    return True
