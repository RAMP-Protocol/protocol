"""Wire constants shared across the SDK — Python port of the sdk/go oracle
(helpers/constants.go + core/requestid.go). Encoding is negotiated per hop via
Content-Type (ADR-020): application/proto for binary, application/json for
canonical proto-JSON. The Go layer splits RequestIDHeader across
helpers/constants.go and core/requestid.go; the single Python module exposes all
eight values once. Pinned to wire-constants-vectors.json.

Also home to the pure receive-side rule for ``WellKnownManifest.ver``, so the
constant and the check that reads it sit together.
"""

from __future__ import annotations

#: Content-Type for binary protobuf bodies.
ContentTypeProto = "application/proto"
#: Content-Type for canonical proto-JSON bodies.
ContentTypeJSON = "application/json"
#: Header carrying the Connect unary protocol version.
ConnectProtocolVersionHeader = "Connect-Protocol-Version"
#: The only Connect protocol version RAMP speaks.
ConnectProtocolVersion = "1"
#: The RAMP protocol version stamped on the ``ver`` field of every RAMP message
#: — NOT the Connect transport version above. Senders stamp it from here so a
#: protocol bump is a single edit; receivers treat ``ver`` as advisory. The
#: ``/.well-known/ramp.json`` document carries its own version in a separate
#: namespace, which this constant does NOT supply — that is
#: :data:`WellKnownManifestVersion`.
ProtocolVersion = "1.0"
#: The version of the ``/.well-known/ramp.json`` DOCUMENT layout, stamped on
#: ``WellKnownManifest.ver`` by every party that serves one. A namespace separate
#: from :data:`ProtocolVersion` and never derived from it: a change to the
#: manifest layout bumps both numbers, a protocol change that leaves the manifest
#: untouched bumps only ``ProtocolVersion``. The two read the same today by
#: coincidence, not by rule. The receive-side check a manifest reader applies is
#: :func:`check_well_known_manifest_version`.
WellKnownManifestVersion = "1.0"
#: Header correlating a request across services and the edge.
RequestIDHeader = "X-Request-ID"
#: Header carrying the signer's Web Bot Auth key-directory URL.
SignatureAgentHeader = "Signature-Agent"


def _parse_major(ver: str) -> str | None:
    """The MAJOR run of a MAJOR.MINOR string, or None when ``ver`` is not one.

    Both runs must be non-empty ASCII digits joined by exactly one dot; a missing
    minor, a patch component, a leading ``v``, surrounding whitespace or a
    non-digit is not a version this rule recognises.
    """
    major, dot, minor = ver.partition(".")
    if not dot or not major.isascii() or not major.isdigit():
        return None
    if not minor.isascii() or not minor.isdigit():
        return None
    return major


def manifest_version_refusal(ver: object) -> str | None:
    """The receive-side rule for ``WellKnownManifest.ver``, as a pure verdict.

    Returns ``None`` when the document is accepted — its MAJOR equals the major of
    :data:`WellKnownManifestVersion`, whatever the MINOR, because a minor revision
    of the manifest is additive by definition and a reader ignores members it does
    not know. Otherwise returns the reason: an unrecognised major, a value that is
    not ``MAJOR.MINOR``, or an absent member (``None``, or any non-string, is how
    a missing ``ver`` arrives from ``json.loads``). Absent is refused rather than
    tolerated because the field is required by the wire shape and a document with
    no version is one whose layout the reader cannot classify; the manifest sits
    at a fixed, unversioned path and is read before any signature is checked, so
    the gate fails closed.

    The message names the value found so an operator can tell a version mismatch
    from a network failure. The three SDK languages pin this verdict to a shared
    corpus. The exception a resolver raises for a refusal is
    :class:`ramp_sdk.resolvers.errors.ManifestVersionRefusedError`.
    """
    accept_major = _parse_major(WellKnownManifestVersion)
    if accept_major is None:  # pragma: no cover - a malformed constant is a bug
        msg = f"WellKnownManifestVersion is not MAJOR.MINOR: {WellKnownManifestVersion!r}"
        raise RuntimeError(msg)
    if not isinstance(ver, str) or ver == "":
        return f"ver is absent, accept major {accept_major}"
    major = _parse_major(ver)
    if major is None:
        return f"ver {ver!r} is not MAJOR.MINOR, accept major {accept_major}"
    if major != accept_major:
        return f"ver {ver!r} has major {major}, accept major {accept_major}"
    return None
