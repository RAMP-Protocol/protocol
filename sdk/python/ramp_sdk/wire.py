"""Wire constants shared across the SDK — Python port of the sdk/go oracle
(helpers/constants.go + core/requestid.go). Encoding is negotiated per hop via
Content-Type (ADR-020): application/proto for binary, application/json for
canonical proto-JSON. The Go layer splits RequestIDHeader across
helpers/constants.go and core/requestid.go; the single Python module exposes all
seven values once. Pinned to wire-constants-vectors.json.
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
#: protocol bump is a single edit; receivers treat ``ver`` as advisory.
ProtocolVersion = "1.0"
#: Header correlating a request across services and the edge.
RequestIDHeader = "X-Request-ID"
#: Header carrying the signer's Web Bot Auth key-directory URL.
SignatureAgentHeader = "Signature-Agent"
