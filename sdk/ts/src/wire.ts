// Wire constants shared across the SDK — TS port of the sdk/go oracle
// (helpers/constants.go + core/requestid.go). Encoding is negotiated per hop via
// Content-Type (ADR-020): application/proto for binary, application/json for
// canonical proto-JSON. The Go layer splits RequestIDHeader across
// helpers/constants.go and core/requestid.go; the single TS module exposes all
// six values once. Pinned to wire-constants-vectors.json.

/** ContentTypeProto is the Content-Type for binary protobuf bodies. */
export const ContentTypeProto = "application/proto";
/** ContentTypeJSON is the Content-Type for canonical proto-JSON bodies. */
export const ContentTypeJSON = "application/json";
/** ConnectProtocolVersionHeader carries the Connect unary protocol version. */
export const ConnectProtocolVersionHeader = "Connect-Protocol-Version";
/** ConnectProtocolVersion is the only Connect protocol version RAMP speaks. */
export const ConnectProtocolVersion = "1";
/** RequestIDHeader correlates a request across services and the edge. */
export const RequestIDHeader = "X-Request-ID";
/** SignatureAgentHeader carries the signer's Web Bot Auth key-directory URL. */
export const SignatureAgentHeader = "Signature-Agent";
