package helpers

// Wire constants shared across the SDK. Encoding is negotiated per hop via
// Content-Type (ADR-020): application/proto for binary, application/json for
// canonical proto-JSON. connect-go serves both, so each leg picks independently.
const (
	// ContentTypeProto is the Content-Type for binary protobuf bodies.
	ContentTypeProto = "application/proto"
	// ContentTypeJSON is the Content-Type for canonical proto-JSON bodies.
	ContentTypeJSON = "application/json"
	// ConnectProtocolVersionHeader carries the Connect unary protocol version.
	ConnectProtocolVersionHeader = "Connect-Protocol-Version"
	// ConnectProtocolVersion is the only Connect protocol version RAMP speaks.
	ConnectProtocolVersion = "1"
	// ProtocolVersion is the RAMP protocol version stamped on the `ver` field of
	// every RAMP message — NOT the Connect transport version above. It is the one
	// source this value comes from, so a protocol bump is a single edit here
	// rather than a literal hunt across every message builder. Senders MUST stamp
	// it; receivers treat `ver` as advisory and reject only on an unrecognised
	// MAJOR version (see "Protocol version" in ramp.proto). The
	// /.well-known/ramp.json document carries its own schema version in a
	// separate namespace, which this constant does NOT supply.
	ProtocolVersion = "1.0"
	// RequestIDHeader correlates a request across services and the edge.
	RequestIDHeader = "X-Request-ID"
	// SignatureAgentHeader carries the signer's Web Bot Auth key-directory URL
	// (the WBA identity anchor). It is a required covered component: every RAMP
	// signature commits to it, empty included, so the directory a verifier
	// resolves keys from is the one the signer bound.
	SignatureAgentHeader = "Signature-Agent"
)

// signatureAgentLower is SignatureAgentHeader in the lowercase form RFC 9421
// covered-component names use.
const signatureAgentLower = "signature-agent"
