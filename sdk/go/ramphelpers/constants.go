package ramphelpers

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
	// RequestIDHeader correlates a request across services and the edge.
	RequestIDHeader = "X-Request-ID"
)
