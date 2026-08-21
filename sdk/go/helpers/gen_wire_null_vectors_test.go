package helpers

// Golden-vector emitter for the null half of the wire policy.
//
// proto-JSON spells "this field has no value" as null, and the codec a RAMP Exchange runs
// puts that on the wire: EmitUnpopulated renders an unset non-optional field as null rather
// than omitting it. Every SDK has to READ that, and the corpus is what says so in one place
// for all three.
//
// It exists because the absence of exactly this corpus let a real break ship. The rule was
// implemented once against message-TYPED fields, which is not the same question — the type
// generator flattens google.protobuf.Timestamp to a plain string schema, so an unset
// timestamp arrived as a null that no longer looked like a message and the whole response
// was refused. Go and Python accepted the same bytes. Nothing failed, because no vector
// carried a null on anything but a message.
//
// So the cases are the shapes that broke rather than a tour of the type system: the two
// messages a discovery answer actually carries an unset timestamp in, the response that
// embeds one of them, and a null on a defaulted scalar — which the oracle reads as the
// default, not as an absence, and which a rule written only for optional fields would still
// refuse.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gowebpki/jcs"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const wireNullVectorsPath = "testdata/wire-null-vectors.json"

// wireNullVector is one body a conformant peer may send, and the verdict every SDK owes it.
type wireNullVector struct {
	// Name identifies the shape under test.
	Name string `json:"name"`
	// Message is the generated type the body is parsed against — the schema/model name each
	// language looks up, not the proto path.
	Message string `json:"message"`
	// WireJSON is the body itself. Emitted through the codec's own option set, then
	// JCS-stabilized because protojson's whitespace is deliberately not deterministic and a
	// committed corpus has to be byte-exact.
	WireJSON json.RawMessage `json:"wire_json"`
	// Accepted is the oracle's verdict: whether protojson reads this body without error.
	// Always true here — a body the wire is allowed to carry is a body every SDK must read —
	// and recorded rather than assumed so a replay asserts the oracle's answer instead of
	// its own expectation.
	Accepted bool `json:"accepted"`
	// Note says what the case pins, so a failure names the rule and not just a shape.
	Note string `json:"note"`
}

// buildWireNullVectors renders each case through the codec's option set and records what
// the oracle makes of the result.
func buildWireNullVectors(t *testing.T) []wireNullVector {
	t.Helper()

	emit := func(name, message, note string, m proto.Message) wireNullVector {
		raw, err := wireEmitJSONOptions.Marshal(m)
		if err != nil {
			t.Fatalf("%s: wire proto-JSON marshal: %v", name, err)
		}
		body, err := jcs.Transform(raw)
		if err != nil {
			t.Fatalf("%s: wire JCS: %v", name, err)
		}
		return wireNullVector{
			Name:     name,
			Message:  message,
			WireJSON: body,
			Accepted: acceptedByOracle(t, name, message, body),
			Note:     note,
		}
	}

	// A null the codec never emits, so it cannot be built by marshalling a message: a
	// defaulted scalar renders as its zero value ("" here), and only a peer that is not
	// this codec sends the null. proto-JSON allows it, and the oracle reads it as "".
	defaulted := json.RawMessage(`{"keyid":null,"verifier":"v.test"}`)

	return []wireNullVector{
		emit(
			"attestation_without_an_attested_at",
			"ResourceAttestation",
			"an unset Timestamp renders as null; the type generator flattens it to a string schema, so a rule written for message-typed fields refuses it",
			&rampv1.ResourceAttestation{Verifier: "v.test"},
		),
		emit(
			"rate_limit_without_a_reset_time",
			"RateLimitInfo",
			"the same unset Timestamp, on the message every discovery answer that reports a rate limit carries",
			&rampv1.RateLimitInfo{Limit: 300, Remaining: 299},
		),
		emit(
			"response_carrying_a_rate_limit_without_a_reset_time",
			"ResourceResponse",
			"one unset Timestamp one level down refuses the WHOLE answer, which is what a caller actually meets",
			&rampv1.ResourceResponse{
				Ver:       ProtocolVersion,
				Exchange:  "exchange.test",
				RateLimit: &rampv1.RateLimitInfo{Limit: 300, Remaining: 299},
			},
		),
		{
			Name:     "defaulted_scalar_sent_as_null",
			Message:  "ResourceAttestation",
			WireJSON: defaulted,
			Accepted: acceptedByOracle(t, "defaulted_scalar_sent_as_null", "ResourceAttestation", defaulted),
			Note:     "a null on a field carrying a default is the default, not an absence — the oracle reads keyid as the empty string",
		},
	}
}

// acceptedByOracle records whether protojson reads the body, so the corpus carries the
// oracle's verdict rather than the emitter's belief about it.
func acceptedByOracle(t *testing.T, name, message string, body []byte) bool {
	t.Helper()
	var m proto.Message
	switch message {
	case "ResourceAttestation":
		m = &rampv1.ResourceAttestation{}
	case "RateLimitInfo":
		m = &rampv1.RateLimitInfo{}
	case "ResourceResponse":
		m = &rampv1.ResourceResponse{}
	default:
		t.Fatalf("%s: no oracle wired for message %q", name, message)
	}
	// Default read options: the wire contract adds nothing on the way in, so this is the
	// same parse a RAMP server performs on a request and a client on a response.
	return protojson.Unmarshal(body, m) == nil
}

func TestGenerateWireNullVectors(t *testing.T) {
	doc := map[string]any{"vectors": buildWireNullVectors(t)}
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, filepath.FromSlash(wireNullVectorsPath), doc)
		return
	}
	assertMatches(t, filepath.FromSlash(wireNullVectorsPath), doc)
}
