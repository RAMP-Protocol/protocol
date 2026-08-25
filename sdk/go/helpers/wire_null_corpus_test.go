package helpers

// Go replay of the null wire-policy corpus (wire-null-vectors.json).
//
// Go replays it rather than only emitting it — a corpus its own oracle does not consume
// proves nothing about the oracle. Here that is more than a formality: the emitter records
// the verdict this test re-derives, so if the two ever disagree the corpus is lying to the
// two languages that cannot check it for themselves.

import (
	"encoding/json"
	"os"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestWireNullCorpusReplay(t *testing.T) {
	raw, err := os.ReadFile(wireNullVectorsPath) //nolint:gosec // a committed test vector
	if err != nil {
		t.Fatalf("read %s: %v", wireNullVectorsPath, err)
	}
	var doc struct {
		Vectors []wireNullVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", wireNullVectorsPath, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", wireNullVectorsPath)
	}

	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var m proto.Message
			switch v.Message {
			case "ResourceAttestation":
				m = &rampv1.ResourceAttestation{}
			case "RateLimitInfo":
				m = &rampv1.RateLimitInfo{}
			case "ResourceResponse":
				m = &rampv1.ResourceResponse{}
			default:
				t.Fatalf("no message wired for %q", v.Message)
			}
			err := protojson.Unmarshal(v.WireJSON, m)
			if (err == nil) != v.Accepted {
				t.Fatalf("accepted=%v, want %v: %s (err=%v)", err == nil, v.Accepted, v.Note, err)
			}
		})
	}
}

// TestWireNullCorpusReadsTheDefault pins the half a boolean verdict cannot carry: a null on
// a defaulted field is not merely ACCEPTED, it reads as that default. Without this the
// corpus would be satisfied by a parser that accepted the null and left the field holding
// anything at all, which is the divergence the other two languages are being held to.
func TestWireNullCorpusReadsTheDefault(t *testing.T) {
	var a rampv1.ResourceAttestation
	if err := protojson.Unmarshal([]byte(`{"keyid":null,"verifier":"v.test"}`), &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a.GetKeyid() != "" {
		t.Fatalf("keyid = %q, want the empty string — a null is the default, not an absence", a.GetKeyid())
	}
}
