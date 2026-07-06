// Package conformance — canonical_test.go is the canonical proto-JSON interop
// gate for the generated clients.
//
// PR10's clients (Pydantic/Zod) consume and produce proto-JSON, not the binary
// wire. This asserts that a client's *output* is canonical enough for the Go
// server: each client parses a valid corpus instance, re-serializes it, and the
// re-emitted JSON — read back through Go protojson — must decode to the SAME proto
// message as the original Go-canonical JSON (proto.Equal). This is the round-trip-
// against-Go obligation, NOT a self-round-trip: it tolerates the benign encoding
// differences proto-JSON permits (int64 as number vs the canonical string, omitted
// vs explicit zero fields) because both decode identically, while catching any
// emission Go cannot ingest (e.g. money as a number into a string field, or a
// malformed timestamp).
//
// The client emissions are produced by scripts/check-canonical.sh (Pydantic +
// Zod) and handed in via the CANONICAL_PY / CANONICAL_TS env vars; the test skips
// when they are absent so a plain `go test ./...` stays self-contained.
package conformance

import (
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

type emittedCase struct {
	ID      string          `json:"id"`
	Message string          `json:"message"`
	JSON    json.RawMessage `json:"json"`
}

func TestCanonicalRoundTrip(t *testing.T) {
	corpus := map[string]json.RawMessage{}
	for _, c := range loadCorpus(t) {
		corpus[c.ID] = c.JSON
	}
	for _, lang := range []struct{ env, label string }{
		{"CANONICAL_PY", "Pydantic"},
		{"CANONICAL_TS", "Zod"},
	} {
		t.Run(lang.label, func(t *testing.T) {
			path := os.Getenv(lang.env)
			if path == "" {
				t.Skipf("set %s to the %s round-trip emission (scripts/check-canonical.sh)", lang.env, lang.label)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var emitted []emittedCase
			if err := json.Unmarshal(b, &emitted); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if len(emitted) == 0 {
				t.Fatalf("%s emission is empty", lang.label)
			}
			for _, e := range emitted {
				t.Run(e.ID, func(t *testing.T) {
					orig, ok := corpus[e.ID]
					if !ok {
						t.Fatalf("emission references unknown corpus id %q", e.ID)
					}
					mOrig := newMessage(t, e.Message)
					if err := protojson.Unmarshal(orig, mOrig); err != nil {
						t.Fatalf("unmarshal original: %v", err)
					}
					mClient := newMessage(t, e.Message)
					if err := protojson.Unmarshal(e.JSON, mClient); err != nil {
						t.Errorf("%s emission is not ingestible by Go protojson: %v\n  emitted=%s", e.Message, err, e.JSON)
						return
					}
					if !proto.Equal(mOrig, mClient) {
						t.Errorf("round-trip changed the message.\n  original=%s\n  emitted =%s", orig, e.JSON)
					}
				})
			}
		})
	}
}

func newMessage(t *testing.T, short string) proto.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName("ramp.v1." + short))
	if err != nil {
		t.Fatalf("unknown message ramp.v1.%s: %v", short, err)
	}
	return mt.New().Interface()
}
