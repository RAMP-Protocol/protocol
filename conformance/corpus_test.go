// Package conformance — corpus_test.go pins the cross-language validation corpus
// (conformance/corpus/cases.json) to Go protovalidate.
//
// The corpus is the single, generated source the Python (Pydantic) and TS (Zod)
// parity tests consume: each case is a proto-JSON instance with the verdict Go
// protovalidate — the requirement's only executable form — assigns it. This test
// re-validates every committed case so the corpus can never silently drift from
// what Go actually does; the drift gate (scripts/ci-local.sh) keeps the file
// itself in sync with `go run ./conformance/corpusgen`.
package conformance

import (
	"encoding/json"
	"os"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

type corpusCase struct {
	ID      string          `json:"id"`
	Message string          `json:"message"`
	Valid   bool            `json:"valid"`
	Rules   []string        `json:"rules"`
	JSON    json.RawMessage `json:"json"`
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	b, err := os.ReadFile("corpus/cases.json")
	if err != nil {
		t.Fatalf("read corpus (run 'go run ./conformance/corpusgen'): %v", err)
	}
	var cs []corpusCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(cs) == 0 {
		t.Fatal("empty corpus — corpusgen produced nothing")
	}
	return cs
}

// TestCorpusMatchesProtovalidate re-validates every committed corpus case and
// asserts the recorded verdict still holds — valid cases pass, invalid cases fail
// and include the recorded rule ids. If this drifts, the cross-language parity
// tests would be measuring the clients against a stale oracle.
func TestCorpusMatchesProtovalidate(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	for _, c := range loadCorpus(t) {
		t.Run(c.ID, func(t *testing.T) {
			mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName("ramp.v1." + c.Message))
			if err != nil {
				t.Fatalf("unknown message ramp.v1.%s: %v", c.Message, err)
			}
			m := mt.New().Interface()
			if err := protojson.Unmarshal(c.JSON, m); err != nil {
				t.Fatalf("unmarshal proto-JSON: %v", err)
			}
			verr := v.Validate(m)
			if c.Valid {
				if verr != nil {
					t.Errorf("corpus marks VALID but protovalidate rejects: %v", verr)
				}
				return
			}
			ve, ok := verr.(*protovalidate.ValidationError)
			if !ok {
				t.Fatalf("corpus marks INVALID but protovalidate accepts (err=%v)", verr)
			}
			for _, r := range c.Rules {
				if !violationsContain(ve, r) {
					t.Errorf("corpus records rule %q but actual violations are %v", r, violationIDs(ve))
				}
			}
		})
	}
}
