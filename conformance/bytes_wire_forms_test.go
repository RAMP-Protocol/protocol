// Package conformance — bytes_wire_forms_test.go is the ORACLE half of the
// shared base64 truth table (testdata/bytes_wire_forms.json).
//
// The table says, for each bytes-rule field, which base64 wire forms are
// accepted. The Pydantic and Zod harnesses assert those verdicts against the
// generated schemas; this test asserts the SAME rows against Go — protojson's
// decoder plus protovalidate — which is what the generated patterns are supposed
// to mirror. Without it, the table would be a hand-written claim about Go's
// behavior on both client sides and nothing would check the claim: a row pinned
// from a wrong belief (that protojson accepts a mixed-alphabet string, say) would
// make both clients agree with each other and disagree with the server.
//
// It also keeps the shared bases honest: each one must be a VALID message, so it
// cannot drift into a shape where a "rejected" row is rejected for an unrelated
// reason.
package conformance

import (
	"encoding/json"
	"os"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type bytesWireForm struct {
	Value    string `json:"value"`
	Accepted bool   `json:"accepted"`
	Why      string `json:"why"`
}

type bytesWireVectors struct {
	Bases    map[string]map[string]any `json:"bases"`
	FormSets map[string]struct {
		Rule  string          `json:"rule"`
		Forms []bytesWireForm `json:"forms"`
	} `json:"form_sets"`
	Fields []struct {
		Message string `json:"message"`
		Field   string `json:"field"`
		FormSet string `json:"form_set"`
	} `json:"fields"`
}

func loadBytesWireVectors(t *testing.T) bytesWireVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/bytes_wire_forms.json")
	if err != nil {
		t.Fatalf("read bytes wire-form vectors: %v", err)
	}
	var v bytesWireVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode bytes wire-form vectors: %v", err)
	}
	if len(v.Fields) == 0 {
		t.Fatal("bytes wire-form vectors carry no fields — the shared table is wired to nothing")
	}
	return v
}

// parseBase applies one field override to a base and returns the message, plus
// whether protojson accepted the JSON at all (a malformed base64 string is
// rejected by the DECODER, before any rule runs).
func parseBase(t *testing.T, message string, base map[string]any, field string, value any) (proto.Message, bool) {
	t.Helper()
	obj := map[string]any{}
	for k, v := range base {
		obj[k] = v
	}
	if field != "" {
		obj[field] = value
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal case json: %v", err)
	}
	mt, err := findContractMessage(message)
	if err != nil {
		t.Fatalf("resolve message %s: %v", message, err)
	}
	m := mt.New().Interface()
	if err := protojson.Unmarshal(raw, m); err != nil {
		return nil, false
	}
	return m, true
}

func TestBytesWireFormsMatchGo(t *testing.T) {
	vectors := loadBytesWireVectors(t)
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate: %v", err)
	}

	// The bases must be valid on their own, or a rejected row proves nothing.
	for message, base := range vectors.Bases {
		m, ok := parseBase(t, message, base, "", nil)
		if !ok {
			t.Errorf("base for %s is not decodable proto-JSON", message)
			continue
		}
		if err := v.Validate(m); err != nil {
			t.Errorf("base for %s is not a valid message: %v — a 'rejected' row would then be rejected for the wrong reason", message, err)
		}
	}

	for _, f := range vectors.Fields {
		set, ok := vectors.FormSets[f.FormSet]
		if !ok {
			t.Errorf("%s.%s names form set %q, which the table does not define", f.Message, f.Field, f.FormSet)
			continue
		}
		base, ok := vectors.Bases[f.Message]
		if !ok {
			t.Errorf("%s.%s has no base in the table", f.Message, f.Field)
			continue
		}
		for _, form := range set.Forms {
			m, decoded := parseBase(t, f.Message, base, f.Field, form.Value)
			accepted := decoded && v.Validate(m) == nil
			if accepted != form.Accepted {
				t.Errorf("%s.%s = %q (%s, %s): the table says accepted=%v, Go says %v — the generated client patterns mirror Go, so fix the row or the rule, not the pattern",
					f.Message, f.Field, form.Value, set.Rule, form.Why, form.Accepted, accepted)
			}
		}
	}
}
