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
	"fmt"
	"os"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
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

// TestBytesWireFormCoverageIsComplete derives the table's scope from the
// DESCRIPTOR instead of trusting the table to list itself.
//
// The base64 axis — padded vs unpadded, standard vs url-safe, mixed alphabet,
// pure padding — is the one axis the generated corpus cannot reach, because
// corpusgen emits values through protojson and therefore only ever produces the
// canonical padded standard form. testdata/bytes_wire_forms.json is the ONLY
// coverage those wire forms have, in all three languages.
//
// That made the table's completeness load-bearing and unchecked. Adding a sixth
// bytes-length field tightens the generated Pydantic/Zod pattern automatically,
// so the new field looks covered — while zero wire-form rows exercise it and
// every gate stays green. The failure is silent in exactly the place a reviewer
// would assume coverage exists.
//
// So this fails in BOTH directions, the shape TestRuleIdenticalGroupsAreDeclared
// already uses: a ruled field with no table entry, and a table entry naming a
// field that no longer carries the rule. It also pins the form set to the rule's
// VALUE, so a bytes.len = 64 field cannot quietly point at the 32-byte set and
// collect verdicts computed for a different length.
func TestBytesWireFormCoverageIsComplete(t *testing.T) {
	vectors := loadBytesWireVectors(t)

	// want: every bytes-length rule in the contract, keyed as the table keys it.
	// Bare message names are safe as keys because AssertUniqueBareNames proves
	// they are unique contract-wide.
	want := map[string]string{}
	EachRuleSet(func(md protoreflect.MessageDescriptor, fd protoreflect.FieldDescriptor, prefix string, fr *validate.FieldRules) {
		r := MustBytesLength(fd, fr)
		if r == nil {
			return
		}
		if prefix != "" {
			// A bytes-length rule under repeated.items. (or map values) is real
			// but the table cannot express it: an entry overrides ONE scalar
			// field on a base message, and the JSON value here would be a list.
			// Fail rather than skip — skipping is how a guard silently narrows.
			t.Errorf("%s carries a bytes-length rule at %s, which the wire-form table cannot express; "+
				"extend the table format to override a repeated/map element before adding this rule",
				fd.FullName(), prefix)
			return
		}
		want[string(md.Name())+"."+string(fd.Name())] = fmt.Sprintf("bytes.%s = %d", r.Kind, r.Value)
	})

	got := map[string]string{}
	for _, f := range vectors.Fields {
		key := f.Message + "." + f.Field
		if prev, dup := got[key]; dup {
			t.Errorf("the table lists %s twice (form sets %q and %q) — one field, one form set", key, prev, f.FormSet)
			continue
		}
		got[key] = f.FormSet
	}

	// Direction 1: every ruled field must be in the table.
	for key, rule := range want {
		formSet, listed := got[key]
		if !listed {
			t.Errorf("%s carries %s but has no entry in testdata/bytes_wire_forms.json — the generated "+
				"patterns already enforce it in Pydantic and Zod, so with no rows nothing checks that the "+
				"three languages agree on padding and alphabet", key, rule)
			continue
		}
		// Direction 3: the named form set must be the one for THIS rule value.
		set, defined := vectors.FormSets[formSet]
		if !defined {
			continue // TestBytesWireFormsMatchGo reports the undefined set
		}
		if set.Rule != rule {
			t.Errorf("%s carries %s but points at form set %q, whose rows were computed for %q — "+
				"the verdicts in that set do not describe this field", key, rule, formSet, set.Rule)
		}
	}

	// Direction 2: every table entry must name a field that still carries a rule.
	for key := range got {
		if _, ruled := want[key]; !ruled {
			t.Errorf("testdata/bytes_wire_forms.json lists %s, which carries no bytes-length rule in the "+
				"contract — the rule was removed or the field renamed, and the rows now prove nothing", key)
		}
	}
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
