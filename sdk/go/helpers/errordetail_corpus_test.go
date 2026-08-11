package helpers

// Go replay of the shared ErrorDetail corpus (error-detail-vectors.json). This is
// the Go leg of the cross-language replay: it parses each vector's canonical
// proto-JSON wire form into a *rampv1.ErrorDetail and asserts the extracted
// projection (domain, message, metadata, typed reason) matches the recorded
// oracle. The Python (test_errordetail_parity.py) and TS (errordetail.parity.
// test.ts) replays parse the SAME wire_json into their generated ErrorDetail
// models and assert the same projection — so a divergence in any language's
// ErrorDetail decoding fails here or there, at the replay boundary.
//
// The reason is read back through the REAL helpers.Reason accessor (the emit side
// built it through the helpers.*Detail builders), so this exercises the actual
// read path a Connect client uses once it has the detail in hand.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

func loadErrorDetailCorpus(t *testing.T) []errorDetailVector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "error-detail-vectors.json"))
	if err != nil {
		t.Fatalf("read error-detail corpus: %v", err)
	}
	var doc struct {
		Canonicalization string              `json:"canonicalization"`
		Vectors          []errorDetailVector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode error-detail corpus: %v", err)
	}
	if doc.Canonicalization != "proto-json-snake" {
		t.Fatalf("unexpected canonicalization marker %q", doc.Canonicalization)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("error-detail corpus is empty")
	}
	return doc.Vectors
}

func TestErrorDetailCorpusReplay(t *testing.T) {
	for _, v := range loadErrorDetailCorpus(t) {
		t.Run(v.Name, func(t *testing.T) {
			wireBytes, err := json.Marshal(v.WireJSON)
			if err != nil {
				t.Fatalf("re-marshal wire_json: %v", err)
			}
			var got rampv1.ErrorDetail
			if err := protojson.Unmarshal(wireBytes, &got); err != nil {
				t.Fatalf("protojson unmarshal wire_json: %v", err)
			}
			if got.GetDomain() != v.Domain {
				t.Errorf("domain = %q, want %q", got.GetDomain(), v.Domain)
			}
			if got.GetMessage() != v.Message {
				t.Errorf("message = %q, want %q", got.GetMessage(), v.Message)
			}
			assertMetadataEqual(t, got.GetMetadata(), v.Metadata)
			assertReasonEqual(t, &got, v.ReasonField, v.ReasonEnum)
			assertFieldErrorsEqual(t, &got, v.FieldErrors)
		})
	}
}

// assertFieldErrorsEqual compares the RegistrationFailure per-member detail a
// reader extracts against the recorded projection. An absent list and an empty one
// are equal (proto3 omits an empty repeated field on the wire). The empty path is
// asserted positionally, so a decoder that drops "" as unset fails here rather
// than shifting the list silently.
func assertFieldErrorsEqual(t *testing.T, got *rampv1.ErrorDetail, want []errorDetailFieldError) {
	t.Helper()
	fes := got.GetRegistrationFailure().GetFieldErrors()
	if len(fes) != len(want) {
		t.Errorf("field_errors count = %d, want %d", len(fes), len(want))
		return
	}
	for i, w := range want {
		if fes[i].GetPath() != w.Path || fes[i].GetError() != w.Error {
			t.Errorf("field_errors[%d] = {%q, %q}, want {%q, %q}",
				i, fes[i].GetPath(), fes[i].GetError(), w.Path, w.Error)
		}
	}
}

// assertMetadataEqual compares the extracted metadata against the recorded
// projection, treating a nil map and an empty map as equal (proto3 omits an empty
// map on the wire, so a reader legitimately extracts either).
func assertMetadataEqual(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("metadata size = %d, want %d (%v vs %v)", len(got), len(want), got, want)
		return
	}
	for k, wv := range want {
		if gv, ok := got[k]; !ok || gv != wv {
			t.Errorf("metadata[%q] = %q (present=%v), want %q", k, gv, ok, wv)
		}
	}
}

// assertReasonEqual checks the typed reason extracted via the REAL helpers.Reason
// matches the recorded oneof key + enum NAME (both "" ⇒ no reason).
func assertReasonEqual(t *testing.T, d *rampv1.ErrorDetail, wantField, wantEnum string) {
	t.Helper()
	r := Reason(d)
	if wantField == "" {
		if r != nil {
			t.Errorf("reason = %v, want none", r)
		}
		return
	}
	if r == nil {
		t.Fatalf("reason = none, want field %q enum %q", wantField, wantEnum)
	}
	s, ok := r.(fmt.Stringer)
	if !ok {
		t.Fatalf("reason %T is not a Stringer", r)
	}
	if s.String() != wantEnum {
		t.Errorf("reason enum = %q, want %q", s.String(), wantEnum)
	}
	if gotField, _ := reasonProjection(d); gotField != wantField {
		t.Errorf("reason field = %q, want %q", gotField, wantField)
	}
}
