package conformance

// Drift guard: the delivery edge's refusal tokens, as the proto records them.
//
// A delivery edge is a code-capable worker with no protobuf runtime, so it answers a
// refused fetch with a string from its own vocabulary. RetrievalAuthFailureReason is the
// typed counterpart, and the mapping between them is recorded ONLY as a trailing comment
// beside each enum value:
//
//	RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED = 1;  // 'expired'
//
// That is a real contract — every SDK has to promote the same token to the same reason, or
// one language's caller branches on a typed reason another language's caller never gets —
// and a comment is a contract nothing enforces. So this reads the annotations out of the
// .proto SOURCE, the way ver_field_contract_test.go reads the rule that lives in a comment
// there, and holds the SDK's committed vectors to them.
//
// It is written because the record and the code came apart, silently and in one direction.
// Two of the three SDKs never read this table at all: they DERIVED each reason's name by
// uppercasing the token and prefixing it, which lands on the recorded value for two of the
// eleven tokens and on nothing for the rest. Nine refusals a real edge emits carried a
// typed reason in one language and none in the other two, and every suite was green,
// because no case compared a language's answer to the proto's record.
//
// The mapping is not derivable, which is the whole reason it is written down: 'expired' is
// URL_EXPIRED and 'pop_expired' is PROOF_EXPIRED, and neither is the enum suffix
// lowercased. A guard that recomputed the token from the value would reproduce the bug it
// exists to catch, so this compares against the source text and nothing else.
//
// Vectors are READ as data. Nothing in conformance depends on sdk/, by design — it is the
// guard tier BELOW the SDKs — and the corpus is a committed file generated from the real
// client and replayed by all three languages, exactly like the corpora the neighbouring
// guards read.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// retrievalReasonEnum is the enum whose values carry the token record.
const retrievalReasonEnum = "RetrievalAuthFailureReason"

// tokenAnnotation matches one recorded value: the enum value, then the edge token in
// single quotes. A value with no quoted token — the UNSPECIFIED zero — does not match, and
// the completeness check below is what notices if a real value stops matching.
var tokenAnnotation = regexp.MustCompile(
	`^\s*(RETRIEVAL_AUTH_FAILURE_REASON_[A-Z0-9_]+)\s*=\s*\d+;\s*//\s*'([a-z0-9_]+)'`)

// recordedTokens reads the token→value record out of the .proto source, as
// value→token and token→values.
func recordedTokens(t *testing.T) (byValue map[string]string, byToken map[string][]string) {
	t.Helper()
	byValue, byToken = map[string]string{}, map[string][]string{}
	for _, cf := range Contract {
		path := filepath.Join("..", "proto", cf.File.Path())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			m := tokenAnnotation.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			byValue[m[1]] = m[2]
			byToken[m[2]] = append(byToken[m[2]], m[1])
		}
	}
	return byValue, byToken
}

// retrievalReasonValues returns every non-zero value of the enum, from the descriptor.
func retrievalReasonValues(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, fd := range ContractFiles() {
		enums := fd.Enums()
		for i := 0; i < enums.Len(); i++ {
			ed := enums.Get(i)
			if ed.Name() != retrievalReasonEnum {
				continue
			}
			values := ed.Values()
			for j := 0; j < values.Len(); j++ {
				vd := values.Get(j)
				if vd.Number() != 0 {
					out = append(out, string(vd.Name()))
				}
			}
		}
	}
	return out
}

// Every reason the enum defines names the token it stands for. A value with no annotation
// is a token an SDK has no way to promote, which is the gap silently rather than a
// decision.
func TestRetrievalTokenRecord_EveryReasonNamesItsToken(t *testing.T) {
	byValue, _ := recordedTokens(t)
	values := retrievalReasonValues(t)
	if len(values) == 0 {
		t.Fatalf("%s defines no non-zero values — this guard has lost its anchor",
			retrievalReasonEnum)
	}
	for _, v := range values {
		if byValue[v] == "" {
			t.Errorf("%s records no edge token; the mapping is not derivable from the "+
				"value's own spelling, so an unannotated value cannot be promoted at all", v)
		}
	}
}

// The SDK's committed answers ARE the proto's record. Read from the corpus every language
// replays, so a port that computes the mapping instead of reading it fails here as well as
// in its own suite.
func TestRetrievalTokenRecord_TheCorpusMatchesTheProto(t *testing.T) {
	_, byToken := recordedTokens(t)
	if len(byToken) == 0 {
		t.Fatal("no token annotations were read — this guard would vacuously pass")
	}

	b, err := os.ReadFile(synthesizedDetailVectors)
	if err != nil {
		t.Fatalf("read %s: %v", synthesizedDetailVectors, err)
	}
	var doc struct {
		Edge []struct {
			Name        string `json:"name"`
			ReasonToken string `json:"reason_token"`
			ReasonEnum  string `json:"reason_enum"`
		} `json:"edge_refusal"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", synthesizedDetailVectors, err)
	}
	if len(doc.Edge) == 0 {
		t.Fatalf("%s records no edge refusals — this guard would vacuously pass",
			synthesizedDetailVectors)
	}

	recorded := map[string]bool{}
	for _, row := range doc.Edge {
		recorded[row.ReasonToken] = true
		values := byToken[row.ReasonToken]
		switch {
		case len(values) == 0:
			// A token the proto does not record. It must reach the caller untyped:
			// promoting it would attribute a reason the contract never assigned.
			if row.ReasonEnum != "" {
				t.Errorf("%s: %q is not a token the proto records, but the SDK promoted "+
					"it to %s", row.Name, row.ReasonToken, row.ReasonEnum)
			}
		case len(values) > 1:
			// Recorded against more than one value: the body does not say which check
			// ran, so no language may choose.
			if row.ReasonEnum != "" {
				t.Errorf("%s: the proto records %q against %d values, so promoting it to "+
					"%s attributes a failure the wire never did",
					row.Name, row.ReasonToken, len(values), row.ReasonEnum)
			}
		case row.ReasonEnum != values[0]:
			t.Errorf("%s: the proto records %q as %s, the SDK answers %s",
				row.Name, row.ReasonToken, values[0], row.ReasonEnum)
		}
	}

	// Completeness. A per-token table is only as good as its coverage, and a sample is
	// what let two ports type two tokens and drop nine while looking correct.
	for token := range byToken {
		if !recorded[token] {
			t.Errorf("the proto records the token %q and no vector replays it, so no "+
				"language is held to it", token)
		}
	}
}

// The meta-tests: the annotation reader answers for the shapes it claims to. A regex that
// silently matches nothing is a guard that silently passes.
func TestRetrievalTokenRecord_ReaderAnswersForBothShapes(t *testing.T) {
	for line, want := range map[string][2]string{
		"  RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED = 1;             // 'expired'": {
			"RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED", "expired"},
		"  RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED = 11; // 'pop_expired'": {
			"RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED", "pop_expired"},
	} {
		m := tokenAnnotation.FindStringSubmatch(line)
		if m == nil || m[1] != want[0] || m[2] != want[1] {
			t.Errorf("reader missed the annotation in %q", line)
		}
	}
	for _, line := range []string{
		"  RETRIEVAL_AUTH_FAILURE_REASON_UNSPECIFIED = 0;  // unset — rejected at ingest",
		"  // 'expired' is what the edge answers",
		"  DENIAL_REASON_RATE_LIMITED = 3;  // 'rate_limited'",
	} {
		if tokenAnnotation.MatchString(line) {
			t.Errorf("reader matched a line that records no retrieval token: %q", line)
		}
	}
}
