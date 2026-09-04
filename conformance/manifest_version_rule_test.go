package conformance

// Drift guard: the manifest-version rule the SDKs enforce IS the rule the contract
// states.
//
// WellKnownManifest.ver carries a normative receive-side rule — accept a recognised
// MAJOR, reject an unrecognised MAJOR, a malformed value, and an absent field — and
// it deliberately carries no protovalidate rule: a pattern would make the field
// structurally required on every message that embeds the manifest, and an exact
// match would refuse the additive minor revisions the rule exists to admit. So the
// contract's whole statement of the rule is prose in the field's comment, and the
// enforcement is code in three SDK endpoint resolvers.
//
// Between them sits the shared corpus, which pins the three implementations to each
// other. This file pins both to the prose, the same construction as
// endpoint_rule_test.go and for the same reason: both halves are DATA READS, and
// nothing here imports sdk/go.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// manifestVersionVectors is the SDK's committed verdict set for the rule, read as data.
const manifestVersionVectors = "../sdk/go/helpers/testdata/manifest-version-vectors.json"

type manifestVersionCase struct {
	Name     string `json:"name"`
	Ver      string `json:"ver"`
	Present  bool   `json:"present"`
	Accepted bool   `json:"accepted"`
}

var errNoManifestVersionVectors = errors.New(
	"the manifest-version corpus is missing or empty — regenerate it with " +
		"RAMP_UPDATE_VECTORS=1 go test ./sdk/go/helpers/ -run TestGenerateManifestVersionVectors")

var sdkManifestVersionCases = sync.OnceValues(func() ([]manifestVersionCase, error) {
	b, err := os.ReadFile(manifestVersionVectors)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Cases []manifestVersionCase `json:"manifest_version"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Cases) == 0 {
		return nil, errNoManifestVersionVectors
	}
	return doc.Cases, nil
})

func mustManifestVersionCases(t *testing.T) []manifestVersionCase {
	t.Helper()
	cases, err := sdkManifestVersionCases()
	if err != nil {
		t.Fatalf("read %s: %v", manifestVersionVectors, err)
	}
	return cases
}

// manifestVerComment is the comment block above WellKnownManifest.ver specifically.
// `string ver = 1` appears on every message, so the shared fieldComment extractor
// (first match in file order) would return some other message's envelope comment;
// this walk is message-scoped, the same way ver_field_contract_test.go attributes
// each `ver` to its enclosing message.
func manifestVerComment(t *testing.T) string {
	t.Helper()
	for _, f := range collectVerFields(t) {
		if f.message == "WellKnownManifest" {
			// collectVerFields joins the raw lines, `//` markers included, so a
			// clause that wraps across two source lines carries a marker in the
			// middle. Strip them so phrases are matched against prose.
			return strings.TrimPrefix(strings.ReplaceAll(f.comment, " // ", " "), "// ")
		}
	}
	t.Fatal("WellKnownManifest.ver not found in the contract protos")
	return ""
}

// TestManifestVersionCommentStatesEveryClauseTheSDKEnforces reads the rule out of
// the contract and holds it to the clauses the SDK actually applies.
func TestManifestVersionCommentStatesEveryClauseTheSDKEnforces(t *testing.T) {
	comment := manifestVerComment(t)

	// Guard the guard: pin the extraction to the block it is supposed to have read.
	const opening = "Version of THIS MANIFEST DOCUMENT's layout"
	if !strings.HasPrefix(comment, opening) {
		t.Fatalf("the extracted comment does not begin with the manifest ver's own first line "+
			"(%q) — this guard is reading the wrong block and would assert nothing.\n  read: %.120s…",
			opening, comment)
	}

	for _, clause := range []struct {
		name   string
		phrase string
		why    string
	}{
		{"separate namespace", "separate from the RPC envelope",
			"the manifest version is not the protocol version and is never stamped from it"},
		{"own constant", "WellKnownManifestVersion",
			"the value has one owner, and it is not ProtocolVersion"},
		{"coupling direction", "bumps both numbers",
			"a manifest change moves the protocol version; the reverse does not hold"},
		{"read first", "before any other member",
			"the gate runs before the endpoint is so much as looked at"},
		{"recognised major accepted", "ACCEPT a recognised MAJOR version whatever the MINOR",
			"a minor revision of the manifest is additive"},
		{"unrecognised major rejected", "REJECT an unrecognised MAJOR",
			"a layout the reader cannot classify must not supply the endpoint"},
		{"malformed rejected", "not MAJOR.MINOR",
			"a value the rule cannot parse is not a version it recognises"},
		{"absent rejected", "an ABSENT `ver`",
			"a document with no version is one whose layout the reader cannot classify"},
	} {
		if !strings.Contains(comment, clause.phrase) {
			t.Errorf("the WellKnownManifest.ver comment no longer states %q (%s).\n"+
				"The SDKs still enforce it and the corpus still pins it, so the contract and the "+
				"implementations have drifted — restore the clause or change all four together.",
				clause.name, clause.why)
		}
	}
}

// TestManifestVersionCorpusCoversEveryStatedClause holds the other direction: each
// clause the contract states must be exercised by at least one vector, so three
// SDKs cannot quietly stop enforcing it while the comment still reads correctly.
func TestManifestVersionCorpusCoversEveryStatedClause(t *testing.T) {
	cases := mustManifestVersionCases(t)
	var sameMajorHigherMinor, unrecognisedMajor, malformed, absent bool
	for _, c := range cases {
		switch {
		case !c.Present:
			absent = absent || !c.Accepted
		case c.Accepted && strings.HasPrefix(c.Ver, "1.") && c.Ver != "1.0":
			sameMajorHigherMinor = true
		case !c.Accepted && isMajorMinor(c.Ver) && !strings.HasPrefix(c.Ver, "1."):
			unrecognisedMajor = true
		case !c.Accepted && !isMajorMinor(c.Ver):
			malformed = true
		}
	}
	for name, ok := range map[string]bool{
		"a same-major higher-minor version accepted": sameMajorHigherMinor,
		"an unrecognised major refused":              unrecognisedMajor,
		"a value that is not MAJOR.MINOR refused":    malformed,
		"an absent ver refused":                      absent,
	} {
		if !ok {
			t.Errorf("the corpus at %s has no vector for %s — the contract states the clause, so the SDKs must be pinned to it",
				filepath.Base(manifestVersionVectors), name)
		}
	}
}

// isMajorMinor is the corpus-side classifier used only to sort vectors into the
// clauses above. It is deliberately a loose re-statement, not the SDK's parser:
// the SDK's verdict is what the corpus records, and this only decides which
// clause a recorded verdict exercises.
func isMajorMinor(ver string) bool {
	major, minor, found := strings.Cut(ver, ".")
	return found && digitsOnly(major) && digitsOnly(minor)
}

func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
