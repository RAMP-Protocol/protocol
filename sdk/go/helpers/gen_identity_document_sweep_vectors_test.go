package helpers

// Identity-document DIFFERENTIAL SWEEP corpus.
//
// THIS EMITTER RECORDS THE FACE, NOT A DECLARED INTENT, and that is the one way
// it differs from gen_identity_document_vectors_test.go beside it. That emitter
// carries the verdict its author meant for each case and refuses to write a file
// where the real face disagrees, so it catches "the behaviour changed". This one
// generates thousands of machine-made inputs that no author could hand-declare a
// verdict for, and writes down whatever Go answers. It therefore catches a
// different failure: the three SDKs, or three versions of them, ANSWERING
// DIFFERENTLY. Read a diff here as "something moved", never as "something broke"
// — check it against the intent corpus, which is where intent lives.
//
// Why it exists at all. A golden corpus proves parity only over the inputs it
// holds, and a corpus written from realistic values holds only realistic values
// — exactly the region where independent implementations already agree. Three
// review rounds of hand-written vectors passed in all three languages while the
// ports returned different strings for an apostrophe in a query, a second hash
// in a fragment, a dot segment in the manifest URL, and a second colon in an
// authority. Every one of those was found by sweeping, not by reading.
//
// The sweep used to be a scratch script that was thrown away after each use, so
// nothing would have re-run it after the next Go, CPython or Node upgrade
// changed a URL parser. As a committed corpus the Python and TypeScript replays
// pick it up through the ordinary shared-corpus convention, and
// sdk/python/tests/test_corpus_replay_completeness.py makes replaying it in all
// three languages mandatory.
//
// The alphabet is CURATED, not a cross-product: every ASCII byte in each of the
// three positions the parsers treat differently, plus the structural forms. A
// full cross-product would be megabytes and would say nothing the curated set
// does not.
//
// Verification no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// sweepBases are the manifest URLs the character sweep runs against. Each one
// exercises a part of the base that a reference interacts with: a plain base, a
// base whose query a reference may inherit, a base carrying dot segments to be
// removed, and a base on a non-default port that has to survive into the output.
var sweepBases = []string{
	"https://a.example/.well-known/ramp.json",
	"https://a.example/ramp.json?bq",
	"https://a.example/a/../ramp.json",
	"https://a.example:8443/.well-known/ramp.json",
}

// sweepRefTemplates place one character in each position the three URL engines
// treat under a different rule. "%c" is where the character goes. The first
// three are the positions that matter most: the earlier sweep covered only the
// path, and the apostrophe and hash divergences both lived in the other two.
var sweepRefTemplates = []string{
	"/x%cy",    // inside a path segment
	"/x?a=%cb", // inside a query
	"/x#f%cg",  // inside a fragment
	"%cx",      // opening the reference, before anything has been decided
}

// sweepStructuralRefs are shapes rather than characters: the forms where the
// three parsers disagree about what a reference IS, not about how to spell one.
var sweepStructuralRefs = []string{
	"", "/", "//", "///x", "?", "#", "?#", "#?", "/x?", "/x#", "/x?#",
	"..", "../", "../../x", "./x", ".", "/a/../b", "/a/./b", "/../x", "x",
	":/x", "1:x", "a:b", "https:", "https:/x", "https://", "https://a.example",
	"//a.example", "//a.example/x", "//a.example:443/x", "//A.Example/x",
	"//a.example:8443/x", "//a.example:0443/x", "//a.example:70000/x",
	"//a.example:/x", "//a.example:8443:9/x", "//u:p@a.example/x", "//@a.example/x",
	"https://a.example:0443/x", "https://a.example:8443/x", "https://b.example/x",
	"https://keys.a.example/x", "http://a.example/x",
	"?a=b#c", "#a#b", "/x;", "/x;p", "/x;p=1", "%41", "%2e/x", "%2E%2E/x",
	"%zz", "/x%", "/x%2", "/x%00", "/x?a=%41", "/x#%41",
}

// sweepManifests are the manifest URLs the structural forms run against. Wider
// than sweepBases: these add the base shapes that are refusals in their own
// right, so a port that refuses them for the wrong reason still shows up.
var sweepManifests = append([]string{
	"https://a.example:443/ramp.json",
	"https://a.example:8443:9/ramp.json",
	"https://a.example:/ramp.json",
	"https://A.Example/ramp.json",
	"https://a.example/a/./ramp.json",
	"http://a.example/ramp.json",
	"https://u:p@a.example/ramp.json",
	"a.example/ramp.json",
	"",
}, sweepBases...)

// sweepDotAtoms build references out of dot segments and EMPTY segments, in
// every pairing. This is the class the first two sweep alphabets missed: they
// held dot segments and they held empty segments, but never a "..' that pops
// past the root with an empty segment behind it, which is where net/url and RFC
// 3986 5.2.4 part company. Crossed with bases of four different depths, because
// whether a pop underflows depends on how deep the base is.
var sweepDotAtoms = []string{
	"", "/", "//", "///", ".", "..", "./", "../", "/.", "/..", "/./", "/../",
	"x", "/x", "//x", "x/",
}

// sweepDotBases vary only in path depth, which is the one property that decides
// whether a given run of "..' segments underflows.
var sweepDotBases = []string{
	"https://a.example/ramp.json",
	"https://a.example/a/ramp.json",
	"https://a.example/a/b/ramp.json",
	"https://a.example//ramp.json",
}

// A PLAIN segment followed by a segment that BEGINS with a dot without being a
// dot segment. That is the shape Node's URL parser breaks on: it stops removing
// dot segments for the rest of the path, so "x/.x/.." came back as "x/.x/.."
// where the RFC answers "/x/". A dotted atom on its own is not enough — with the
// dotted segment first, or with only dotted segments before it, the parser
// behaves, so a corpus built from bare dotted atoms would have passed on the
// broken code. Kept as its own small product rather than folded into the atom
// cross product above, which would have multiplied the whole corpus to pin one
// class.
var sweepDottedPrefixes = []string{
	"/x/.x", "x/.x", "/a/b/.x", "/a/.x", "/a/.well-known", "/x/..x", "/x/x.",
	"/.x", "/.x/.y",
}

// The tails that ask for dot-segment removal AFTER the dotted segment, which is
// the removal Node skips.
var sweepDottedSuffixes = []string{
	"", "/..", "/../", "/../y", "/.", "/./y", "/..//y", "/y", "/../..",
	"/../b/.y/..",
}

func buildIdentityDocumentSweepVectors(t *testing.T) []identityDocumentVector {
	t.Helper()
	var out []identityDocumentVector
	record := func(manifest, ref string) {
		resolved, err := ResolveIdentityDocument(manifest, ref)
		if err != nil {
			resolved = ""
		}
		out = append(out, identityDocumentVector{
			// Positional, because there is nothing to name: the manifest URL
			// and the reference are the case. Stable across runs because the
			// generation order is fixed.
			Name:        fmt.Sprintf("sweep_%04d", len(out)),
			ManifestURL: manifest,
			Ref:         ref,
			Accepted:    err == nil,
			Resolved:    resolved,
		})
	}
	// Every ASCII byte, control characters and DEL included, in each position.
	for _, manifest := range sweepBases {
		for c := 0; c < 128; c++ {
			for _, tmpl := range sweepRefTemplates {
				record(manifest, fmt.Sprintf(tmpl, rune(c)))
			}
		}
	}
	for _, manifest := range sweepManifests {
		for _, ref := range sweepStructuralRefs {
			record(manifest, ref)
		}
	}
	for _, manifest := range sweepDotBases {
		for _, a := range sweepDotAtoms {
			for _, b := range sweepDotAtoms {
				if a+b == "" {
					continue // the empty reference, already covered and refused
				}
				record(manifest, a+b)
			}
		}
	}
	for _, manifest := range sweepDotBases {
		for _, prefix := range sweepDottedPrefixes {
			for _, suffix := range sweepDottedSuffixes {
				record(manifest, prefix+suffix)
			}
		}
	}
	return out
}

// TestGenerateIdentityDocumentSweepVectors emits the differential sweep corpus.
// Verification no-op by default, (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateIdentityDocumentSweepVectors(t *testing.T) {
	doc := map[string]any{
		"identity_document_sweep": buildIdentityDocumentSweepVectors(t),
	}
	path := filepath.Join("testdata", "identity-document-sweep-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
