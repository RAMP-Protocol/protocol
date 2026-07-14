package resolvers

// Golden-vector emitter for the cross-language WBA-directory URL-builder parity
// corpus. sdk/python `wba_directory_url` and sdk/ts `wbaDirectoryURL` REPLAY this
// corpus and MUST reproduce the sdk/go `WBADirectoryURL` oracle's built URL for
// EVERY vector.
//
// The built URL is what a WBA identity directory is fetched from:
// scheme://host + WBADirectoryPath. Each vector is {label, scheme, host,
// expected_url}; scheme/host are the two explicit builder args (scheme empty →
// https, host arrives ALREADY-JOINED) and expected_url is emitted by RUNNING the
// real Go WBADirectoryURL — Go is the oracle, never a hand-authored table.
//
// COVERAGE (the seam the three languages must agree on): (a) https-default — an
// empty scheme defaults to https; (b) explicit-http — a non-default scheme is
// honored verbatim; (c) host-with-port — a host carrying :port is passed through
// unchanged; (d) ipv6-passthrough — an ALREADY-bracketed IPv6 host is not mangled
// (this proves the PURE builder passes a pre-joined host through verbatim; it does
// NOT lock the fetcher-level Go-net.JoinHostPort-vs-TS-${domain}:${port} port-join,
// which lives in the fetchers and is tracked separately).
//
// DETERMINISM: the inputs are fixed literals, so re-running reproduces
// byte-identical output. Default `go test` asserts the committed file matches a
// fresh emit; RAMP_UPDATE_VECTORS=1 rewrites it (same drift-gate shape as
// gen_offer_key_clamp_vectors_test.go).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// wbaURLVector is one builder input pair + the oracle's built URL.
type wbaURLVector struct {
	Label       string `json:"label"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	ExpectedURL string `json:"expected_url"` // emitted by the Go WBADirectoryURL
}

type wbaURLCorpus struct {
	Note    string         `json:"note"`
	Vectors []wbaURLVector `json:"vectors"`
}

func buildWBAURLCorpus() wbaURLCorpus {
	build := func(label, scheme, host string) wbaURLVector {
		return wbaURLVector{
			Label:       label,
			Scheme:      scheme,
			Host:        host,
			ExpectedURL: WBADirectoryURL(scheme, host),
		}
	}
	return wbaURLCorpus{
		Note: "WBA directory URL = scheme://host + /.well-known/http-message-signatures-directory, produced by the sdk/go WBADirectoryURL oracle; py/ts replay and must match every vector",
		Vectors: []wbaURLVector{
			build("https-default", "", "exchange.example"),
			build("explicit-http", "http", "exchange.example"),
			build("host-with-port", "https", "exchange.example:8443"),
			build("ipv6-passthrough", "https", "[2001:db8::1]:8443"),
		},
	}
}

// TestGenerateWBAURLVector emits the WBA-URL golden vector. Default run asserts
// the committed file is byte-identical to a fresh emit; RAMP_UPDATE_VECTORS=1
// rewrites it.
func TestGenerateWBAURLVector(t *testing.T) {
	t.Parallel()
	corpus := buildWBAURLCorpus()
	path := filepath.Join("testdata", "wba-url-vectors.json")

	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeWBAURLVector(t, path, corpus)
		return
	}
	want, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = append(want, '\n')
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate", path)
	}
}

func writeWBAURLVector(t *testing.T, path string, corpus wbaURLCorpus) {
	t.Helper()
	b, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // committed test vector
		t.Fatalf("write %s: %v", path, err)
	}
}
