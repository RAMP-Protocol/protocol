package resolvers

// Content-leg golden-vector emitter.
//
// The delivery fetch is the one leg where the peer's own words are promoted over the
// SDK's classification: an edge that refuses a bound GET answers a small JSON object, and
// the token in it becomes the reason a caller branches on. That makes three decisions
// cross-language, and none of them is obvious from reading either side alone.
//
// Which answers are a REFUSAL and which are something else. A 4xx and a 5xx are both the
// edge saying no; an oversized body is not — the edge did nothing wrong and the URL is
// still good, so a caller can retry with a larger budget rather than treating the
// purchase as lost.
//
// Which tokens the SDK will repeat. The refusal body is written by the host just fetched
// from. Unchecked, a publisher could answer any few kilobytes of text and have it render
// as though the SDK had said it, so anything that is not token-shaped falls back to the
// failure class, which the SDK does own.
//
// What a Content-Type means. The media type is the content's; the charset belongs to
// whoever decodes the bytes, and a body with no usable header is labelled rather than
// sniffed — the caller is told what the publisher said, and "unknown" is a true answer
// where a guess might not be.
//
// Every vector is DERIVED by driving the real ContentFetcher against a server that
// answers the case, so the corpus records what the oracle does rather than a description
// of it. The Python and TypeScript clients fold this leg into their fetch verb and replay
// the same projection through their own failure type.
//
// Verification no-op by default (asserts the committed file matches a fresh emit);
// (re)writes under RAMP_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/vectorio"
)

// contentFetchVector is one delivery answer and what a client must read out of it.
type contentFetchVector struct {
	Name string `json:"name"`
	//: The status the edge answered with.
	Status int `json:"status"`
	//: The body it answered with, verbatim.
	Body string `json:"body"`
	//: The Content-Type it served, empty when it served none.
	ContentType string `json:"content_type"`
	//: Whether the fetch succeeded.
	OK bool `json:"ok"`
	//: The failure class, in the shared vocabulary. Empty when OK.
	Failure string `json:"failure"`
	//: The edge's own refusal token, when the SDK was willing to repeat it.
	Reason string `json:"reason"`
	//: The most specific machine-readable answer: the token when there is one,
	//: otherwise the failure class. This is what a caller actually branches on.
	ReasonOf string `json:"reason_of"`
	//: The media type a successful fetch reports. Empty when the fetch failed.
	MIMEType string `json:"mime_type"`
}

// contentFetchCases enumerate the delivery answers whose reading must not drift.
func contentFetchCases() []struct {
	name        string
	status      int
	body        string
	contentType string
} {
	return []struct {
		name        string
		status      int
		body        string
		contentType string
	}{
		// Success, and what the media type reduces to.
		{"ok_plain_text", 200, "the licensed bytes", "text/plain; charset=utf-8"},
		{"ok_content_type_uppercased", 200, "{}", "Application/JSON"},
		{"ok_no_content_type", 200, "raw", ""},
		{"ok_content_type_unparseable", 200, "raw", "not a media type; ;"},
		// The rule's own edges, and why it is stated rather than delegated. A malformed
		// PARAMETER cannot discard a good media type — the parameters are the part this
		// is defined to ignore — and a bare token with no slash is not a media type.
		{"ok_content_type_malformed_parameter", 200, "raw", "text/plain; ;"},
		{"ok_content_type_empty_parameter_section", 200, "raw", "text/plain;"},
		{"ok_content_type_space_before_parameters", 200, "raw", "text/plain ; charset=utf-8"},
		{"ok_content_type_no_slash", 200, "raw", "text"},
		{"ok_content_type_subtype_with_suffix", 200, "raw", "image/svg+xml"},

		// A refusal carrying a token the SDK is willing to repeat.
		{"refused_with_token", 403, `{"error":"denied","reason":"url_expired"}`, "application/json"},
		{"refused_token_with_digits", 403, `{"error":"denied","reason":"agent_key_mismatch2"}`, "application/json"},

		// A refusal whose "reason" is not a token. The body is the publisher's; prose,
		// an uppercase value, a leading digit and a wrong JSON type all fall back to the
		// class rather than rendering as though the SDK had said them.
		{"refused_prose_reason", 403, `{"reason":"Access denied by our WAF. Contact support."}`, "application/json"},
		{"refused_uppercase_reason", 403, `{"reason":"URL_EXPIRED"}`, "application/json"},
		{"refused_leading_digit_reason", 403, `{"reason":"4xx"}`, "application/json"},
		{"refused_reason_not_a_string", 403, `{"reason":42}`, "application/json"},
		{"refused_no_reason_member", 403, `{"error":"denied"}`, "application/json"},
		{"refused_body_not_json", 403, "<html>403</html>", "text/html"},
		{"refused_empty_body", 401, "", ""},

		// A server fault is still the edge saying no: it answered.
		{"refused_server_error", 500, `{"reason":"internal"}`, "application/json"},
	}
}

// TestGenerateContentFetchVectors emits the content-leg golden corpus.
func TestGenerateContentFetchVectors(t *testing.T) {
	path := filepath.Join("testdata", "content-fetch-vectors.json")
	doc := map[string]any{
		"note": "Delivery answers and what a client must read out of them, derived by " +
			"driving the real ContentFetcher. `reason` is the edge's own token, repeated " +
			"only when it is token-shaped; `reason_of` is what a caller branches on.",
		"vectors": buildContentFetchVectors(t),
	}
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(path, doc); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	stale, err := vectorio.Stale(path, doc)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate", path)
	}
}

func buildContentFetchVectors(t *testing.T) []contentFetchVector {
	t.Helper()
	// The guard is stood down for the emitter alone: httptest binds loopback, which the
	// dial guard refuses by design, and what is under test here is the READING of an
	// answer rather than which addresses may be dialled. The address rule has its own
	// corpus next door. Set before the fetcher is built, because the transport reads the
	// flags at construction.
	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "true")
	out := make([]contentFetchVector, 0, len(contentFetchCases()))
	for _, c := range contentFetchCases() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if c.contentType != "" {
				w.Header().Set("Content-Type", c.contentType)
			} else {
				// Suppressed rather than merely unset: net/http sniffs a type from the
				// first bytes when the handler names none, which would make the
				// no-header case record a header after all.
				w.Header()["Content-Type"] = nil
			}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		fetcher := NewContentFetcher(ContentFetchOptions{})
		content, err := fetcher.Fetch(context.Background(), srv.URL+"/asset", stubProofSigner{})
		srv.Close()

		vector := contentFetchVector{
			Name: c.name, Status: c.status, Body: c.body, ContentType: c.contentType,
		}
		if err == nil {
			vector.OK = true
			vector.MIMEType = content.MIMEType
		} else {
			var ferr *FetchError
			if !errors.As(err, &ferr) {
				t.Fatalf("%s: fetch failed with an untyped error: %v", c.name, err)
			}
			vector.Failure = ferr.Failure.String()
			vector.Reason = ferr.Reason
			vector.ReasonOf = ferr.ReasonOf()
		}
		if vector.OK {
			vector.ReasonOf = ""
		}
		out = append(out, vector)
	}
	return out
}

// stubProofSigner mints a fixed binding. What the proof CONTAINS is pinned by
// pop-vectors.json; here it only has to exist, so the reading of the answer is what the
// vectors record.
type stubProofSigner struct{}

func (stubProofSigner) SignFetch(context.Context, string) (helpers.AgentBinding, error) {
	return helpers.AgentBinding{
		AgentKey:       "stub-agent-key",
		SignatureInput: `sig1=("@method" "@target-uri");keyid="stub";alg="ed25519";created=1;expires=2`,
		Signature:      "sig1=:c3R1Yg==:",
	}, nil
}
