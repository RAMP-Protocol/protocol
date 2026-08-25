package resolvers

// Go replay of the content-leg corpus (content-fetch-vectors.json).
//
// The corpus is the cross-language contract for reading a delivery answer, so Go replays
// it too rather than only emitting it — a corpus its own oracle does not consume proves
// nothing about the oracle.
//
// The emitter and the replay are deliberately not the same code path: the emitter records
// what the fetcher DID, and this asserts the committed record still describes it. That is
// what makes the file a contract rather than a snapshot — a change to the classification,
// the token rule or the media-type reduction fails here with the case named, before the
// Python and TypeScript replays see it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestContentFetchCorpusReplay(t *testing.T) {
	path := filepath.Join("testdata", "content-fetch-vectors.json")
	raw, err := os.ReadFile(path) //nolint:gosec // a committed test vector this package owns
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Vectors     []contentFetchVector `json:"vectors"`
		URLRefusals []urlRefusalVector   `json:"url_refusals"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", path)
	}
	if len(doc.URLRefusals) == 0 {
		t.Fatalf("%s carries no url_refusals — the replay would assert nothing", path)
	}

	// The URL refusals FIRST, with both guards UP: the scheme gate is what refuses a
	// plaintext or non-http delivery URL, and the reading vectors below stand it down to
	// reach a loopback server. Nothing here dials.
	t.Run("url_refusals", func(t *testing.T) {
		t.Setenv("SKIP_SSRF", "")
		t.Setenv("ALLOW_INSECURE", "")
		fetcher := NewContentFetcher(ContentFetchOptions{})
		for _, v := range doc.URLRefusals {
			t.Run(v.Name, func(t *testing.T) {
				_, err := fetcher.Fetch(context.Background(), v.URL, stubProofSigner{})
				var ferr *FetchError
				if !errors.As(err, &ferr) {
					t.Fatalf("want a typed FetchError, got %v", err)
				}
				// The split the corpus exists to hold: a fault in the VALUE is malformed
				// and permanent, a refusal of the DIAL is unreachable and may not be.
				if got := ferr.Failure.String(); got != v.Failure {
					t.Errorf("failure = %q, want %q", got, v.Failure)
				}
				if got := ferr.ReasonOf(); got != v.ReasonOf {
					t.Errorf("reason_of = %q, want %q", got, v.ReasonOf)
				}
			})
		}
	})

	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "true")
	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if v.ContentType != "" {
					w.Header().Set("Content-Type", v.ContentType)
				} else {
					w.Header()["Content-Type"] = nil
				}
				w.WriteHeader(v.Status)
				_, _ = w.Write([]byte(v.Body))
			}))
			defer srv.Close()

			content, err := NewContentFetcher(ContentFetchOptions{}).
				Fetch(context.Background(), srv.URL+"/asset", stubProofSigner{})
			if v.OK {
				if err != nil {
					t.Fatalf("fetch failed for a vector recorded as OK: %v", err)
				}
				if content.MIMEType != v.MIMEType {
					t.Errorf("mime type = %q, want %q", content.MIMEType, v.MIMEType)
				}
				return
			}
			var ferr *FetchError
			if !errors.As(err, &ferr) {
				t.Fatalf("want a typed FetchError, got %v", err)
			}
			if got := ferr.Failure.String(); got != v.Failure {
				t.Errorf("failure = %q, want %q", got, v.Failure)
			}
			if ferr.Reason != v.Reason {
				t.Errorf("reason = %q, want %q", ferr.Reason, v.Reason)
			}
			if got := ferr.ReasonOf(); got != v.ReasonOf {
				t.Errorf("reason_of = %q, want %q", got, v.ReasonOf)
			}
		})
	}
}
