package resolvers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// The content leg, driven through its public surface against a real HTTP server.
// The server verifies the proof the way the edge does — rebuilding the signature
// base from the raw request line and the Signature-Input as received — so these
// tests assert the wire contract rather than the SDK agreeing with itself.

// popSigner is the application-supplied ProofSigner seam. The SDK never holds a
// key; this is the caller composing one.
type popSigner struct {
	signer  helpers.Signer
	pub     ed25519.PublicKey
	created int64
	expires int64
	err     error
}

func (p popSigner) SignFetch(ctx context.Context, target string) (helpers.AgentBinding, error) {
	if p.err != nil {
		return helpers.AgentBinding{}, p.err
	}
	return helpers.SignAgentBinding(ctx, p.signer, p.pub, helpers.PoPOptions{
		URL: target, Created: p.created, Expires: p.expires,
	})
}

func newPopSigner(t *testing.T) popSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	thumb, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	signer, err := helpers.NewEd25519Signer(thumb, priv)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	now := time.Now().Unix()
	return popSigner{signer: signer, pub: pub, created: now, expires: now + 30}
}

// verifyProofLikeTheEdge reproduces the offline three-way identity check a
// code-capable edge runs: the presented key's thumbprint must equal the keyid on
// the signature, and the signature must verify over a base rebuilt from the raw
// request line.
func verifyProofLikeTheEdge(t *testing.T, r *http.Request) {
	t.Helper()
	presented := r.Header.Get(helpers.AgentKeyHeader)
	if presented == "" {
		t.Error("request carries no agent key header")
		return
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		t.Errorf("agent key is not base64url-no-pad: %v", err)
		return
	}
	sigInput := r.Header.Get("Signature-Input")
	rawParams, ok := strings.CutPrefix(sigInput, "sig1=")
	if !ok {
		t.Errorf("unexpected Signature-Input label: %q", sigInput)
		return
	}
	keyID := betweenQuotes(rawParams, "keyid=")
	thumb, err := helpers.Thumbprint(pubBytes)
	if err != nil {
		t.Errorf("thumbprint presented key: %v", err)
		return
	}
	if keyID != thumb {
		t.Errorf("keyid %q is not the presented key's thumbprint %q", keyID, thumb)
	}
	sigValue := r.Header.Get("Signature")
	encoded := strings.TrimSuffix(strings.TrimPrefix(sigValue, "sig1=:"), ":")
	sig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Errorf("signature is not standard base64: %v", err)
		return
	}
	// The edge rebuilds @target-uri from the raw request line it received.
	target := "http://" + r.Host + r.URL.RequestURI()
	base := `"@method": ` + r.Method + "\n" +
		`"@target-uri": ` + target + "\n" +
		`"@signature-params": ` + rawParams
	if !ed25519.Verify(pubBytes, []byte(base), sig) {
		t.Errorf("proof does not verify over the base the edge reconstructs:\n%s", base)
	}
}

func betweenQuotes(s, key string) string {
	rest, ok := strings.CutPrefix(s[strings.Index(s, key):], key+`"`)
	if !ok {
		return ""
	}
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// plainFetcher builds a fetcher that may reach a loopback httptest server. The
// guard is not removable by option — a caller supplies what sits UNDER it — so a
// test opts out the way a deployment does, through the two documented env flags.
func plainFetcher(t *testing.T, opts resolvers.ContentFetchOptions) *resolvers.ContentFetcher {
	t.Helper()
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")
	return resolvers.NewContentFetcher(opts)
}

func TestContentFetcher_PresentsAVerifiableProof(t *testing.T) {
	signer := newPopSigner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyProofLikeTheEdge(t, r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>licensed</html>"))
	}))
	defer srv.Close()

	got, err := plainFetcher(t, resolvers.ContentFetchOptions{}).
		Fetch(context.Background(), srv.URL+"/doc?agent_id=tp", signer)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(got.Body) != "<html>licensed</html>" {
		t.Errorf("body = %q", got.Body)
	}
	if got.MIMEType != "text/html" {
		t.Errorf("MIMEType = %q, want the media type with parameters stripped", got.MIMEType)
	}
	if got.URL != srv.URL+"/doc?agent_id=tp" {
		t.Errorf("URL = %q, want the fetched URL echoed back", got.URL)
	}
}

func TestContentFetcher_MIMEFallback(t *testing.T) {
	tests := map[string]string{
		"":                 "application/octet-stream",
		"not a media type": "application/octet-stream",
		"application/pdf":  "application/pdf",
	}
	for header, want := range tests {
		t.Run("content-type "+header, func(t *testing.T) {
			signer := newPopSigner(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if header != "" {
					w.Header().Set("Content-Type", header)
				} else {
					// net/http sniffs a type on write unless the header is
					// explicitly suppressed, and an absent Content-Type is the case
					// under test.
					w.Header()["Content-Type"] = nil
				}
				_, _ = w.Write([]byte("bytes"))
			}))
			defer srv.Close()

			got, err := plainFetcher(t, resolvers.ContentFetchOptions{}).
				Fetch(context.Background(), srv.URL+"/doc", signer)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if got.MIMEType != want {
				t.Errorf("MIMEType = %q, want %q", got.MIMEType, want)
			}
		})
	}
}

// A redirect is refused, and the crucial half of the assertion is that the target
// is never contacted: following one would hand a fresh proof of possession of the
// agent's key to whatever host the first hop named.
func TestContentFetcher_RefusesRedirectsAndNeverContactsTheTarget(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("attacker content"))
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()

	_, err := plainFetcher(t, resolvers.ContentFetchOptions{}).
		Fetch(context.Background(), origin.URL+"/doc", newPopSigner(t))
	if err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	var ferr *resolvers.FetchError
	if !errors.As(err, &ferr) || ferr.Failure != resolvers.FetchUnreachable {
		t.Errorf("error = %v, want a FetchUnreachable FetchError", err)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("redirect target was contacted %d times; it must never be reached", n)
	}
}

// A URL that does not survive re-serialization is refused BEFORE anything is
// signed or sent, because the proof covers the verbatim string and a mismatch
// would surface at the edge as an undifferentiated 403.
func TestContentFetcher_RefusesANonRoundTripStableURLWithoutSending(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("never served"))
	}))
	defer srv.Close()

	// A RAW space in the path. The signed-URL contract covers scheme/host/path as
	// opaque bytes, so an Exchange can mint exactly this — but the request line
	// escapes it to %20, so the bytes sent would not be the bytes the proof covers.
	// (A percent-escape does NOT trip this: the URL value preserves the raw path.)
	_, err := plainFetcher(t, resolvers.ContentFetchOptions{}).
		Fetch(context.Background(), srv.URL+"/a b/doc", newPopSigner(t))
	if err == nil {
		t.Fatal("expected the unstable URL to be refused")
	}
	var ferr *resolvers.FetchError
	if !errors.As(err, &ferr) || ferr.Failure != resolvers.FetchMalformed {
		t.Errorf("error = %v, want a FetchMalformed FetchError", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server was contacted %d times; the refusal must be local", n)
	}
}

// The proof is minted after the URL check, so a signer failure means nothing left
// the process.
func TestContentFetcher_UnsignableProofSendsNothing(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	custodyDown := errors.New("custody backend unavailable")
	signer := newPopSigner(t)
	signer.err = custodyDown

	_, err := plainFetcher(t, resolvers.ContentFetchOptions{}).
		Fetch(context.Background(), srv.URL+"/doc", signer)
	var ferr *resolvers.FetchError
	if !errors.As(err, &ferr) || ferr.Failure != resolvers.FetchNotSignable {
		t.Fatalf("error = %v, want a FetchNotSignable FetchError", err)
	}
	if !errors.Is(err, custodyDown) {
		t.Error("the custody cause must stay reachable through errors.Is")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server was contacted %d times; an unsignable fetch must send nothing", n)
	}
}

// An oversized body is DETECTED, not truncated: content that looks whole but is
// not is worse than a refusal, because it has been paid for.
func TestContentFetcher_OversizedBodyIsDetectedNotTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 64))
	}))
	defer srv.Close()

	_, err := plainFetcher(t, resolvers.ContentFetchOptions{MaxBytes: 16}).
		Fetch(context.Background(), srv.URL+"/doc", newPopSigner(t))
	var ferr *resolvers.FetchError
	if !errors.As(err, &ferr) || ferr.Failure != resolvers.FetchTooLarge {
		t.Fatalf("error = %v, want a FetchTooLarge FetchError", err)
	}
}

// A body exactly at the cap is served, so the boundary is inclusive.
func TestContentFetcher_BodyAtTheCapIsServed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 16))
	}))
	defer srv.Close()

	got, err := plainFetcher(t, resolvers.ContentFetchOptions{MaxBytes: 16}).
		Fetch(context.Background(), srv.URL+"/doc", newPopSigner(t))
	if err != nil {
		t.Fatalf("a body exactly at the cap must be served: %v", err)
	}
	if len(got.Body) != 16 {
		t.Errorf("body length = %d, want 16", len(got.Body))
	}
}

func TestContentFetcher_EdgeRefusal(t *testing.T) {
	tests := map[string]struct {
		body       string
		wantReason string
	}{
		"token surfaces":              {`{"error":"forbidden","reason":"pop_expired"}`, "pop_expired"},
		"non token shaped is dropped": {`{"reason":"You are not allowed, friend."}`, ""},
		"absent reason is dropped":    {`{"error":"forbidden"}`, ""},
		"unparseable body is dropped": {`not json at all`, ""},
		"oversized body is dropped":   {`{"reason":"` + strings.Repeat("a", 8192) + `"}`, ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := plainFetcher(t, resolvers.ContentFetchOptions{}).
				Fetch(context.Background(), srv.URL+"/doc", newPopSigner(t))
			var ferr *resolvers.FetchError
			if !errors.As(err, &ferr) || ferr.Failure != resolvers.FetchRefused {
				t.Fatalf("error = %v, want a FetchRefused FetchError", err)
			}
			if ferr.Status != http.StatusForbidden {
				t.Errorf("Status = %d, want 403", ferr.Status)
			}
			if ferr.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", ferr.Reason, tc.wantReason)
			}
			// The class is owned by this SDK and is always available.
			wantFallback := tc.wantReason
			if wantFallback == "" {
				wantFallback = "refused"
			}
			if got := ferr.ReasonOf(); got != wantFallback {
				t.Errorf("ReasonOf() = %q, want %q", got, wantFallback)
			}
		})
	}
}

// No credential may reach a log or an error string: the signed URL carries sig,
// kid, exp and agent_id in its query.
func TestContentFetcher_ErrorsCarryNoCredential(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen?sig=REDIRECTSECRET", http.StatusFound)
	}))
	defer origin.Close()

	_, err := plainFetcher(t, resolvers.ContentFetchOptions{}).
		Fetch(context.Background(), origin.URL+"/doc?sig=ORIGINSECRET&agent_id=tp", newPopSigner(t))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, leak := range []string{"ORIGINSECRET", "REDIRECTSECRET", "sig=", "agent_id="} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error string leaks %q: %s", leak, err)
		}
	}
}
