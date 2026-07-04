package connectserver_test

// Contract tests for two verify-face semantics the platform pins (each was a
// platform-integration regression before being encoded here):
//
//  1. GATE PREDICATE — a /ramp. request that carries NO Signature-Input is not
//     seam-rejected: it reaches the origin handler, which owns the typed
//     Unauthenticated fault (the ADR-019 ErrorDetail contract). Only a request
//     that presents a signature is verified at the seam.
//
//  2. REPLAY NONCE — the replay guard keys on the SIGNATURE (per verified
//     signature: keyid + signature bytes), never on the body digest. An
//     idempotent retry re-signs the same body with a fresh created window and
//     MUST pass the transport gate (the handler dedups per verified signer via
//     idempotency_key and returns the original result); replaying the exact
//     signed bytes MUST still be rejected.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

const discoverProcedure = "/ramp.v1.ExchangeService/DiscoverResources"

// signedDiscover builds a signed POST to the Discover procedure over body with
// the given created/expires window.
func signedDiscover(t *testing.T, srvURL string, f serverFixture, body []byte, created, expires int64) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srvURL+discoverProcedure, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := helpers.SignRequest(context.Background(), req, body, f.signer, helpers.SignOptions{Created: created, Expires: expires}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return req
}

func discoverBody(t *testing.T) []byte {
	t.Helper()
	raw, err := protojson.Marshal(&rampv1.ResourceQuery{Ver: "1.0"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestServerVerify_UnsignedRequestReachesHandler pins the gate predicate: an
// unsigned /ramp. request is NOT rejected at the seam — it reaches the origin,
// which owns the typed Unauthenticated fault and rejects before acting. The
// seam verifies only requests that present a Signature-Input. The origin's
// marker in the error body proves the rejection came from the handler, not the
// seam's reject writer; the absence of business side effects (hits) proves
// fail-closed held.
func TestServerVerify_UnsignedRequestReachesHandler(t *testing.T) {
	f := newServerFixture(t)
	srv := f.serve(t, newCountingReplayStore())
	defer srv.Close()

	body := discoverBody(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+discoverProcedure, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned request: status %d, want 401 (typed handler fault)", resp.StatusCode)
	}
	if !bytes.Contains(respBody, []byte("origin: unverified caller")) {
		t.Errorf("rejection must come from the ORIGIN handler (typed-fault contract), not the seam; body = %s", respBody)
	}
	if f.origin.hitCount() != 0 {
		t.Errorf("origin business side effects must be absent on the unauthenticated path; hits = %d", f.origin.hitCount())
	}
}

// TestServerVerify_ResignedIdempotentRetryPasses pins the replay-nonce
// semantics: the same body re-signed with a fresh window is a NEW signature and
// must pass the gate; replaying the exact signed bytes must be rejected.
func TestServerVerify_ResignedIdempotentRetryPasses(t *testing.T) {
	f := newServerFixture(t)
	store := newCountingReplayStore()
	srv := f.serve(t, store)
	defer srv.Close()

	body := discoverBody(t)
	now := time.Now().Unix()

	// First attempt.
	resp1, err := srv.Client().Do(signedDiscover(t, srv.URL, f, body, now, now+60))
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first signed request: status %d, want 200", resp1.StatusCode)
	}

	// Idempotent retry: SAME body, FRESH window → new signature bytes. Must pass.
	resp2, err := srv.Client().Do(signedDiscover(t, srv.URL, f, body, now+1, now+61))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("re-signed idempotent retry must pass the transport gate (handler owns dedup); status %d, want 200", resp2.StatusCode)
	}

	// Exact replay of the first signed request: same signature bytes → rejected.
	replayReq := signedDiscover(t, srv.URL, f, body, now, now+60)
	resp3, err := srv.Client().Do(replayReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("exact signature replay must be rejected; status %d, want 401", resp3.StatusCode)
	}
}
