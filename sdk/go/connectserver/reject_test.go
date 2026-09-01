package connectserver_test

// The exported reject writer. These tests exist because the classification has a
// SECOND consumer: a mount whose gate carries its own resource-limit sentinel calls
// RejectCode and WriteReject rather than re-deriving the 413/429/401 split. That is
// only worth doing if the exported functions are the same ones this package's own
// handlers answer with, so the first test compares the two byte for byte.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	connectrpc "connectrpc.com/connect"

	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestWriteReject_MountAnswerIsTheExportedWriterAnswer is the load-bearing one. A
// consumer delegating to WriteReject gets the mount's answer only if WriteReject IS
// what the mount calls; a second writer that merely agrees today is the drift this
// export exists to remove. Driven end to end through a real mount rather than
// through the writer twice, so a change to either side breaks it.
func TestWriteReject_MountAnswerIsTheExportedWriterAnswer(t *testing.T) {
	t.Parallel()
	const capBytes = 64 << 10
	srv := mountCatalog(t, &catalogEcho{}, rampserver.WithMaxRequestBytes(capBytes))

	resp := postRaw(t, srv.URL+"/ramp.v1.CatalogService/PushResources", oversizeJSON(capBytes*2))
	mountBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read mount body: %v", err)
	}

	// The error the mount refused with: MaxBytesHandler caps the body, so the
	// buffering ReadAll fails with exactly this, unwrapped.
	overCap := &http.MaxBytesError{Limit: capBytes}
	rec := httptest.NewRecorder()
	rampserver.WriteReject(rec, rampserver.RejectCode(overCap), overCap)

	if rec.Code != resp.StatusCode {
		t.Errorf("status: writer = %d, mount = %d — the mount answers from a different writer",
			rec.Code, resp.StatusCode)
	}
	if got, want := rec.Header().Get("Content-Type"), resp.Header.Get("Content-Type"); got != want {
		t.Errorf("content-type: writer = %q, mount = %q", got, want)
	}
	if got := rec.Body.String(); got != string(mountBody) {
		t.Errorf("body: writer = %s, mount = %s", got, mountBody)
	}
}

func TestRejectCode_ClassifiesEachRejectionClass(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want connectrpc.Code
	}{
		{"over-cap body", &http.MaxBytesError{Limit: 1}, connectrpc.CodeResourceExhausted},
		{"over-cap body wrapped", fmt.Errorf("read: %w", &http.MaxBytesError{Limit: 1}), connectrpc.CodeResourceExhausted},
		{"hop budget", helpers.ErrTooManyHops, connectrpc.CodeResourceExhausted},
		{"hop budget wrapped", fmt.Errorf("gate: %w", helpers.ErrTooManyHops), connectrpc.CodeResourceExhausted},
		{"replay", rampserver.ErrReplayed, connectrpc.CodeUnauthenticated},
		{"broken chain", helpers.ErrBrokenSignatureChain, connectrpc.CodeUnauthenticated},
		{"broken chain wrapped", fmt.Errorf("verify: %w", helpers.ErrBrokenSignatureChain), connectrpc.CodeUnauthenticated},
		{"unclassified", errors.New("bad signature"), connectrpc.CodeUnauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rampserver.RejectCode(tc.err); got != tc.want {
				t.Errorf("RejectCode(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestWriteReject_StatusAgreesWithTheCodeItIsGiven pins the split, including the
// case the exported form makes reachable for the first time: a caller supplying a
// code that is not a resource limit. Answering 413 there would contradict the body,
// which names the code the caller passed.
func TestWriteReject_StatusAgreesWithTheCodeItIsGiven(t *testing.T) {
	t.Parallel()
	overCap := &http.MaxBytesError{Limit: 1}
	cases := []struct {
		name string
		code connectrpc.Code
		err  error
		want int
	}{
		{"over cap is 413", connectrpc.CodeResourceExhausted, overCap, http.StatusRequestEntityTooLarge},
		{"hop budget is 429", connectrpc.CodeResourceExhausted, helpers.ErrTooManyHops, http.StatusTooManyRequests},
		{"signature is 401", connectrpc.CodeUnauthenticated, errors.New("bad signature"), http.StatusUnauthorized},
		{"over cap called unauthenticated is 401", connectrpc.CodeUnauthenticated, overCap, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rampserver.WriteReject(rec, tc.code, tc.err)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not the Connect error envelope: %v", err)
			}
			if body["code"] != tc.code.String() {
				t.Errorf("body code = %q, want %q — the status and the body must name one verdict",
					body["code"], tc.code.String())
			}
		})
	}
}

// TestWriteReject_NeverAnswersSuccess holds the one property no caller may break now
// that the code is theirs to choose: this writes a REFUSAL, whatever it is handed.
func TestWriteReject_NeverAnswersSuccess(t *testing.T) {
	t.Parallel()
	for code := connectrpc.Code(0); code <= connectrpc.Code(20); code++ {
		rec := httptest.NewRecorder()
		rampserver.WriteReject(rec, code, errors.New("refused"))
		if rec.Code < 400 {
			t.Errorf("code %v answered %d — a reject writer must never answer success", code, rec.Code)
		}
	}
}

// TestWriteReject_BodyCarriesOnlyCodeAndMessage pins the response shape now that it
// is a public contract. The message is the error's own text, so a caller learns what
// it publishes by rejecting with a wrapped internal error; nothing else leaves.
func TestWriteReject_BodyCarriesOnlyCodeAndMessage(t *testing.T) {
	t.Parallel()
	err := errors.New("signature verification failed")
	rec := httptest.NewRecorder()
	rampserver.WriteReject(rec, connectrpc.CodeUnauthenticated, err)

	var body map[string]any
	if uerr := json.Unmarshal(rec.Body.Bytes(), &body); uerr != nil {
		t.Fatalf("unmarshal body: %v", uerr)
	}
	if len(body) != 2 || body["code"] == nil || body["message"] == nil {
		t.Errorf("body carries %v, want exactly the keys code and message", body)
	}
	if body["message"] != err.Error() {
		t.Errorf("message = %v, want the error's own text %q", body["message"], err.Error())
	}
	if got := len(rec.Header()); got != 1 || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("writer set headers %v, want only Content-Type: application/json", rec.Header())
	}
}

func TestIsBodyTooLarge_MatchesTheStdlibSignalOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"stdlib signal", &http.MaxBytesError{Limit: 1}, true},
		{"stdlib signal wrapped", fmt.Errorf("read: %w", &http.MaxBytesError{Limit: 1}), true},
		// A predicate that matched on text would accept this, and a caller reading
		// an over-cap verdict off a peer's error string is exactly the drift the
		// exported predicate exists to prevent.
		{"same text, not the signal", errors.New("http: request body too large"), false},
		{"another resource limit", helpers.ErrTooManyHops, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rampserver.IsBodyTooLarge(tc.err); got != tc.want {
				t.Errorf("IsBodyTooLarge(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
