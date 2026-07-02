package connectserver

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// errReplayed is the verify-face sentinel for a nonce the injected ReplayStore
// reports as already seen. It maps to CodeUnauthenticated like any other
// verification failure.
var errReplayed = errors.New("connectserver: request replayed within window")

// verifyMiddleware is the server SIGN-VERIFY face realized as an http.Handler
// wrapper — NOT a connect.Interceptor. Like the client sign face, it must run at
// the HTTP seam because RFC 9421 verification is over the EXACT request body bytes,
// which a connect interceptor never sees (it holds the decoded proto message). It
// buffers the body, runs helpers.VerifyMultisigRequestResolved with the injected
// KeyResolver (single-sig is the N=1 case), then orchestrates the replay check over
// the injected ReplayStore. A rejected request never reaches next — the origin
// handler's side effects are absent on the negative path (fail-closed).
func verifyMiddleware(cfg serverConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isRampProcedure(r) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := bufferBody(r)
		if err != nil {
			writeReject(w, err)
			return
		}
		if err := cfg.verify(r, body); err != nil {
			writeReject(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// verify runs signature verification then the replay check. Verification uses the
// multisig resolver path so a relay chain and a single signature share one gate;
// the hop budget is the injected maxSignatures. The replay nonce is the request's
// Content-Digest — stable across an idempotency-key replay (identical body bytes)
// yet distinct per distinct request — so reusing an idempotency key trips the store.
func (cfg serverConfig) verify(r *http.Request, body []byte) error {
	opts := helpers.VerifyOptions{MaxSignatures: cfg.maxSignatures}
	sigs, err := helpers.VerifyMultisigRequestResolved(r.Context(), r, body, cfg.resolver, opts)
	if err != nil {
		return err
	}
	if cfg.replay == nil || len(sigs) == 0 {
		return nil
	}
	nonce := r.Header.Get("Content-Digest")
	seen, rerr := cfg.replay.SeenOrAdd(r.Context(), nonce, cfg.replayTTL)
	if rerr != nil {
		return rerr
	}
	if seen {
		return errReplayed
	}
	return nil
}

// bufferBody reads the request body and re-seats it so the downstream handler
// (and Connect's own decode) reads the same bytes verification checked.
func bufferBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// isRampProcedure reports whether r targets a ramp.v1 Connect procedure — the
// signed surface. Health checks and well-known endpoints are intentionally left
// unsigned and pass through unverified.
func isRampProcedure(r *http.Request) bool {
	return r.URL != nil && strings.HasPrefix(r.URL.Path, "/ramp.")
}
