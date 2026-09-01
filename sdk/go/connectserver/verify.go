package connectserver

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// ErrReplayed is the verify-face sentinel for a nonce the injected ReplayStore
// reports as already seen. It maps to CodeUnauthenticated like any other
// verification failure. Exported so a WithOnReject observer can classify a
// replay rejection distinctly from a signature or chain failure (the reject
// error is otherwise opaque to the consumer).
var ErrReplayed = errors.New("connectserver: request replayed within window")

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
		if !isRampProcedure(r) || (cfg.verifyGate != nil && !cfg.verifyGate(r)) {
			// The default gates every /ramp. procedure (fail-closed). An injected
			// WithVerifyGate can narrow the seam — e.g. to signature-presenting
			// requests only, for a service whose handlers own the typed
			// Unauthenticated fault for unsigned callers. A declined request
			// flows to the origin handler UNVERIFIED (helpers.FromContext is nil
			// there); the gate never widens the seam past /ramp. procedures.
			next.ServeHTTP(w, r)
			return
		}
		body, err := bufferBody(r)
		if err != nil {
			cfg.reject(w, r, err)
			return
		}
		sigs, err := cfg.verify(r, body)
		if err != nil {
			cfg.reject(w, r, err)
			return
		}
		// Expose the proven signatures to the handler: downstream authz reads
		// them via helpers.FromContext / helpers.AllSignaturesFromContext.
		next.ServeHTTP(w, r.WithContext(helpers.NewMultisigContext(r.Context(), sigs)))
	})
}

// reject writes the Connect-compatible rejection response and, if the app
// injected WithOnReject, hands it the request + the rejection error FIRST so the
// consumer can audit-classify it (via errors.Is against ErrTooManyHops /
// ErrReplayed / helpers.ErrBrokenSignatureChain). The observer runs before the
// response is written and must not write to w; a rejected request never reaches
// the origin handler either way (fail-closed).
func (cfg serverConfig) reject(w http.ResponseWriter, r *http.Request, err error) {
	if cfg.onReject != nil {
		cfg.onReject(r, err)
	}
	WriteReject(w, RejectCode(err), err)
}

// verify runs signature verification then the replay check, returning the
// verified signatures (sig1..sigN) for the middleware to place into the request
// context. Verification uses the multisig resolver path so a relay chain and a
// single signature share one gate; the hop budget is the injected maxSignatures.
//
// The replay nonce is PER VERIFIED SIGNATURE — keyid plus the signature bytes —
// never the body digest: an idempotent retry re-signs the same body with a
// fresh window and must pass the transport gate (the handler dedups per
// verified signer via idempotency_key and returns the original result), while
// replaying the exact signed bytes trips the store. The check is two-phase —
// read-only Seen over every signature, then SeenOrAdd commits them all — so a
// request rejected part-way never burns its other signatures' nonces.
func (cfg serverConfig) verify(r *http.Request, body []byte) ([]helpers.VerifiedRequest, error) {
	opts := helpers.VerifyOptions{MaxSignatures: cfg.maxSignatures, MaxSignatureAge: cfg.maxSignatureAge}
	sigs, err := helpers.VerifyMultisigRequestResolved(r.Context(), r, body, cfg.resolver, opts)
	if err != nil {
		return nil, err
	}
	if cfg.replay == nil || len(sigs) == 0 {
		return sigs, nil
	}
	for i := range sigs {
		seen, rerr := cfg.replay.Seen(r.Context(), replayNonce(&sigs[i]))
		if rerr != nil {
			return nil, rerr
		}
		if seen {
			return nil, ErrReplayed
		}
	}
	for i := range sigs {
		seen, rerr := cfg.replay.SeenOrAdd(r.Context(), replayNonce(&sigs[i]), cfg.replayTTL)
		if rerr != nil {
			return nil, rerr
		}
		if seen {
			// A concurrent duplicate raced between the phases.
			return nil, ErrReplayed
		}
	}
	return sigs, nil
}

// replayNonce derives a signature's replay-store key: the resolved keyid and
// the signature bytes, NUL-separated so neither part can forge a boundary.
func replayNonce(v *helpers.VerifiedRequest) string {
	return v.KeyID + "\x00" + v.Signature
}

// bufferBody reads the request body and re-seats it so the downstream handler
// (and Connect's own decode) reads the same bytes verification checked.
//
// The read is unbounded HERE by design and bounded one layer out: the handler
// composes http.MaxBytesHandler outside this face, so r.Body is already capped
// when it arrives and a body past the cap fails this ReadAll with
// http.MaxBytesError rather than being buffered whole.
//
// Outside rather than here, because where the bound sits decides what a refusal
// carries. MaxBytesHandler is composed inside request-id, so an over-cap body is
// refused with the X-Request-ID already stamped and the reject-path logs can be
// read; a bound applied in this function would refuse after request-id had been
// passed but from a face that answers on its own, and the correlation the ordering
// exists to give would be lost. The cap also belongs to the handler's
// configuration — one value, set once by WithMaxRequestBytes and shared with
// Connect's own decoded-message bound — not to a middleware that has no access to
// it.
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

// isRampProcedure reports whether r targets a RAMP Connect procedure — the signed
// surface. Health checks and well-known endpoints are intentionally left unsigned and
// pass through unverified.
//
// The prefix spans EVERY ramp.* package, so it also matches the operator plane
// (/ramp.admin.v1.AdminService/...). That plane carries no RFC 9421 request signing by
// design, and this gate is fail-closed — it denies any caller it cannot verify. Since an
// admin request presents no signature, every admin call reaching this middleware is
// rejected as unsigned (this is not an authz decision — the gate has no signer to verify).
// Mount the generated rampadminv1connect handler directly, on its own internal listener,
// never behind this seam (nor on a mux this middleware fronts). The SDK exports no
// AdminService handler for exactly that reason.
func isRampProcedure(r *http.Request) bool {
	return r.URL != nil && strings.HasPrefix(r.URL.Path, "/ramp.")
}
