package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// signWindow is the freshness TTL stamped on an outbound signature's
// created/expires pair by the DEFAULT window. The verifier enforces the window
// against its own clock; a generous default keeps a slow round-trip inside it
// while still bounding replay. Callers with their own freshness policy inject
// a window via WithWindow (see ClockWindow / MonotonicWindow).
const signWindow = 5 * time.Minute

// signingTransport is the client SIGN face realized as an http.RoundTripper —
// NOT a connect.Interceptor. RFC 9421 Content-Digest is computed over the EXACT
// marshaled body bytes, which a connect unary interceptor never sees (it holds
// the proto message, not the serialized payload). So signing MUST happen at the
// HTTP seam, after Connect has marshaled the request. This is the single correct
// place to sign; realizing sign as a connect.Interceptor would produce a wrong or
// absent Content-Digest and break interop with every verifier: the
// signing seam is the RoundTripper, not an interceptor.
type signingTransport struct {
	base   http.RoundTripper
	signer helpers.Signer
	// window supplies the per-request (created, expires) freshness cutoffs.
	// One field, one clock: the default reads time.Now once and adds
	// signWindow; WithWindow replaces the whole pair source.
	window Window
	// directory is the signer's own directory origin, stamped into the covered
	// Signature-Agent header set-if-absent (WithSignatureAgent). Empty = no
	// stamping; helpers still bind the header (empty value) into the covered
	// set at sign time.
	directory string
	// appendOnly selects the always-append signing branch (WithAppendSigner).
	appendOnly bool
	// predicate gates which requests are signed (WithSignPredicate). The
	// default signs every bodied request — the pre-option compat contract.
	predicate func(*http.Request) bool
}

// SigningOption customizes the signing transport built by NewSigningTransport.
type SigningOption func(*signingTransport)

// WithWindow replaces the default freshness window (time.Now + 5 minutes) with
// a caller-supplied source of the RFC 9421 (created, expires) pair. Use
// ClockWindow for a plain wall-clock TTL and MonotonicWindow for the relay
// path's replay-store uniqueness requirement.
func WithWindow(w Window) SigningOption {
	return func(t *signingTransport) { t.window = w }
}

// WithAppendSigner routes EVERY signed request through helpers.AppendSignature
// instead of the default split (fresh sig1 via helpers.SignRequest, chained
// sigN+1 via helpers.AppendSignature when an incoming Signature is present).
// This is the relay caller's mode: AppendSignature degrades to a plain sig1
// when no incoming signature is present and appends a forwarding-chain-linked
// sigN+1 when one is, so a single always-append branch serves both the
// broker-originated and the relayed call. Pair it with MonotonicWindow so
// identical back-to-back relay requests do not collide in the server's replay
// store.
func WithAppendSigner() SigningOption {
	return func(t *signingTransport) { t.appendOnly = true }
}

// WithSignatureAgent stamps the covered Signature-Agent header with dir — the
// signer's own directory origin — when, and only when, the request does not
// already carry one. The option supplies the covered VALUE; the sign helpers
// still bind-if-absent to the empty string for the no-directory bootstrap
// path. The set-if-absent guard is load-bearing on the relay path: the
// originating agent already set Signature-Agent to ITS directory and its sig1
// covers that value, so overwriting it would break sig1 at the verifier.
func WithSignatureAgent(dir string) SigningOption {
	return func(t *signingTransport) { t.directory = dir }
}

// WithSignPredicate gates signing on fn: only requests for which fn returns
// true are signed; everything else passes through unmodified. The default (no
// predicate) signs every bodied request — the behavior existing callers rely
// on. A RAMP application that shares one *http.Client across RAMP and non-RAMP
// traffic typically passes a procedure-namespace predicate such as
//
//	core.WithSignPredicate(func(r *http.Request) bool {
//		return strings.HasPrefix(r.URL.Path, "/ramp.")
//	})
//
// mirroring the /ramp. procedure boundary the server-side verify seam already
// enforces.
func WithSignPredicate(fn func(*http.Request) bool) SigningOption {
	return func(t *signingTransport) { t.predicate = fn }
}

// NewSigningTransport returns the client sign-face RoundTripper: it buffers each
// outbound request body, stamps Content-Digest, binds Authorization, and writes
// the RFC 9421 Signature-Input / Signature headers via the injected Signer, then
// forwards to base. A request already carrying a Signature header is CHAINED onto
// (helpers.AppendSignature, the forwarding chain) rather than replaced.
// base defaults to http.DefaultTransport when nil. It is exported so an
// application can compose the SDK sign face onto its own *http.Client (e.g. to
// wrap it in a tracing or metrics RoundTripper). Options tune transport
// behavior — freshness window, relay append mode, Signature-Agent stamping,
// and the sign predicate; with zero options the transport behaves exactly as
// it did before options existed (sign every bodied request, time.Now + 5m).
func NewSigningTransport(signer helpers.Signer, base http.RoundTripper, opts ...SigningOption) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	t := &signingTransport{
		base:   base,
		signer: signer,
		window: ClockWindow(time.Now, signWindow),
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// RoundTrip signs req (or chains a co-signature onto an already-signed req) and
// forwards it to the base transport. A request with no body passes through
// unsigned — there is nothing to bind a Content-Digest to — as does any request
// the sign predicate excludes.
func (t *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.signer == nil || req.Body == nil || (t.predicate != nil && !t.predicate(req)) {
		return t.base.RoundTrip(req)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))
	if req.Host == "" && req.URL != nil {
		req.Host = req.URL.Host
	}
	if t.directory != "" && req.Header.Get(helpers.SignatureAgentHeader) == "" {
		req.Header.Set(helpers.SignatureAgentHeader, t.directory)
	}
	if err := t.sign(req.Context(), req, body); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// sign selects the single-sig or chain branch and stamps the freshness window.
// The appendOnly branch (WithAppendSigner) always chains: AppendSignature
// degrades to a fresh sig1 when no incoming signature is present.
func (t *signingTransport) sign(ctx context.Context, req *http.Request, body []byte) error {
	created, expires := t.window()
	opts := helpers.SignOptions{Created: created, Expires: expires}
	if t.appendOnly || req.Header.Get("Signature") != "" {
		return helpers.AppendSignature(ctx, req, body, t.signer, opts)
	}
	return helpers.SignRequest(ctx, req, body, t.signer, opts)
}
