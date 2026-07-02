package ramp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// signWindow is the freshness TTL stamped on an outbound signature's
// created/expires pair. The verifier enforces the window against its own clock;
// a generous default keeps a slow round-trip inside it while still bounding
// replay.
const signWindow = 5 * time.Minute

// signingTransport is the client SIGN face realized as an http.RoundTripper —
// NOT a connect.Interceptor. RFC 9421 Content-Digest is computed over the EXACT
// marshaled body bytes, which a connect unary interceptor never sees (it holds
// the proto message, not the serialized payload). So signing MUST happen at the
// HTTP seam, after Connect has marshaled the request. This is the single correct
// place to sign; realizing sign as a connect.Interceptor would produce a wrong or
// absent Content-Digest and break interop with every verifier (ADR-020 §2, the
// sign-as-RoundTripper decision).
type signingTransport struct {
	base   http.RoundTripper
	signer helpers.Signer
	now    func() time.Time
}

// NewSigningTransport returns the client sign-face RoundTripper: it buffers each
// outbound request body, stamps Content-Digest, binds Authorization, and writes
// the RFC 9421 Signature-Input / Signature headers via the injected Signer, then
// forwards to base. A request already carrying a Signature header is CHAINED onto
// (helpers.AppendSignature, the RAMP-56 forwarding chain) rather than replaced.
// base defaults to http.DefaultTransport when nil. It is exported so an
// application can compose the SDK sign face onto its own *http.Client (e.g. to
// wrap it in a tracing or metrics RoundTripper).
func NewSigningTransport(signer helpers.Signer, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &signingTransport{base: base, signer: signer, now: time.Now}
}

// RoundTrip signs req (or chains a co-signature onto an already-signed req) and
// forwards it to the base transport. A request with no body passes through
// unsigned — there is nothing to bind a Content-Digest to.
func (t *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.signer == nil || req.Body == nil {
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
	if err := t.sign(req.Context(), req, body); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// sign selects the single-sig or chain branch and stamps the freshness window.
func (t *signingTransport) sign(ctx context.Context, req *http.Request, body []byte) error {
	now := t.now()
	opts := helpers.SignOptions{Created: now.Unix(), Expires: now.Add(signWindow).Unix()}
	if req.Header.Get("Signature") != "" {
		return helpers.AppendSignature(ctx, req, body, t.signer, opts)
	}
	return helpers.SignRequest(ctx, req, body, t.signer, opts)
}
