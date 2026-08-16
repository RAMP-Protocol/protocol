package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/failure"
)

// The content leg: fetching the bytes a signed delivery URL names, presenting the
// agent key that URL is bound to.
//
// It lives in this tier because it DIALS — a retrieval endpoint is chosen by a
// party on the network, not by configuration, which is the exact threat shape
// this package exists to contain. The transport-neutral tiers above stay free of
// any dialing surface.

// DefaultContentTimeout bounds one content fetch. An agent is blocked on the call
// that triggered it, so a fetch that has not answered by now is more useful as a
// reported failure than as a hang.
const DefaultContentTimeout = 30 * time.Second

// DefaultMaxContentBytes caps one fetched body at 8 MiB. This is a memory bound
// on the fetching process, not a judgement about how large licensed content may
// be: the body is buffered whole and held for the life of the call, and a batch
// fetches one per item.
const DefaultMaxContentBytes int64 = 8 << 20

// maxErrorBodyBytes caps how much of a refusal body is read before the edge's
// reason is parsed out of it. The payload is a small JSON object; anything past
// this is not a refusal that can be interpreted.
const maxErrorBodyBytes int64 = 4 << 10

// defaultContentMIMEType is what a body with no usable Content-Type is labelled.
// Guessing from the bytes would be worse: the caller is told what the publisher
// said, and "unknown" is a true answer where a sniffed guess might not be.
const defaultContentMIMEType = "application/octet-stream"

// ProofSigner mints the proof of possession for one bound fetch. It is an
// injected seam so this tier never holds key material: the caller composes it
// over whatever custody it uses, and decides the proof window.
type ProofSigner interface {
	// SignFetch returns the agent binding for a GET of targetURL. The URL is
	// passed verbatim because the proof covers it as an exact string.
	SignFetch(ctx context.Context, targetURL string) (helpers.AgentBinding, error)
}

// ContentFetchOptions configures a ContentFetcher. Every field has a safe default.
type ContentFetchOptions struct {
	// BaseTransport carries the caller's own transport settings — a tuned
	// connection pool, client certificates via TLSClientConfig — UNDERNEATH the
	// SSRF guard. It is never a replacement for the guard: a delivery URL names a
	// host chosen by another party, so the address pin and the https-only scheme
	// check are applied in every case. Nil means a fresh transport under the guard.
	//
	// A custom TLS dialer on this base is dropped rather than honoured: net/http
	// would prefer it over the pinned dialer on https and the address check would
	// never run. Configure TLS through TLSClientConfig, which is kept.
	//
	// The redirect policy is likewise a property of this profile rather than a
	// detail a caller supplies. A caller that could inject a whole client would be
	// asserting against its own policy instead of the one production runs.
	//
	// The only way to reach a private or plaintext endpoint is the deliberate,
	// deployment-level SKIP_SSRF / ALLOW_INSECURE opt-out, which is one decision
	// recorded in one place instead of a per-caller copy of it.
	BaseTransport *http.Transport
	// Timeout bounds one fetch, proof minting included. Defaults to
	// DefaultContentTimeout.
	Timeout time.Duration
	// MaxBytes caps one fetched body. Defaults to DefaultMaxContentBytes.
	MaxBytes int64
	// RequestID mints the value of the X-Request-ID correlation header stamped on
	// each delivery GET. Nil sends no header.
	//
	// It matters on THIS leg in particular. The RPC legs correlate through an
	// interceptor, which a plain GET never traverses, so without a hook here the
	// delivery fetch is the one leg carrying no id — and a delivery edge that mints
	// its own when the header is absent then logs a refusal under an id nothing
	// else knows. That is the leg where delivery failures are diagnosed.
	//
	// A func rather than a string because one fetcher serves many requests, and the
	// point of the header is that each carries its own id. It is `func() string`
	// rather than the transport tier's named RequestIDFunc so this package needs no
	// dependency on that tier for one alias; a named type is assignable here.
	//
	// IT MUST RETURN A VALUE THE ADMIN PLANE CAN PERSIST — 1 to 255 printable ASCII
	// characters. This tier does not check, because the check lives one tier up
	// with the wire rule it comes from. A trace id reused as a correlation id is
	// exactly the value that fails it, and a receiving Exchange replaces what it
	// cannot store, so a bad value here does not error: it silently decorrelates
	// this leg from the RPC legs. Clients built by sdk/go/connect are already safe
	// — their mint comes from core.MintRequestID. Wrap your own the same way.
	RequestID func() string
}

// Content is one fetched resource.
type Content struct {
	// URL is the signed delivery URL that was fetched, echoed back so a caller
	// correlating a batch does not have to keep its own map.
	URL string
	// MIMEType is the media type the edge served, parameters stripped.
	MIMEType string
	// Body is the fetched bytes.
	Body []byte
}

// FetchFailure classifies why a content fetch failed, so a caller can branch on
// the class without reading the message.
type FetchFailure int

const (
	// FetchUnknown is the zero value; it carries no classification.
	FetchUnknown FetchFailure = iota
	// FetchRefused is an edge that answered and said no. Reason carries the
	// edge's own token when it sent one.
	FetchRefused
	// FetchUnreachable is an edge that did not answer: dial failure, timeout, or
	// a refused redirect.
	FetchUnreachable
	// FetchTooLarge is a body past the configured cap. Deliberately distinct from
	// FetchRefused: the edge did nothing wrong and the URL is still good, so the
	// caller can retry with a larger budget.
	FetchTooLarge
	// FetchNotSignable is the proof failing to be produced. No request leaves on
	// this path — a custody backend that hangs lands here too, as a deadline,
	// because the timeout covers proof minting.
	FetchNotSignable
	// FetchMalformed is a delivery URL this client cannot sign faithfully.
	FetchMalformed
)

var fetchFailureNames = map[FetchFailure]string{
	FetchRefused:     "refused",
	FetchUnreachable: "unreachable",
	FetchTooLarge:    "too_large",
	FetchNotSignable: "not_signable",
	FetchMalformed:   "malformed",
}

// String renders the failure class for logging and for the reason a caller sees
// when the edge supplied none.
func (f FetchFailure) String() string { return failure.Name(fetchFailureNames, f) }

// FetchError is this tier's canonical content-fetch error.
//
// Reason exists so the edge's own refusal token survives as a value rather than
// being flattened into a sentence here. Those tokens are the difference between
// "the publisher refused us" and "our own key wiring is broken", and the layer
// that decides how a refusal reads can only tell them apart if the token arrives
// intact.
type FetchError struct {
	Failure FetchFailure
	Op      string
	Status  int    // HTTP status when the edge answered; 0 otherwise
	Reason  string // the edge's refusal token when it sent one
	Err     error
}

func (e *FetchError) Error() string {
	return failure.Render("resolvers", e.Op, e.Failure.String(), e.Status, e.Reason, e.Err)
}

// Unwrap keeps the cause matchable, so a caller can still reach a custody
// sentinel through errors.Is after the failure has been classified here.
func (e *FetchError) Unwrap() error { return e.Err }

// ReasonOf returns the most specific machine-readable reason available: the
// edge's own token when it sent one, otherwise the failure class.
func (e *FetchError) ReasonOf() string { return failure.ReasonOr(e.Reason, e.Failure.String()) }

// ContentFetcher fetches licensed content from a signed delivery URL. Build it
// with NewContentFetcher; it is safe for concurrent use.
type ContentFetcher struct {
	http      *http.Client
	timeout   time.Duration
	maxBytes  int64
	requestID func() string
}

// NewContentFetcher returns a fetcher whose zero-value options are safe defaults:
// the SSRF-guarded transport, a 30-second bound, an 8 MiB body cap, and redirects
// refused.
func NewContentFetcher(opts ContentFetchOptions) *ContentFetcher {
	// The guard is composed here and cannot be handed in already-built: a caller
	// supplies what sits UNDER it, never what replaces it.
	//
	// The redirect policy is this profile's own, which is why the guarded CLIENT
	// is not reused: it follows up to five hops, which is right for a public
	// well-known document and wrong for anything carrying a credential.
	transport := NewGuardedTransport(opts.BaseTransport)
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultContentTimeout
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxContentBytes
	}
	return &ContentFetcher{
		http:      &http.Client{Transport: transport, CheckRedirect: refuseContentRedirect},
		timeout:   timeout,
		maxBytes:  maxBytes,
		requestID: opts.RequestID,
	}
}

// refuseContentRedirect stops the client following any 3xx.
//
// Following one either replays a proof bound to the old URL — which the edge's
// own check rejects — or, if the proof were re-minted per hop, hands a fresh
// proof of possession of the agent's key to whatever host the first hop named.
var refuseContentRedirect = failure.RefuseRedirect(
	"resolvers", "a bound fetch is never redirected", helpers.RedactURL)

// Fetch retrieves the content at signedURL, presenting the proof of possession
// signer mints for it.
func (f *ContentFetcher) Fetch(ctx context.Context, signedURL string, signer ProofSigner) (Content, error) {
	const op = "fetch content"
	if signer == nil {
		return Content{}, &FetchError{Failure: FetchNotSignable, Op: op,
			Err: errors.New("no proof signer supplied")}
	}
	// The deadline is derived BEFORE the request is built, because building it
	// mints a proof — which may call out to a custody backend bounded only by that
	// backend's own client otherwise. A timeout covering the round trip alone
	// would leave "bounds one content fetch" untrue against a degraded custody
	// service, and a batch pays that cost once per item.
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	req, err := f.request(ctx, op, signedURL, signer)
	if err != nil {
		return Content{}, err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return Content{}, &FetchError{Failure: FetchUnreachable, Op: op, Err: redactTransportError(err)}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Content{}, &FetchError{
			Failure: FetchRefused, Op: op, Status: resp.StatusCode, Reason: edgeReason(resp.Body),
		}
	}
	body, err := f.read(resp.Body)
	if err != nil {
		return Content{}, err
	}
	return Content{URL: signedURL, MIMEType: mimeTypeOf(resp.Header.Get("Content-Type")), Body: body}, nil
}

// request builds the signed GET. It is separate from Fetch so the preconditions
// are in one place and no partially-built request can reach the wire.
//
// The round-trip check runs BEFORE the proof is minted, so a URL that cannot be
// sent faithfully never costs a signing operation.
func (f *ContentFetcher) request(ctx context.Context, op, signedURL string, signer ProofSigner) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signedURL, nil)
	if err != nil {
		// The cause is NOT wrapped: a parse failure prints the offending URL, and a
		// delivery URL carries a live credential in its query. Nothing safe can be
		// named either — redaction itself needs a parseable value — so the class is
		// the whole message.
		return nil, &FetchError{
			Failure: FetchMalformed, Op: op,
			Err: errors.New("delivery url is not parseable (value withheld: it carries a live credential)"),
		}
	}
	// The proof covers @target-uri as the VERBATIM string, while the request line
	// carries whatever the URL value re-serializes to. The signed-URL contract
	// treats scheme/host/path as opaque bytes, so an Exchange can legitimately mint
	// a URL those two disagree on — a raw space in the path is the reachable case,
	// since the request line escapes it. The signature then cannot verify and the
	// edge reports only an undifferentiated 403, so refusing here names the cause
	// instead. (A percent-escape does not trip this: the URL value preserves it.)
	if req.URL.String() != signedURL {
		// The given URL is deliberately NOT echoed: this error reaches a log, and
		// the value carries a live credential in its query. The re-serialized form
		// is what an operator compares against what the Exchange minted.
		return nil, &FetchError{
			Failure: FetchMalformed, Op: op,
			Err: fmt.Errorf("url is not round-trip stable: it re-serializes to %s (query redacted)",
				helpers.RedactURL(req.URL.String())),
		}
	}
	// Stamped BEFORE the binding, so the covered headers are written last and
	// nothing here can be mistaken for part of the proof. The correlation id is not
	// covered by the signature and is not meant to be: it identifies the request in
	// two sets of logs, it authorises nothing.
	if f.requestID != nil {
		req.Header.Set(helpers.RequestIDHeader, f.requestID())
	}
	binding, err := signer.SignFetch(ctx, signedURL)
	if err != nil {
		// Wrapped, not replaced: a caller must still be able to reach a custody
		// sentinel underneath through errors.Is.
		return nil, &FetchError{Failure: FetchNotSignable, Op: op, Err: err}
	}
	binding.Apply(req.Header)
	return req, nil
}

// redactTransportError strips the credential out of a transport failure.
//
// The HTTP client wraps every failure in a *url.Error carrying the full URL it
// was dialing — query included. For a delivery fetch that query IS the
// credential, and on a refused redirect it is the credential of a URL the FIRST
// HOP chose, so the wrapper leaks even when this package's own message is already
// redacted. Rebuilding it is the only way to keep the value out of whatever reads
// the error; the underlying cause is preserved so errors.Is still reaches it.
func redactTransportError(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	return fmt.Errorf("%s %s: %w", urlErr.Op, helpers.RedactURL(urlErr.URL), urlErr.Err)
}

// read consumes the body under the configured cap.
//
// It reads one byte past the cap so an oversized body is DETECTED rather than
// silently truncated. Truncated content that looks whole is worse than a refusal:
// the caller has paid for it and has no way to tell it is incomplete.
func (f *ContentFetcher) read(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, f.maxBytes+1))
	if err != nil {
		return nil, &FetchError{Failure: FetchUnreachable, Op: "read content", Err: err}
	}
	if int64(len(body)) > f.maxBytes {
		return nil, &FetchError{
			Failure: FetchTooLarge, Op: "read content",
			Err: fmt.Errorf("body exceeds the %d byte cap", f.maxBytes),
		}
	}
	return body, nil
}

// edgeReason pulls the edge's own refusal token out of a rejection body. The edge
// answers {"error": "...", "reason": "..."} on a binding failure; anything else
// yields "", and the caller falls back to the failure class.
func edgeReason(r io.Reader) string {
	var payload struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxErrorBodyBytes)).Decode(&payload); err != nil {
		return ""
	}
	if !edgeReasonToken.MatchString(payload.Reason) {
		return ""
	}
	return payload.Reason
}

// edgeReasonToken is the shape a refusal token may have.
//
// The body this is read from is written by the host just fetched from, and the
// value is promoted over this SDK's own classification. Unchecked, a publisher
// could answer any 4 KiB of text and have it render as though the SDK had said
// it. Anything that is not token-shaped falls back to the failure class, which
// the SDK does own.
var edgeReasonToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// mimeTypeOf reduces a Content-Type to its media type, dropping parameters such
// as charset. The charset belongs to whoever decodes the bytes; the content
// carries the media type alone.
func mimeTypeOf(header string) string {
	if header == "" {
		return defaultContentMIMEType
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil || mediaType == "" {
		return defaultContentMIMEType
	}
	return mediaType
}
