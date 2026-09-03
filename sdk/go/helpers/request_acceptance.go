package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// ErrRequestAcceptanceSignatureInvalid signals that the agent did not sign the
// request-acceptance payload presented by the caller.
var ErrRequestAcceptanceSignatureInvalid = errors.New("helpers: request-acceptance signature invalid")

// maxRequestAcceptanceItems mirrors the repeated.max_items rule on
// AgentRequestAcceptancePayload.items. The helper enforces it itself, before
// any canonicalization work, because a verifier may run with wire validation
// off and rendering an unbounded caller-controlled list to canonical JSON is
// the expensive step. A test pins this constant to the wire rule.
const maxRequestAcceptanceItems = 256

// RequestAcceptancePayload builds the complete ordered request-set payload an
// agent signs before any Broker fan-out.
func RequestAcceptancePayload(req *rampv1.TransactionRequest) (*rampv1.AgentRequestAcceptancePayload, error) {
	if req == nil {
		return nil, errors.New("helpers: transaction request is nil")
	}
	if req.GetRequester() == nil {
		return nil, errors.New("helpers: requester is nil")
	}
	if len(req.GetItems()) == 0 {
		return nil, errors.New("helpers: transaction request has no items")
	}
	items := make([]*rampv1.AgentRequestAcceptanceItem, 0, len(req.GetItems()))
	for i, item := range req.GetItems() {
		offer := item.GetOffer()
		if offer == nil {
			return nil, fmt.Errorf("helpers: item %d offer is nil", i)
		}
		if offer.GetSignature() == "" {
			return nil, fmt.Errorf("helpers: item %d offer is unsigned", i)
		}
		if offer.GetExchange() == "" {
			return nil, fmt.Errorf("helpers: item %d offer exchange is empty", i)
		}
		items = append(items, &rampv1.AgentRequestAcceptanceItem{
			OfferSig: offer.GetSignature(),
			Exchange: offer.GetExchange(),
		})
	}
	return &rampv1.AgentRequestAcceptancePayload{
		Items:           items,
		RequesterId:     req.GetRequester().GetId(),
		RequesterDomain: req.GetRequester().GetDomain(),
		IdempotencyKey:  req.GetIdempotencyKey(),
	}, nil
}

// CanonicalRequestAcceptanceBytes returns the exact JCS(protojson(...)) bytes
// covered by an AgentRequestAcceptance signature.
func CanonicalRequestAcceptanceBytes(payload *rampv1.AgentRequestAcceptancePayload) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("helpers: request-acceptance payload is nil")
	}
	if len(payload.GetItems()) == 0 {
		return nil, errors.New("helpers: request-acceptance payload has no items")
	}
	if len(payload.GetItems()) > maxRequestAcceptanceItems {
		return nil, fmt.Errorf("helpers: request-acceptance payload has %d items, the maximum is %d",
			len(payload.GetItems()), maxRequestAcceptanceItems)
	}
	for i, item := range payload.GetItems() {
		if item.GetOfferSig() == "" {
			return nil, fmt.Errorf("helpers: request-acceptance item %d offer signature is empty", i)
		}
		if item.GetExchange() == "" {
			return nil, fmt.Errorf("helpers: request-acceptance item %d exchange is empty", i)
		}
	}
	return canonicalSignPayload(payload)
}

// SignRequestAcceptance signs req's complete ordered request set with priv.
func SignRequestAcceptance(priv ed25519.PrivateKey, req *rampv1.TransactionRequest) (*rampv1.AgentRequestAcceptance, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("helpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	payload, err := RequestAcceptancePayload(req)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalRequestAcceptanceBytes(payload)
	if err != nil {
		return nil, err
	}
	return &rampv1.AgentRequestAcceptance{
		Payload:            payload,
		Signature:          hex.EncodeToString(ed25519.Sign(priv, canonical)),
		SignatureAlgorithm: AcceptanceSignatureAlgorithm,
	}, nil
}

// SignRequestAcceptanceWith is SignRequestAcceptance for a KMS/HSM-backed
// Signer.
func SignRequestAcceptanceWith(ctx context.Context, signer Signer, req *rampv1.TransactionRequest) (*rampv1.AgentRequestAcceptance, error) {
	if signer == nil {
		return nil, errors.New("helpers: request-acceptance signer is nil")
	}
	if signer.Algorithm() != AlgEd25519 {
		return nil, fmt.Errorf("%w: request acceptance requires %q, signer offers %q",
			ErrUnsupportedAlgorithm, AlgEd25519, signer.Algorithm())
	}
	payload, err := RequestAcceptancePayload(req)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalRequestAcceptanceBytes(payload)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(ctx, canonical)
	if err != nil {
		return nil, fmt.Errorf("helpers: sign request acceptance: %w", err)
	}
	return &rampv1.AgentRequestAcceptance{
		Payload:            payload,
		Signature:          hex.EncodeToString(sig),
		SignatureAlgorithm: AcceptanceSignatureAlgorithm,
	}, nil
}

// VerifyRequestAcceptance verifies the signature and the shared request
// envelope fields. It deliberately does not apply a fan-out projection rule;
// an Exchange must call VerifyRequestAcceptanceProjection instead.
func VerifyRequestAcceptance(req *rampv1.TransactionRequest, acceptance *rampv1.AgentRequestAcceptance, pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("helpers: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if req == nil || req.GetRequester() == nil {
		return nil, errors.New("helpers: transaction request or requester is nil")
	}
	if acceptance == nil || acceptance.GetPayload() == nil {
		return nil, errors.New("helpers: request acceptance or payload is nil")
	}
	if acceptance.GetSignatureAlgorithm() != AcceptanceSignatureAlgorithm {
		return nil, fmt.Errorf("helpers: request acceptance algorithm must be %q", AcceptanceSignatureAlgorithm)
	}
	payload := acceptance.GetPayload()
	if payload.GetRequesterId() != req.GetRequester().GetId() ||
		payload.GetRequesterDomain() != req.GetRequester().GetDomain() ||
		payload.GetIdempotencyKey() != req.GetIdempotencyKey() {
		return nil, ErrRequestAcceptanceSignatureInvalid
	}
	// The signature is decoded and size-checked before canonicalization: the
	// canonical rendering is the expensive step, and a caller whose signature
	// cannot possibly verify must not be able to buy that work.
	sig, err := hex.DecodeString(acceptance.GetSignature())
	if err != nil {
		return nil, fmt.Errorf("helpers: decode request-acceptance signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrRequestAcceptanceSignatureInvalid
	}
	canonical, err := CanonicalRequestAcceptanceBytes(payload)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, ErrRequestAcceptanceSignatureInvalid
	}
	return canonical, nil
}

// VerifyRequestAcceptanceProjection additionally proves that req.items is the
// complete ordered projection of the signed original set addressed to exchange.
func VerifyRequestAcceptanceProjection(req *rampv1.TransactionRequest, acceptance *rampv1.AgentRequestAcceptance, exchange string, pub ed25519.PublicKey) ([]byte, error) {
	// An empty subrequest must be refused outright: for an exchange the signed
	// set never names, the projection is also empty, zero equals zero, and the
	// comparison loop below would report a verified projection for a request
	// addressed to nobody. Wire validation (items.min_items = 1) catches this
	// on the request path, but a verifier may run with validation off, and a
	// security primitive does not assume its caller validated first.
	if len(req.GetItems()) == 0 {
		return nil, ErrRequestAcceptanceSignatureInvalid
	}
	canonical, err := VerifyRequestAcceptance(req, acceptance, pub)
	if err != nil {
		return nil, err
	}
	// Membership uses the Exchange identity rule CheckAudience owns — case
	// folds, an explicit :443 equals the omitted HTTPS-default port — not raw
	// string equality. With raw equality, a signed set holding one.example and
	// one.example:443 lets a relay drop the differently spelled item and still
	// pass, while an honest complete forward is refused. A value that is not a
	// bare domain names nobody and never matches.
	if !IsBareDomain(exchange) {
		return nil, fmt.Errorf("helpers: projection exchange %q is not a bare domain", exchange)
	}
	namesExchange := func(v string) bool {
		verdict, err := CheckAudience(exchange, v)
		return err == nil && verdict == AudienceAccepted
	}
	want := make([]*rampv1.AgentRequestAcceptanceItem, 0, len(req.GetItems()))
	for _, ref := range acceptance.GetPayload().GetItems() {
		if namesExchange(ref.GetExchange()) {
			want = append(want, ref)
		}
	}
	if len(want) != len(req.GetItems()) {
		return nil, ErrRequestAcceptanceSignatureInvalid
	}
	for i, item := range req.GetItems() {
		offer := item.GetOffer()
		if offer == nil || !namesExchange(offer.GetExchange()) ||
			offer.GetSignature() != want[i].GetOfferSig() {
			return nil, ErrRequestAcceptanceSignatureInvalid
		}
	}
	return canonical, nil
}
