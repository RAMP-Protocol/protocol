package helpers

// Golden-vector emitter for the cross-language parity corpus (ADR-020 §8).
//
// The sdk/ts and sdk/python L1 helpers assert byte-parity against the sdk/go
// oracle for the signed-URL and RFC 9421 GET-PoP schemes. Rather than
// hand-author vectors (which would silently defeat the "no re-sort on verify"
// guard — see signedurl.go), this emitter signs with the REAL Go signer and
// writes the vectors to committed JSON, exactly as testdata/thumbprint-vectors.json
// pins the thumbprint scheme.
//
// DETERMINISM: every key is derived from a FIXED hardcoded Ed25519 seed and
// every created/expires/now is a FIXED unix timestamp — never time.Now() or a
// random source — so re-running the emitter reproduces byte-identical files
// (drift-gated in CI alongside the generated artifacts).
//
// Default `go test` behaviour is a no-op unless RAMP_UPDATE_VECTORS=1 is set;
// the vectors are committed, and CI regenerates + diffs them. Living in
// package helpers (internal test) lets the emitter reuse the unexported
// signature-base machinery (buildSignatureBase / sigParams / plainComponents /
// signatureInputInner) so the PoP vectors carry the exact bytes the edge
// verifier reconstructs.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// signedURLVector mirrors the SignedUrlVector shape the TS/py parity tests read.
type signedURLVector struct {
	Name          string `json:"name"`
	PubB64URL     string `json:"pub_b64url"`
	KID           string `json:"kid"`
	SignedURL     string `json:"signed_url"`
	NowUnix       int64  `json:"now_unix"`
	ExpectedValid bool   `json:"expected_valid"`
}

// popVector mirrors the PopVector shape the TS/py parity tests read.
type popVector struct {
	Name               string `json:"name"`
	Method             string `json:"method"`
	URL                string `json:"url"`
	AgentID            string `json:"agent_id"`
	PresentedKeyB64URL string `json:"presented_key_b64url"`
	// SignerSeedHex is the raw Ed25519 seed of the key that PRODUCED the
	// vector's signature, so a sign-face port can re-sign and byte-compare
	// against the stored Signature (the same self-contained-oracle shape
	// acceptance-vectors.json uses via seed_hex).
	SignerSeedHex  string `json:"signer_seed_hex"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
	NowUnix        int64  `json:"now_unix"`
	ExpectedValid  bool   `json:"expected_valid"`
}

// fixedSeed returns a deterministic 32-byte Ed25519 seed: byte i = (b+i) mod 256.
func fixedSeed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = byte(int(b) + i)
	}
	return s
}

func b64urlNoPad(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// buildSignedURLVectors signs a set of URLs with the real signer and records
// the verdict the real verifier reaches for each (against the pinned clock).
func buildSignedURLVectors(t *testing.T) []signedURLVector {
	t.Helper()
	const (
		kid      = "ex.v1"
		expUnix  = int64(1_700_000_300)
		freshNow = int64(1_700_000_100) // before expiry
		staleNow = int64(1_700_000_400) // after expiry
	)
	exSeed := fixedSeed(0x11)
	exPriv := ed25519.NewKeyFromSeed(exSeed)
	exPub := exPriv.Public().(ed25519.PublicKey)

	// An agent key, so one vector is agent-bound (agent_id present).
	agentPub := ed25519.NewKeyFromSeed(fixedSeed(0x22)).Public().(ed25519.PublicKey)
	agentTP, err := Thumbprint(agentPub)
	if err != nil {
		t.Fatal(err)
	}

	expiry := time.Unix(expUnix, 0)

	signOrFail := func(rawURL, agentID string) SignedURL {
		su, err := SignURLEd25519(exPriv, kid, rawURL, agentID, expiry)
		if err != nil {
			t.Fatalf("sign %s: %v", rawURL, err)
		}
		return su
	}

	valid := signOrFail("https://cdn.example/a?doc=1&z=9&a=2", "")
	bound := signOrFail("https://cdn.example/b?doc=7", agentTP)
	expired := signOrFail("https://cdn.example/c", "")

	// Tampered: flip a byte in the signed valid URL's path so verify fails.
	tampered := valid.URL
	// Replace "/a?" with "/A?" (path tamper leaves query params intact).
	tampered = replaceFirst(tampered, "/a?", "/x?")

	pub := b64urlNoPad(exPub)
	return []signedURLVector{
		{Name: "valid_bearer_sorted_query", PubB64URL: pub, KID: kid, SignedURL: valid.URL, NowUnix: freshNow, ExpectedValid: true},
		{Name: "valid_agent_bound", PubB64URL: pub, KID: kid, SignedURL: bound.URL, NowUnix: freshNow, ExpectedValid: true},
		{Name: "expired", PubB64URL: pub, KID: kid, SignedURL: expired.URL, NowUnix: staleNow, ExpectedValid: false},
		{Name: "tampered_path", PubB64URL: pub, KID: kid, SignedURL: tampered, NowUnix: freshNow, ExpectedValid: false},
	}
}

func replaceFirst(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

// signEdgePoP produces an edge-form RFC 9421 GET PoP over exactly the two
// covered components the edge verifier (src/edge/src/pop.ts) checks: @method and
// @target-uri. It reuses the oracle's buildSignatureBase / signatureInputInner so
// the emitted Signature-Input header and the signed bytes are the canonical Go
// byte contract. keyid is the agent thumbprint (the 3-way identity anchor).
func signEdgePoP(t *testing.T, priv ed25519.PrivateKey, keyid, method, rawURL string, created, expires int64) (sigInput, sig string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	params := sigParams{
		Label:   "sig1",
		Covered: plainComponents("@method", "@target-uri"),
		KeyID:   keyid,
		Alg:     AlgEd25519,
		Created: created,
		Expires: expires,
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		t.Fatalf("build signature base: %v", err)
	}
	raw := ed25519.Sign(priv, []byte(base))
	inner := signatureInputInner(params)
	// Edge Signature-Input header carries "sig1=" + inner list; Signature carries
	// the std-base64 byte string (label=:...:), matching pop.ts parseSignature.
	return params.Label + "=" + inner, params.Label + "=:" + base64.StdEncoding.EncodeToString(raw) + ":"
}

func buildPopVectors(t *testing.T) []popVector {
	t.Helper()
	const (
		method   = "GET"
		created  = int64(1_700_000_000)
		expires  = int64(1_700_000_600)
		freshNow = int64(1_700_000_100)
		staleNow = int64(1_700_000_700) // after expires
	)
	agentSeed := fixedSeed(0x33)
	agentPriv := ed25519.NewKeyFromSeed(agentSeed)
	agentPub := agentPriv.Public().(ed25519.PublicKey)
	agentTP, err := Thumbprint(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	presented := b64urlNoPad(agentPub)

	// The agent_id lives in the URL query (agent_id=<thumbprint>); the edge
	// @target-uri is the full URL including that param, so the signer signs the
	// same string the verifier reconstructs.
	url := "https://cdn.example/doc?agent_id=" + agentTP

	validInput, validSig := signEdgePoP(t, agentPriv, agentTP, method, url, created, expires)

	// Expired: same signature, but the verifier's clock is past `expires`.
	// (freshnessFailure rejects before the crypto check.)

	// Wrong-key: an actor presents a DIFFERENT key + a self-signature. Its
	// thumbprint != agent_id, so the 3-way identity check rejects it.
	wrongPriv := ed25519.NewKeyFromSeed(fixedSeed(0x44))
	wrongPub := wrongPriv.Public().(ed25519.PublicKey)
	wrongInput, wrongSig := signEdgePoP(t, wrongPriv, agentTP, method, url, created, expires)
	wrongPresented := b64urlNoPad(wrongPub)

	return []popVector{
		{
			Name: "valid", Method: method, URL: url, AgentID: agentTP,
			PresentedKeyB64URL: presented, SignerSeedHex: hex.EncodeToString(agentSeed),
			SignatureInput: validInput, Signature: validSig,
			NowUnix: freshNow, ExpectedValid: true,
		},
		{
			Name: "expired", Method: method, URL: url, AgentID: agentTP,
			PresentedKeyB64URL: presented, SignerSeedHex: hex.EncodeToString(agentSeed),
			SignatureInput: validInput, Signature: validSig,
			NowUnix: staleNow, ExpectedValid: false,
		},
		{
			// Presented key's thumbprint != agent_id -> thumbprint_mismatch.
			Name: "wrong_key_thumbprint_mismatch", Method: method, URL: url, AgentID: agentTP,
			PresentedKeyB64URL: wrongPresented, SignerSeedHex: hex.EncodeToString(fixedSeed(0x44)),
			SignatureInput: wrongInput, Signature: wrongSig,
			NowUnix: freshNow, ExpectedValid: false,
		},
	}
}

// signRequestVector mirrors the SignRequestVector shape the py parity test reads.
// It records the exact bytes the Go SignRequest emits (signature base,
// Signature-Input, Signature) plus everything the port needs to reproduce them
// (method, absolute URL, body, authorization, created/expires, seed) and to
// round-trip verify (pubkey, content-digest).
type signRequestVector struct {
	Name           string `json:"name"`
	Method         string `json:"method"`
	URL            string `json:"url"`
	BodyHex        string `json:"body_hex"`
	Authorization  string `json:"authorization"`
	SignatureAgent string `json:"signature_agent"`
	KeyID          string `json:"keyid"`
	Created        int64  `json:"created"`
	Expires        int64  `json:"expires"`
	SignerSeedHex  string `json:"signer_seed_hex"`
	PubkeyB64URL   string `json:"pubkey_b64url"`
	ContentDigest  string `json:"content_digest"`
	SignatureBase  string `json:"signature_base"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
}

// acceptanceVector mirrors the AcceptanceVector shape the py parity test reads.
// Seeded 0102..1f20 — the SAME seed the app fixture (testdata/acceptance-vectors.json)
// uses — so the emitted canonical bytes + signature cross-check byte-for-byte
// against the app.
type acceptanceVector struct {
	Name            string `json:"name"`
	OfferSig        string `json:"offer_sig"`
	RequesterID     string `json:"requester_id"`
	RequesterDomain string `json:"requester_domain"`
	IdempotencyKey  string `json:"idempotency_key"`
	// CanonicalJCS is the exact RFC 8785 JCS UTF-8 string the acceptance signature
	// covers (JCS(protojson(AgentAcceptancePayload))). Replaces the old
	// proto3-field-tag canonical_bytes_hex — the canonicalization itself changed.
	CanonicalJCS string `json:"canonical_jcs"`
	SignatureHex string `json:"signature_hex"`
	PubkeyB64    string `json:"pubkey_b64"`
	SeedHex      string `json:"seed_hex"`
}

// acceptanceSeedHex is the fixed seed shared with the app's committed
// testdata/acceptance-vectors.json (BINDING amendment); its raw bytes are the
// signer seed for every acceptance vector.
const acceptanceSeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

// offerVerifyVector mirrors the OfferVerifyVector shape the TS/py core
// offer-verify parity suites read. The signed payload is
// JCS(protojson(offer with sig cleared)); offer_json is the FULL canonical
// proto-JSON of the SIGNED offer (signature + signature_algorithm present) so the
// port re-derives the signed bytes by clearing those two keys and re-running JCS,
// exactly as the Go oracle does. A tamper vector carries a signature that does not
// verify (offer mutated after signing) so the port lands it in Rejected.
type offerVerifyVector struct {
	Name              string          `json:"name"`
	Exchange          string          `json:"exchange"`
	ExchangePubB64URL string          `json:"exchange_pub_b64url"`
	OfferJSON         json.RawMessage `json:"offer_json"`
	NowUnix           int64           `json:"now_unix"`
	ExpectedVerified  bool            `json:"expected_verified"`
}

// offerVerifyDoc is the {"vectors":[...]} wrapper the offer-verify suites read,
// carrying the canonicalization marker so a reader cannot confuse it with a
// deterministic-protobuf form.
type offerVerifyDoc struct {
	Canonicalization string              `json:"canonicalization"`
	Vectors          []offerVerifyVector `json:"vectors"`
}

// offerCanonicalProtoJSON renders offer to the SAME pinned proto-JSON the signer
// canonicalizes over (camelCase, enums-as-names, omit-unpopulated). Emitting the
// vector's offer_json through the identical option set is what lets the port
// reproduce JCS(protojson(offer)) byte-for-byte.
func offerCanonicalProtoJSON(t *testing.T, offer *rampv1.Offer) json.RawMessage {
	t.Helper()
	pj, err := canonicalSignJSONOptions.Marshal(offer)
	if err != nil {
		t.Fatalf("offer proto-JSON marshal: %v", err)
	}
	// Re-key through JCS so the committed offer_json is itself canonical and stable
	// across protojson's non-deterministic whitespace/ordering (the port clears sig
	// + re-JCS-es regardless, but a canonical stored form keeps the vector file
	// deterministic under the drift gate).
	canon, err := jcs.Transform(pj)
	if err != nil {
		t.Fatalf("offer_json JCS: %v", err)
	}
	return json.RawMessage(canon)
}

// buildOfferVerifyVectors signs a MATRIX of offers with the REAL Go SignOffer and
// records, for each, the canonical proto-JSON, the exchange offer-signing pubkey,
// and the verdict the real VerifyOffer + expiry gate reaches. The matrix exercises
// the hard JCS encodings (architect-review MEDIUM): minimal / Struct-ext-with->1-
// key (recursive key-sort) / two Timestamps / repeated terms+attestations+enum /
// a tamper negative.
func buildOfferVerifyVectors(t *testing.T) []offerVerifyVector {
	t.Helper()
	const (
		exchange = "exchange.example.com"
		nowUnix  = int64(1_700_000_100)
		expUnix  = int64(1_700_000_900) // after now → not expired
	)
	exSeed := fixedSeed(0x66)
	exPriv := ed25519.NewKeyFromSeed(exSeed)
	exPub := exPriv.Public().(ed25519.PublicKey)
	pubB64URL := b64urlNoPad(exPub)

	// signVerdict signs offer in place and records the verdict the real verifier
	// reaches (against the pinned clock). tamper mutates the offer AFTER signing so
	// the recorded verdict is a genuine reject.
	emit := func(name string, offer *rampv1.Offer, tamper func(*rampv1.Offer)) offerVerifyVector {
		offer.Exchange = exchange
		sig, err := SignOffer(exPriv, offer)
		if err != nil {
			t.Fatalf("%s: sign offer: %v", name, err)
		}
		offer.Signature = sig
		offer.SignatureAlgorithm = OfferSignatureAlgorithm
		if tamper != nil {
			tamper(offer)
		}
		verifyErr := VerifyOffer(offer, offer.GetSignature(), exPub)
		expired := offer.GetExpiresAt() != nil && offer.GetExpiresAt().AsTime().Before(time.Unix(nowUnix, 0))
		return offerVerifyVector{
			Name:              name,
			Exchange:          exchange,
			ExchangePubB64URL: pubB64URL,
			OfferJSON:         offerCanonicalProtoJSON(t, offer),
			NowUnix:           nowUnix,
			ExpectedVerified:  verifyErr == nil && !expired,
		}
	}

	minimal := &rampv1.Offer{OfferId: "offer-minimal"}

	structExt, err := structpb.NewStruct(map[string]any{
		// >1 key, intentionally NOT in sorted order, to force JCS recursive key-sort.
		"zebra":  "last",
		"alpha":  "first",
		"nested": map[string]any{"y": 2.0, "x": 1.0},
	})
	if err != nil {
		t.Fatalf("struct ext: %v", err)
	}
	structExtOffer := &rampv1.Offer{OfferId: "offer-struct", Ext: structExt}

	twoTimestamps := &rampv1.Offer{
		OfferId:   "offer-two-ts",
		ExpiresAt: timestamppb.New(time.Unix(expUnix, 0).UTC()),
		DataAsOf:  timestamppb.New(time.Unix(1_699_990_000, 0).UTC()),
	}

	repeated := &rampv1.Offer{
		OfferId:        "offer-repeated",
		DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_DIRECT,
		Pricing:        &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD"},
		Terms: []*rampv1.LicenseTerm{
			{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Scopes: []string{"ai-train", "ai-infer"}},
			{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, Scopes: []string{"resell"}},
		},
		Attestations: []*rampv1.ResourceAttestation{
			{Verifier: "verifier.example", Keyid: "v1", Uri: "https://verifier.example/a"},
			{Verifier: "verifier2.example", Keyid: "v2", Uri: "https://verifier2.example/b"},
		},
		IabCategories: []string{"IAB1", "IAB2"},
	}

	return []offerVerifyVector{
		emit("minimal", minimal, nil),
		emit("struct_ext_multi_key", structExtOffer, nil),
		emit("two_timestamps", twoTimestamps, nil),
		emit("repeated_terms_enum", repeated, nil),
		// tamper_negative: sign a clean offer, then bump the price. The stored
		// signature no longer matches the (tampered) offer_json, so the port rejects.
		emit("tamper_negative", &rampv1.Offer{
			OfferId: "offer-tamper",
			Pricing: &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"},
		}, func(o *rampv1.Offer) {
			o.Pricing.Rate = "999.00" // mutate AFTER signing → signature invalid
		}),
	}
}

// buildSignRequestVectors signs a fixed set of requests with the REAL Go
// SignRequest and records the exact bytes it emits. Covered set is exactly
// @method @target-uri content-digest authorization signature-agent (no biscuit
// header present, so coveredFor never appends the conditional entitlement
// component). created/expires are the non-zero pinned window (reused from the
// pop emitter) so renderParamsTail never drops them. One vector carries an
// empty-authorization bound value; one carries an absent Signature-Agent so the
// empty-bind (static bootstrap) semantics are pinned cross-language.
func buildSignRequestVectors(t *testing.T) []signRequestVector {
	t.Helper()
	const (
		keyid   = "mcp.v1"
		created = int64(1_700_000_000)
		expires = int64(1_700_000_600)
	)
	seed := fixedSeed(0x55)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	type spec struct {
		name           string
		method         string
		url            string
		body           []byte
		authorization  string
		signatureAgent string
	}
	specs := []spec{
		{
			name:           "post_with_authorization",
			method:         "POST",
			url:            "https://broker.example/ramp.v1.BrokerService/Fetch",
			body:           []byte(`{"uri":"https://cdn.example/doc"}`),
			authorization:  "Bearer token-123",
			signatureAgent: "https://agent.example",
		},
		{
			// Signature-Agent left absent: bindSignatureAgent binds "" — the
			// static-bootstrap empty-bind case, pinned cross-language.
			name:          "post_empty_authorization_bound",
			method:        "POST",
			url:           "https://broker.example/ramp.v1.BrokerService/Fetch?trace=1",
			body:          []byte(`{"uri":"https://cdn.example/other"}`),
			authorization: "",
		},
	}

	out := make([]signRequestVector, 0, len(specs))
	for _, s := range specs {
		req, err := http.NewRequest(s.method, s.url, nil)
		if err != nil {
			t.Fatalf("%s: new request: %v", s.name, err)
		}
		if s.authorization != "" {
			req.Header.Set("Authorization", s.authorization)
		}
		if s.signatureAgent != "" {
			req.Header.Set(SignatureAgentHeader, s.signatureAgent)
		}
		signer, err := NewEd25519SignerFromSeed(keyid, seed)
		if err != nil {
			t.Fatalf("%s: signer: %v", s.name, err)
		}
		params := sigParams{
			Label:   "sig1",
			Covered: coveredFor(req),
			KeyID:   keyid,
			Alg:     AlgEd25519,
			Created: created,
			Expires: expires,
		}
		// SignRequest sets Content-Digest + binds Authorization + writes headers;
		// buildSignatureBase over the same params reproduces the exact base bytes.
		if err := SignRequest(context.Background(), req, s.body, signer, SignOptions{Created: created, Expires: expires}); err != nil {
			t.Fatalf("%s: sign: %v", s.name, err)
		}
		base, err := buildSignatureBase(req, params)
		if err != nil {
			t.Fatalf("%s: build base: %v", s.name, err)
		}
		out = append(out, signRequestVector{
			Name:           s.name,
			Method:         s.method,
			URL:            s.url,
			BodyHex:        hex.EncodeToString(s.body),
			Authorization:  s.authorization,
			SignatureAgent: s.signatureAgent,
			KeyID:          keyid,
			Created:        created,
			Expires:        expires,
			SignerSeedHex:  hex.EncodeToString(seed),
			PubkeyB64URL:   b64urlNoPad(pub),
			ContentDigest:  req.Header.Get("Content-Digest"),
			SignatureBase:  base,
			SignatureInput: req.Header.Get("Signature-Input"),
			Signature:      req.Header.Get("Signature"),
		})
	}
	return out
}

// verifySignRequestVector round-trips a sign-request vector through the REAL Go
// VerifyRequest at a pinned `now` inside the window, so any divergence surfaces
// in the Go drift gate rather than in the Python port.
func verifySignRequestVector(t *testing.T, v signRequestVector) {
	t.Helper()
	pubBytes, err := base64.RawURLEncoding.DecodeString(v.PubkeyB64URL)
	if err != nil {
		t.Fatalf("%s: decode pub: %v", v.Name, err)
	}
	body, err := hex.DecodeString(v.BodyHex)
	if err != nil {
		t.Fatalf("%s: decode body: %v", v.Name, err)
	}
	req, err := http.NewRequest(v.Method, v.URL, nil)
	if err != nil {
		t.Fatalf("%s: new request: %v", v.Name, err)
	}
	req.Header.Set("Content-Digest", v.ContentDigest)
	req.Header.Set("Authorization", v.Authorization)
	req.Header.Set(SignatureAgentHeader, v.SignatureAgent)
	req.Header.Set("Signature-Input", v.SignatureInput)
	req.Header.Set("Signature", v.Signature)
	now := time.Unix((v.Created+v.Expires)/2, 0)
	if _, err := VerifyRequest(req, body, ed25519.PublicKey(pubBytes), VerifyOptions{Now: now}); err != nil {
		t.Fatalf("sign-request vector %s: oracle VerifyRequest rejected a self-signed vector: %v", v.Name, err)
	}
}

// buildAcceptanceVectors signs a fixed set of offer acceptances with the REAL Go
// SignOfferAcceptance, seeded 0102..1f20 (shared with the app fixture). Includes
// the empty-domain case (proto3 field-3 default-skip). Records canonical bytes
// hex + signature hex + std-base64 pubkey.
func buildAcceptanceVectors(t *testing.T) []acceptanceVector {
	t.Helper()
	seed, err := hex.DecodeString(acceptanceSeedHex)
	if err != nil {
		t.Fatalf("decode acceptance seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	type spec struct {
		name            string
		offerSig        string
		requesterID     string
		requesterDomain string
		idempotencyKey  string
	}
	specs := []spec{
		{"all_present", "ex-offer-sig-hex", "agent-1", "agent.example.com", "idem-1"},
		{"empty_domain", "sig2deadbeef", "agent-2", "", "idem-2"},
	}

	out := make([]acceptanceVector, 0, len(specs))
	for _, s := range specs {
		offer := &rampv1.Offer{Signature: s.offerSig}
		requester := &rampv1.Requester{Id: s.requesterID, Domain: s.requesterDomain}
		canon, err := canonicalAcceptancePayload(offer, requester, s.idempotencyKey)
		if err != nil {
			t.Fatalf("%s: canonical: %v", s.name, err)
		}
		sigHex, err := SignOfferAcceptance(priv, offer, requester, s.idempotencyKey)
		if err != nil {
			t.Fatalf("%s: sign: %v", s.name, err)
		}
		// Self-check: the oracle verifies its own signature.
		if err := VerifyOfferAcceptance(offer, requester, s.idempotencyKey, sigHex, pub); err != nil {
			t.Fatalf("%s: oracle rejected its own acceptance signature: %v", s.name, err)
		}
		out = append(out, acceptanceVector{
			Name:            s.name,
			OfferSig:        s.offerSig,
			RequesterID:     s.requesterID,
			RequesterDomain: s.requesterDomain,
			IdempotencyKey:  s.idempotencyKey,
			CanonicalJCS:    string(canon),
			SignatureHex:    sigHex,
			PubkeyB64:       pubB64,
			SeedHex:         acceptanceSeedHex,
		})
	}
	return out
}

// verifySignedURLVector runs the vector through the real Go verifier so the
// recorded verdict is exactly what the oracle returns (self-consistency guard).
func verifySignedURLVector(t *testing.T, v signedURLVector) {
	t.Helper()
	pubBytes, err := base64.RawURLEncoding.DecodeString(v.PubB64URL)
	if err != nil {
		t.Fatalf("%s: decode pub: %v", v.Name, err)
	}
	_, err = VerifyURLEd25519(v.SignedURL, ed25519.PublicKey(pubBytes), time.Unix(v.NowUnix, 0))
	got := err == nil
	if got != v.ExpectedValid {
		t.Fatalf("signed-url vector %s: oracle verdict=%v, recorded=%v (err=%v)", v.Name, got, v.ExpectedValid, err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestGenerateVectors emits the signed-URL and PoP golden vectors. It is a
// verification no-op by default (asserts the committed files match what the
// emitter would produce right now); with RAMP_UPDATE_VECTORS=1 it (re)writes
// them. This makes the emitter both the generator and its own drift gate.
func TestGenerateVectors(t *testing.T) {
	signedURLVectors := buildSignedURLVectors(t)
	for _, v := range signedURLVectors {
		verifySignedURLVector(t, v)
	}
	popVectors := buildPopVectors(t)

	signRequestVectors := buildSignRequestVectors(t)
	for _, v := range signRequestVectors {
		verifySignRequestVector(t, v)
	}
	acceptanceVectors := buildAcceptanceVectors(t)
	offerVerifyVectors := buildOfferVerifyVectors(t)

	signedURLPath := filepath.Join("testdata", "signedurl-vectors.json")
	popPath := filepath.Join("testdata", "pop-vectors.json")
	signRequestPath := filepath.Join("testdata", "sign-request-vectors.json")
	acceptancePath := filepath.Join("testdata", "acceptance-vectors.json")
	offerVerifyPath := filepath.Join("testdata", "offer-verify-vectors.json")

	// The sign-request + acceptance parity suites read a {"vectors": [...]} object
	// (the thumbprint-vectors.json shape), not a bare array like signedurl/pop. The
	// acceptance + offer-verify docs additionally carry a canonicalization marker
	// ("jcs") so a reader cannot confuse them with the old proto-binary form.
	signRequestDoc := map[string]any{"vectors": signRequestVectors}
	acceptanceDoc := map[string]any{"canonicalization": "jcs", "vectors": acceptanceVectors}
	offerVerifyDocValue := offerVerifyDoc{Canonicalization: "jcs", Vectors: offerVerifyVectors}

	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, signedURLPath, signedURLVectors)
		writeJSON(t, popPath, popVectors)
		writeJSON(t, signRequestPath, signRequestDoc)
		writeJSON(t, acceptancePath, acceptanceDoc)
		writeJSON(t, offerVerifyPath, offerVerifyDocValue)
		return
	}

	// Default run: assert the committed files are byte-identical to a fresh emit.
	assertMatches(t, signedURLPath, signedURLVectors)
	assertMatches(t, popPath, popVectors)
	assertMatches(t, signRequestPath, signRequestDoc)
	assertMatches(t, acceptancePath, acceptanceDoc)
	assertMatches(t, offerVerifyPath, offerVerifyDocValue)
}

func assertMatches(t *testing.T, path string, v any) {
	t.Helper()
	want, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	want = append(want, '\n')
	got := readFile(t, path)
	if string(got) != string(want) {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate", path)
	}
}
