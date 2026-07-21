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
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// signedURLVector mirrors the SignedUrlVector shape the TS/py parity tests read.
// The SIGN-parity fields (SignerSeedHex, SourceURL, AgentID, ExpUnix) let a
// TS/python port re-sign the exact SOURCE under the oracle's seed and reproduce
// the emitted SignedURL string byte-for-byte.
type signedURLVector struct {
	Name          string `json:"name"`
	PubB64URL     string `json:"pub_b64url"`
	KID           string `json:"kid"`
	SignedURL     string `json:"signed_url"`
	NowUnix       int64  `json:"now_unix"`
	ExpectedValid bool   `json:"expected_valid"`
	// --- SIGN-parity additions ---
	SignerSeedHex string `json:"signer_seed_hex"`
	SourceURL     string `json:"source_url"`
	AgentID       string `json:"agent_id"`
	ExpUnix       int64  `json:"exp_unix"`
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
	exSeedHex := hex.EncodeToString(exSeed)
	pub := b64urlNoPad(exPub)

	signOrFail := func(rawURL, agentID string) SignedURL {
		su, err := SignURLEd25519(exPriv, kid, rawURL, agentID, expiry)
		if err != nil {
			t.Fatalf("sign %s: %v", rawURL, err)
		}
		return su
	}

	// emit signs `source` and records everything a sign-face port needs to
	// reproduce the exact `signed_url` string (source, agent_id, exp, signer seed).
	emit := func(name, source, agentID string, now int64, valid bool) signedURLVector {
		return signedURLVector{
			Name: name, PubB64URL: pub, KID: kid,
			SignedURL: signOrFail(source, agentID).URL,
			NowUnix:   now, ExpectedValid: valid,
			SignerSeedHex: exSeedHex, SourceURL: source, AgentID: agentID, ExpUnix: expUnix,
		}
	}

	// Tampered: flip a byte in the signed valid URL's path so verify fails. Its
	// stored signed_url no longer matches a fresh sign of any source, so it is
	// NOT exercised by the positive (re-sign) parity loop (expected_valid=false).
	tampered := replaceFirst(signOrFail("https://cdn.example/a?doc=1&z=9&a=2", "").URL, "/a?", "/x?")

	return []signedURLVector{
		emit("valid_bearer_sorted_query", "https://cdn.example/a?doc=1&z=9&a=2", "", freshNow, true),
		emit("valid_agent_bound", "https://cdn.example/b?doc=7", agentTP, freshNow, true),
		emit("expired", "https://cdn.example/c", "", staleNow, false),
		{
			Name: "tampered_path", PubB64URL: pub, KID: kid, SignedURL: tampered,
			NowUnix: freshNow, ExpectedValid: false,
			SignerSeedHex: exSeedHex, SourceURL: "https://cdn.example/a?doc=1&z=9&a=2", AgentID: "", ExpUnix: expUnix,
		},
		// TRICKY vectors — the cases a `new URL()`/urlsplit-normalizing sign face
		// gets WRONG: mixed-case host, an explicit default :443, and a raw space or
		// percent in the PATH. Signed as OPAQUE BYTES, they MUST round-trip verbatim.
		emit("tricky_mixed_case_host", "https://CDN.Example/Doc?x=1", "", freshNow, true),
		emit("tricky_explicit_default_port", "https://cdn.example:443/doc?x=1", "", freshNow, true),
		emit("tricky_space_in_path", "https://cdn.example/a path/doc?x=1", "", freshNow, true),
		emit("tricky_percent_in_path", "https://cdn.example/Doc%2Fpart?z=9&a=2", "", freshNow, true),
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
// testdata/acceptance-vectors.json; its raw bytes are the
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
	// ExchangeSeedHex is the exchange offer-signing seed (fixedSeed 0x66), so a
	// sign-face port re-signs canonicalOfferPayload(offer_json) and byte-matches
	// the signature already embedded in offer_json.
	ExchangeSeedHex string `json:"exchange_seed_hex"`
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
// the hard JCS encodings: minimal / Struct-ext-with->1-
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
		// Freshness is fail-closed and mirrors core.Verifier.expired: a missing
		// expires_at is expired (not eternal); a present bound is inclusive at now.
		expired := offer.GetExpiresAt() == nil || offer.GetExpiresAt().AsTime().Before(time.Unix(nowUnix, 0))
		return offerVerifyVector{
			Name:              name,
			Exchange:          exchange,
			ExchangePubB64URL: pubB64URL,
			OfferJSON:         offerCanonicalProtoJSON(t, offer),
			NowUnix:           nowUnix,
			ExpectedVerified:  verifyErr == nil && !expired,
			ExchangeSeedHex:   hex.EncodeToString(exSeed),
		}
	}

	// A conformant offer is always minted now+TTL, so every positive (verified)
	// fixture carries a future expires_at; the freshness dimension is exercised
	// by the dedicated vectors appended below.
	future := timestamppb.New(time.Unix(expUnix, 0).UTC())

	minimal := &rampv1.Offer{OfferId: "offer-minimal", ExpiresAt: future}

	structExt, err := structpb.NewStruct(map[string]any{
		// >1 key, intentionally NOT in sorted order, to force JCS recursive key-sort.
		"zebra":  "last",
		"alpha":  "first",
		"nested": map[string]any{"y": 2.0, "x": 1.0},
	})
	if err != nil {
		t.Fatalf("struct ext: %v", err)
	}
	structExtOffer := &rampv1.Offer{OfferId: "offer-struct", Ext: structExt, ExpiresAt: future}

	twoTimestamps := &rampv1.Offer{
		OfferId:   "offer-two-ts",
		ExpiresAt: timestamppb.New(time.Unix(expUnix, 0).UTC()),
		DataAsOf:  timestamppb.New(time.Unix(1_699_990_000, 0).UTC()),
	}

	repeated := &rampv1.Offer{
		OfferId:        "offer-repeated",
		ExpiresAt:      future,
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
			OfferId:   "offer-tamper",
			ExpiresAt: future,
			Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"},
		}, func(o *rampv1.Offer) {
			o.Pricing.Rate = "999.00" // mutate AFTER signing → signature invalid
		}),

		// --- Freshness dimension (M-7): every port must agree token-for-token on
		// the expires_at verdict against the injected clock. These lock the
		// fail-closed contract so a port cannot silently regress to fail-open. ---

		// fresh_at_now_inclusive: expires_at == now. Inclusive boundary → verified.
		emit("fresh_at_now_inclusive", &rampv1.Offer{
			OfferId:   "offer-fresh-now",
			ExpiresAt: timestamppb.New(time.Unix(nowUnix, 0).UTC()),
		}, nil),

		// expired_past: valid signature, expires_at strictly before now → rejected
		// on freshness (not signature).
		emit("expired_past", &rampv1.Offer{
			OfferId:   "offer-expired",
			ExpiresAt: timestamppb.New(time.Unix(nowUnix-100, 0).UTC()),
		}, nil),

		// missing_expires_at: valid signature, NO expires_at. Fail-closed → rejected.
		// This is the exact fail-open hole M-7 flagged: a port that returns "fresh"
		// on a missing bound admits an unbounded bearer offer and breaks here.
		emit("missing_expires_at", &rampv1.Offer{
			OfferId: "offer-no-expiry",
		}, nil),
	}
}

// wireCanonicalVector pins the wire-to-canonical conversion: wire_json is the
// offer exactly as the Connect codec emits it (camelCase json_names, enums as
// names, EmitUnpopulated zero-inflation; JCS-stabilized so the committed file is
// deterministic), canonical_json is the byte sequence the offer signature covers
// (canonicalOfferPayload: signature/signature_algorithm cleared, snake_case,
// omit-unpopulated, JCS). A from-wire canonicalizer in any language must map
// wire_json to canonical_json exactly.
type wireCanonicalVector struct {
	Name          string          `json:"name"`
	WireJSON      json.RawMessage `json:"wire_json"`
	CanonicalJSON json.RawMessage `json:"canonical_json"`
}

// wireEmitJSONOptions is the Connect wire emission the broker's codec produces:
// snake_case proto names (UseProtoNames=true, the RAMP wire contract) plus
// EmitUnpopulated (see sdk/go/connectserver codec).
var wireEmitJSONOptions = protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}

// buildWireCanonicalVectors renders a matrix of offers through BOTH pinned
// option sets. The matrix deliberately covers the pruning rules a from-wire
// canonicalizer must implement: an UNSPECIFIED (zero) enum the wire inflates
// but the canonical form omits, a proto3-optional scalar SET to its zero value
// ("" — kept, presence-tracked), Struct ext key order, two Timestamps, and
// repeated message fields.
func buildWireCanonicalVectors(t *testing.T) []wireCanonicalVector {
	t.Helper()
	emit := func(name string, offer *rampv1.Offer) wireCanonicalVector {
		wirePJ, err := wireEmitJSONOptions.Marshal(offer)
		if err != nil {
			t.Fatalf("%s: wire proto-JSON marshal: %v", name, err)
		}
		// JCS-stabilize the committed wire form (protojson whitespace/order is not
		// deterministic); key CASE is untouched, so the camel wire shape survives.
		wireCanon, err := jcs.Transform(wirePJ)
		if err != nil {
			t.Fatalf("%s: wire JCS: %v", name, err)
		}
		canonical, err := canonicalOfferPayload(offer)
		if err != nil {
			t.Fatalf("%s: canonical payload: %v", name, err)
		}
		return wireCanonicalVector{Name: name, WireJSON: wireCanon, CanonicalJSON: canonical}
	}

	structExt, err := structpb.NewStruct(map[string]any{
		"zebra": "last", "alpha": "first",
		"nested": map[string]any{"y": 2.0, "x": 1.0},
	})
	if err != nil {
		t.Fatalf("wire-canonical struct ext: %v", err)
	}

	return []wireCanonicalVector{
		// deliveryMethod is the zero enum: the wire renders
		// DELIVERY_METHOD_UNSPECIFIED, the canonical form omits the field.
		emit("unspecified_enum_pruned", &rampv1.Offer{
			OfferId:  "offer-wire-unspec",
			Exchange: "exchange.example.com",
		}),
		// Pricing.unit is proto3 optional: set to "" it is presence-tracked and
		// KEPT by the canonical form, while the sibling non-optional zero scalars
		// the wire inflates are pruned.
		emit("set_empty_optional_unit", &rampv1.Offer{
			OfferId:  "offer-wire-unit",
			Exchange: "exchange.example.com",
			Pricing: &rampv1.Pricing{
				Model:    rampv1.PricingModel_PRICING_MODEL_FREE,
				Currency: "EUR",
				Unit:     proto.String(""),
			},
		}),
		emit("struct_ext_multi_key", &rampv1.Offer{
			OfferId:  "offer-wire-struct",
			Exchange: "exchange.example.com",
			Ext:      structExt,
		}),
		emit("two_timestamps", &rampv1.Offer{
			OfferId:   "offer-wire-two-ts",
			Exchange:  "exchange.example.com",
			ExpiresAt: timestamppb.New(time.Unix(1_700_000_900, 0).UTC()),
			DataAsOf:  timestamppb.New(time.Unix(1_699_990_000, 0).UTC()),
		}),
		emit("repeated_terms_enum", &rampv1.Offer{
			OfferId:        "offer-wire-repeated",
			Exchange:       "exchange.example.com",
			DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_DIRECT,
			Pricing: &rampv1.Pricing{
				Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD",
			},
			Terms: []*rampv1.LicenseTerm{
				{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Scopes: []string{"ai-train"}},
			},
		}),
	}
}

// buildSignRequestVectors signs a fixed set of requests with the REAL Go
// SignRequest and records the exact bytes it emits. Covered set is exactly
// @method @target-uri content-digest authorization signature-agent (no
// entitlement-token header present, so coveredFor never appends the conditional entitlement
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

// verifyRequestNegVector mirrors the NegVerifyVector shape the TS/py server-verify
// parity suites read. It is a fully-formed SINGLE-SIG request whose verification
// MUST be rejected, tagged with the exact reason token the connectserver taxonomy
// (classify.go RejectReason.String()) assigns — proven by running the REAL Go
// verify path (VerifyRequest + the replay orchestration) against the vector and
// asserting it produces that reason. The port reconstructs the request from these
// fields, injects resolver_pubkey for keyid, pins the clock to `now`, and asserts
// the same rejection.
type verifyRequestNegVector struct {
	Name           string `json:"name"`
	Method         string `json:"method"`
	URL            string `json:"url"`
	BodyHex        string `json:"body_hex"`
	Authorization  string `json:"authorization"`
	SignatureAgent string `json:"signature_agent"`
	ContentDigest  string `json:"content_digest"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
	// KeyID is the keyid the request's Signature-Input claims.
	KeyID string `json:"keyid"`
	// ResolverKeyID / ResolverPubkeyB64URL describe the key the injected resolver
	// serves: for most cases resolver_keyid==keyid and the pubkey is the true
	// signer key; for neg_wrong_key the resolver serves a DIFFERENT (wrong) key so
	// the crypto check fails.
	ResolverKeyID        string `json:"resolver_keyid"`
	ResolverPubkeyB64URL string `json:"resolver_pubkey_b64url"`
	// Now is the verifier clock the case is pinned to (inside the window except for
	// neg_expired, which is post-expiry).
	Now int64 `json:"now"`
	// ExpectedReason is RejectReason.String() for the Go rejection.
	ExpectedReason string `json:"expected_reason"`
	// Replay marks the neg_replay case: the same request is presented twice; the
	// SECOND presentation is the one that must be rejected as "replay".
	Replay bool `json:"replay,omitempty"`
	// Entitlement, when non-empty, is set as the X-Entitlement-Token request
	// header. The neg_entitlement_uncovered case carries it WITHOUT the signature
	// covering x-entitlement-token, so a conformant server-verify must reject an
	// unsigned entitlement claim (enforceEntitlementCoverage). Format-neutral —
	// the token value stands in for any JWT/opaque capability token.
	Entitlement string `json:"entitlement,omitempty"`
}

// negRequest is one signed request the negative emitter mutates into a reject case.
type negRequest struct {
	method, url    string
	body           []byte
	authorization  string
	signatureAgent string
	req            *http.Request
	sigInput       string
	sig            string
	contentDigest  string
}

// signNegBase signs a fixed request with the neg-vector signer (seed 0x77) and
// returns the wire artifacts, so each negative is a real signature the Go verifier
// accepts before the case-specific mutation flips it to a rejection.
func signNegBase(t *testing.T, keyid string, seed []byte, created, expires int64) negRequest {
	t.Helper()
	const (
		method        = "POST"
		url           = "https://broker.example/ramp.v1.BrokerService/Fetch"
		authorization = "Bearer neg-token"
		sigAgent      = "https://agent.example"
	)
	body := []byte(`{"uri":"https://cdn.example/neg"}`)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("neg base: new request: %v", err)
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set(SignatureAgentHeader, sigAgent)
	signer, err := NewEd25519SignerFromSeed(keyid, seed)
	if err != nil {
		t.Fatalf("neg base: signer: %v", err)
	}
	if err := SignRequest(context.Background(), req, body, signer, SignOptions{Created: created, Expires: expires}); err != nil {
		t.Fatalf("neg base: sign: %v", err)
	}
	return negRequest{
		method: method, url: url, body: body,
		authorization: authorization, signatureAgent: sigAgent, req: req,
		sigInput:      req.Header.Get("Signature-Input"),
		sig:           req.Header.Get("Signature"),
		contentDigest: req.Header.Get("Content-Digest"),
	}
}

// verifyNegReason drives the REAL Go verify path (VerifyRequest, then the
// connectserver replay orchestration when replay!=nil) over a reconstructed
// request and returns the classified reject reason token — the authoritative
// oracle the emitted expected_reason is taken from. The reconstruction mirrors
// what the TS/py port does: headers off the vector fields, key from the resolver,
// clock pinned to now.
func verifyNegReason(
	t *testing.T, v verifyRequestNegVector, resolverPub ed25519.PublicKey,
	replaySeen map[string]bool,
) string {
	t.Helper()
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
	if v.Entitlement != "" {
		req.Header.Set(entitlementHeader, v.Entitlement)
	}
	resolver := NewStaticKeyResolver(map[string]ed25519.PublicKey{})
	if resolverPub != nil {
		resolver.Put(v.ResolverKeyID, resolverPub)
	}
	opts := VerifyOptions{Now: time.Unix(v.Now, 0)}
	sigs, verr := VerifyMultisigRequestResolved(context.Background(), req, body, resolver, opts)
	if verr != nil {
		return classifyNegReason(verr)
	}
	// Replay orchestration mirrors connectserver.serverConfig.verify: the nonce is
	// keyid+"\x00"+std-base64(sig); a seen nonce classifies as "replay".
	for i := range sigs {
		nonce := sigs[i].KeyID + "\x00" + sigs[i].Signature
		if replaySeen != nil {
			if replaySeen[nonce] {
				return "replay"
			}
			replaySeen[nonce] = true
		}
	}
	return ""
}

// classifyNegReason mirrors connectserver.ClassifyReject over the helpers
// sentinels for the SINGLE-SIG surface (broken_chain / hop_budget are multisig,
// out of scope): every signature-authenticity/freshness/key failure is the
// default "signature" token.
func classifyNegReason(err error) string {
	switch {
	case errors.Is(err, ErrTooManyHops):
		return "hop_budget"
	case errors.Is(err, ErrBrokenSignatureChain):
		return "broken_chain"
	default:
		return "signature"
	}
}

// buildVerifyRequestNegVectors emits the SINGLE-SIG negative-verify corpus the
// TS/py server-verify suites consume: neg_bad_sig, neg_replay, neg_expired,
// neg_wrong_key, neg_tampered_authorization. Each is produced by signing with the
// REAL Go signer then applying the case mutation, and each recorded
// expected_reason is taken from the REAL Go verify path (verifyNegReason) so the
// tokens are authoritative, never hand-authored.
func buildVerifyRequestNegVectors(t *testing.T) []verifyRequestNegVector {
	t.Helper()
	const (
		keyid    = "mcp.v1"
		created  = int64(1_700_000_000)
		expires  = int64(1_700_000_600)
		freshNow = int64(1_700_000_100) // inside window
		staleNow = int64(1_700_000_900) // past expires
	)
	seed := fixedSeed(0x77)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	pubB64 := b64urlNoPad(pub)
	base := signNegBase(t, keyid, seed, created, expires)
	bodyHex := hex.EncodeToString(base.body)

	// mk builds a vector template carrying the base (valid) artifacts; each case
	// then overrides the field it mutates.
	mk := func(name string, now int64) verifyRequestNegVector {
		return verifyRequestNegVector{
			Name: name, Method: base.method, URL: base.url, BodyHex: bodyHex,
			Authorization: base.authorization, SignatureAgent: base.signatureAgent,
			ContentDigest: base.contentDigest, SignatureInput: base.sigInput, Signature: base.sig,
			KeyID: keyid, ResolverKeyID: keyid, ResolverPubkeyB64URL: pubB64, Now: now,
		}
	}

	// neg_bad_sig: flip the last signature byte so the Ed25519 check fails.
	badSig := mk("neg_bad_sig", freshNow)
	badSig.Signature = corruptSignatureLastByte(base.sig)

	// neg_replay: the base request is valid; presented twice the second trips the
	// replay store. Reason "replay".
	replay := mk("neg_replay", freshNow)
	replay.Replay = true

	// neg_expired: the base request, verified past its expires. Reason "signature".
	expired := mk("neg_expired", staleNow)

	// neg_wrong_key: the resolver serves a DIFFERENT key (seed 0x78) for keyid, so
	// the crypto check fails against the wrong public key. Reason "signature".
	wrongPub := ed25519.NewKeyFromSeed(fixedSeed(0x78)).Public().(ed25519.PublicKey)
	wrongKey := mk("neg_wrong_key", freshNow)
	wrongKey.ResolverPubkeyB64URL = b64urlNoPad(wrongPub)

	// neg_tampered_authorization: the covered authorization header value is changed
	// after signing, so the reconstructed base no longer matches. Reason "signature".
	tampered := mk("neg_tampered_authorization", freshNow)
	tampered.Authorization = base.authorization + "-tampered"

	// neg_entitlement_uncovered: a validly-signed request that ALSO carries the
	// X-Entitlement-Token header WITHOUT the signature covering it. The entitlement
	// claim is unsigned, so a conformant server-verify must reject it
	// (enforceEntitlementCoverage) even though the Ed25519 check itself passes.
	entitlement := mk("neg_entitlement_uncovered", freshNow)
	entitlement.Entitlement = "jwt:demo-unsigned-entitlement-token"

	out := []verifyRequestNegVector{badSig, replay, expired, wrongKey, tampered, entitlement}
	// Derive expected_reason from the REAL Go verify path — never hand-author it.
	for i := range out {
		out[i].ExpectedReason = oracleNegReason(t, out[i])
	}
	return out
}

// oracleNegReason runs the emitted vector through the REAL Go verify path and
// returns the reason token it produces, so expected_reason is authoritative.
func oracleNegReason(t *testing.T, v verifyRequestNegVector) string {
	t.Helper()
	var resolverPub ed25519.PublicKey
	if v.ResolverPubkeyB64URL != "" {
		raw, err := base64.RawURLEncoding.DecodeString(v.ResolverPubkeyB64URL)
		if err != nil {
			t.Fatalf("%s: decode resolver pub: %v", v.Name, err)
		}
		resolverPub = ed25519.PublicKey(raw)
	}
	var seen map[string]bool
	if v.Replay {
		seen = map[string]bool{}
		_ = verifyNegReason(t, v, resolverPub, seen) // first presentation records the nonce
	}
	return verifyNegReason(t, v, resolverPub, seen)
}

// corruptSignatureLastByte decodes the `sig1=:<b64>:` value, flips the final byte,
// and re-encodes — a minimal, deterministic mutation that fails the Ed25519 check
// while keeping the wire form well-formed (so the rejection is a signature failure,
// not a parse failure).
func corruptSignatureLastByte(sig string) string {
	i := strings.IndexByte(sig, ':')
	j := strings.LastIndexByte(sig, ':')
	if i < 0 || j <= i {
		return sig
	}
	label := sig[:i]
	raw, err := base64.StdEncoding.DecodeString(sig[i+1 : j])
	if err != nil || len(raw) == 0 {
		return sig
	}
	raw[len(raw)-1] ^= 0x01
	return label + ":" + base64.StdEncoding.EncodeToString(raw) + ":"
}

// verifyNegVectorReason asserts each emitted negative rejects with the recorded
// reason through the REAL Go verify path — the self-consistency guard that makes
// expected_reason authoritative rather than hand-authored.
func verifyNegVectorReason(t *testing.T, v verifyRequestNegVector) {
	t.Helper()
	var resolverPub ed25519.PublicKey
	if v.ResolverPubkeyB64URL != "" {
		raw, err := base64.RawURLEncoding.DecodeString(v.ResolverPubkeyB64URL)
		if err != nil {
			t.Fatalf("%s: decode resolver pub: %v", v.Name, err)
		}
		resolverPub = ed25519.PublicKey(raw)
	}
	var seen map[string]bool
	if v.Replay {
		seen = map[string]bool{}
		// First presentation must be accepted (empty reason), recording the nonce.
		if got := verifyNegReason(t, v, resolverPub, seen); got != "" {
			t.Fatalf("%s: first presentation unexpectedly rejected: %q", v.Name, got)
		}
	}
	got := verifyNegReason(t, v, resolverPub, seen)
	if got != v.ExpectedReason {
		t.Fatalf("neg vector %s: oracle reason=%q, recorded=%q", v.Name, got, v.ExpectedReason)
	}
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
	verifyRequestNegVectors := buildVerifyRequestNegVectors(t)
	for _, v := range verifyRequestNegVectors {
		verifyNegVectorReason(t, v)
	}
	acceptanceVectors := buildAcceptanceVectors(t)
	offerVerifyVectors := buildOfferVerifyVectors(t)
	wireCanonicalVectors := buildWireCanonicalVectors(t)

	signedURLPath := filepath.Join("testdata", "signedurl-vectors.json")
	popPath := filepath.Join("testdata", "pop-vectors.json")
	signRequestPath := filepath.Join("testdata", "sign-request-vectors.json")
	verifyNegPath := filepath.Join("testdata", "verify-request-neg-vectors.json")
	acceptancePath := filepath.Join("testdata", "acceptance-vectors.json")
	offerVerifyPath := filepath.Join("testdata", "offer-verify-vectors.json")
	wireCanonicalPath := filepath.Join("testdata", "wire-canonical-vectors.json")

	// The sign-request + acceptance parity suites read a {"vectors": [...]} object
	// (the thumbprint-vectors.json shape), not a bare array like signedurl/pop. The
	// acceptance + offer-verify docs additionally carry a canonicalization marker
	// ("jcs") so a reader cannot confuse them with the old proto-binary form.
	signRequestDoc := map[string]any{"vectors": signRequestVectors}
	verifyNegDoc := map[string]any{"vectors": verifyRequestNegVectors}
	acceptanceDoc := map[string]any{"canonicalization": "jcs", "vectors": acceptanceVectors}
	offerVerifyDocValue := offerVerifyDoc{Canonicalization: "jcs", Vectors: offerVerifyVectors}
	wireCanonicalDoc := map[string]any{"canonicalization": "jcs", "vectors": wireCanonicalVectors}

	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, signedURLPath, signedURLVectors)
		writeJSON(t, popPath, popVectors)
		writeJSON(t, signRequestPath, signRequestDoc)
		writeJSON(t, verifyNegPath, verifyNegDoc)
		writeJSON(t, acceptancePath, acceptanceDoc)
		writeJSON(t, offerVerifyPath, offerVerifyDocValue)
		writeJSON(t, wireCanonicalPath, wireCanonicalDoc)
		return
	}

	// Default run: assert the committed files are byte-identical to a fresh emit.
	assertMatches(t, signedURLPath, signedURLVectors)
	assertMatches(t, popPath, popVectors)
	assertMatches(t, signRequestPath, signRequestDoc)
	assertMatches(t, verifyNegPath, verifyNegDoc)
	assertMatches(t, acceptancePath, acceptanceDoc)
	assertMatches(t, offerVerifyPath, offerVerifyDocValue)
	assertMatches(t, wireCanonicalPath, wireCanonicalDoc)
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
