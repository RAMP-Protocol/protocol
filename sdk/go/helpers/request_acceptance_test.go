package helpers_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"buf.build/go/protovalidate"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func requestAcceptanceFixture() *rampv1.TransactionRequest {
	return &rampv1.TransactionRequest{
		IdempotencyKey: "idem-1",
		Requester:      &rampv1.Requester{Id: "agent-1", Domain: "agent.example"},
		Items: []*rampv1.TransactionItem{
			{Offer: &rampv1.Offer{Signature: "sig-a", Exchange: "one.example"}},
			{Offer: &rampv1.Offer{Signature: "sig-b", Exchange: "two.example"}},
			{Offer: &rampv1.Offer{Signature: "sig-c", Exchange: "one.example"}},
		},
	}
}

func TestRequestAcceptanceProjection_roundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	original := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, original)
	if err != nil {
		t.Fatal(err)
	}
	projected := &rampv1.TransactionRequest{
		IdempotencyKey: original.GetIdempotencyKey(),
		Requester:      original.GetRequester(),
		Items:          []*rampv1.TransactionItem{original.GetItems()[0], original.GetItems()[2]},
	}
	if _, err := helpers.VerifyRequestAcceptanceProjection(projected, acceptance, "one.example", pub); err != nil {
		t.Fatalf("verify exact projection: %v", err)
	}
}

func TestRequestAcceptanceProjection_membershipAndOrderAreClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	original := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, original)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]*rampv1.TransactionItem{
		"removed":   {original.GetItems()[0]},
		"reordered": {original.GetItems()[2], original.GetItems()[0]},
		"appended":  {original.GetItems()[0], original.GetItems()[2], original.GetItems()[0]},
	}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) {
			projected := &rampv1.TransactionRequest{
				IdempotencyKey: original.GetIdempotencyKey(),
				Requester:      original.GetRequester(),
				Items:          items,
			}
			if _, err := helpers.VerifyRequestAcceptanceProjection(projected, acceptance, "one.example", pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
				t.Fatalf("expected invalid request acceptance, got %v", err)
			}
		})
	}
}

func TestRequestAcceptance_tamperRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, req)
	if err != nil {
		t.Fatal(err)
	}
	acceptance.Payload.Items[0].Exchange = "evil.example"
	if _, err := helpers.VerifyRequestAcceptance(req, acceptance, pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
		t.Fatalf("expected invalid request acceptance, got %v", err)
	}
}

// A subrequest with zero items must be refused even when the signed set names
// zero items for that exchange: zero equals zero, the comparison loop runs no
// iterations, and without the guard a request addressed to nobody would report
// a verified projection.
func TestRequestAcceptanceProjection_emptySubrequestRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	original := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, original)
	if err != nil {
		t.Fatal(err)
	}
	empty := &rampv1.TransactionRequest{
		IdempotencyKey: original.GetIdempotencyKey(),
		Requester:      original.GetRequester(),
	}
	// "three.example" is absent from the signed set, so its projection is also
	// empty — the exact shape the guard exists to refuse.
	if _, err := helpers.VerifyRequestAcceptanceProjection(empty, acceptance, "three.example", pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
		t.Fatalf("expected invalid request acceptance, got %v", err)
	}
}

// mixedSpellingFixture spells one Exchange identity three ways the SDK treats
// as equal — bare, upper-cased, and with the HTTPS-default port written out —
// plus one genuinely different party.
func mixedSpellingFixture() *rampv1.TransactionRequest {
	return &rampv1.TransactionRequest{
		IdempotencyKey: "idem-1",
		Requester:      &rampv1.Requester{Id: "agent-1", Domain: "agent.example"},
		Items: []*rampv1.TransactionItem{
			{Offer: &rampv1.Offer{Signature: "sig-a", Exchange: "one.example"}},
			{Offer: &rampv1.Offer{Signature: "sig-b", Exchange: "ONE.EXAMPLE"}},
			{Offer: &rampv1.Offer{Signature: "sig-c", Exchange: "one.example:443"}},
			{Offer: &rampv1.Offer{Signature: "sig-d", Exchange: "two.example"}},
		},
	}
}

// Projection membership uses the CheckAudience identity rule, not raw string
// equality: an honest complete forward whose items spell one Exchange three
// equivalent ways verifies, whichever accepted spelling the verifier holds as
// its own identity.
func TestRequestAcceptanceProjection_equivalentSpellingsVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	original := mixedSpellingFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, original)
	if err != nil {
		t.Fatal(err)
	}
	projected := &rampv1.TransactionRequest{
		IdempotencyKey: original.GetIdempotencyKey(),
		Requester:      original.GetRequester(),
		Items:          original.GetItems()[:3],
	}
	for _, self := range []string{"one.example", "One.Example:443"} {
		if _, err := helpers.VerifyRequestAcceptanceProjection(projected, acceptance, self, pub); err != nil {
			t.Fatalf("verify mixed-spelling projection as %q: %v", self, err)
		}
	}
}

// With raw equality, a relay could remove the differently spelled item and
// still pass, because the count of raw-equal refs would shrink to match. Under
// the identity rule, dropping ANY of the three equivalent items is an
// incomplete projection and is refused.
func TestRequestAcceptanceProjection_equivalentSpellingRemovalRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	original := mixedSpellingFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, original)
	if err != nil {
		t.Fatal(err)
	}
	for drop := 0; drop < 3; drop++ {
		items := make([]*rampv1.TransactionItem, 0, 2)
		for i, item := range original.GetItems()[:3] {
			if i != drop {
				items = append(items, item)
			}
		}
		projected := &rampv1.TransactionRequest{
			IdempotencyKey: original.GetIdempotencyKey(),
			Requester:      original.GetRequester(),
			Items:          items,
		}
		if _, err := helpers.VerifyRequestAcceptanceProjection(projected, acceptance, "one.example", pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
			t.Fatalf("dropped item %d: expected invalid request acceptance, got %v", drop, err)
		}
	}
	// The sharpest cut: forward only the item whose spelling raw-equals the
	// verifier's own. Under raw equality the shrunken filter count would match
	// and this would pass; under the identity rule the projection is three
	// items and one is an incomplete forward.
	rawOnly := &rampv1.TransactionRequest{
		IdempotencyKey: original.GetIdempotencyKey(),
		Requester:      original.GetRequester(),
		Items:          original.GetItems()[:1],
	}
	if _, err := helpers.VerifyRequestAcceptanceProjection(rawOnly, acceptance, "one.example", pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
		t.Fatalf("raw-equal subset: expected invalid request acceptance, got %v", err)
	}
}

// The identity rule folds only the HTTPS-default port, and a value that is not
// a bare domain names nobody — neither may fail open.
func TestRequestAcceptanceProjection_portsAndMalformedValuesStayClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	t.Run("port 80 is a different identity", func(t *testing.T) {
		original := &rampv1.TransactionRequest{
			IdempotencyKey: "idem-1",
			Requester:      &rampv1.Requester{Id: "agent-1", Domain: "agent.example"},
			Items: []*rampv1.TransactionItem{
				{Offer: &rampv1.Offer{Signature: "sig-a", Exchange: "one.example"}},
				{Offer: &rampv1.Offer{Signature: "sig-b", Exchange: "one.example:80"}},
			},
		}
		acceptance, err := helpers.SignRequestAcceptance(priv, original)
		if err != nil {
			t.Fatal(err)
		}
		// Forwarding both items to one.example must fail: the :80 item belongs
		// to a different identity, so the projection for one.example is one item.
		if _, err := helpers.VerifyRequestAcceptanceProjection(original, acceptance, "one.example", pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
			t.Fatalf("expected invalid request acceptance, got %v", err)
		}
	})

	t.Run("malformed projection exchange is an error", func(t *testing.T) {
		original := requestAcceptanceFixture()
		acceptance, err := helpers.SignRequestAcceptance(priv, original)
		if err != nil {
			t.Fatal(err)
		}
		for _, self := range []string{"", "https://one.example"} {
			if _, err := helpers.VerifyRequestAcceptanceProjection(original, acceptance, self, pub); err == nil {
				t.Fatalf("projection exchange %q: expected an error", self)
			}
		}
	})

	t.Run("malformed forwarded offer exchange is refused", func(t *testing.T) {
		original := requestAcceptanceFixture()
		acceptance, err := helpers.SignRequestAcceptance(priv, original)
		if err != nil {
			t.Fatal(err)
		}
		projected := &rampv1.TransactionRequest{
			IdempotencyKey: original.GetIdempotencyKey(),
			Requester:      original.GetRequester(),
			Items: []*rampv1.TransactionItem{
				{Offer: &rampv1.Offer{Signature: "sig-a", Exchange: "https://one.example"}},
				{Offer: &rampv1.Offer{Signature: "sig-c", Exchange: "one.example"}},
			},
		}
		if _, err := helpers.VerifyRequestAcceptanceProjection(projected, acceptance, "one.example", pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
			t.Fatalf("expected invalid request acceptance, got %v", err)
		}
	})
}

// oversizedFixture returns a request carrying n items, every one signed-offer
// shaped, so payload construction succeeds and only the cap can refuse it.
func oversizedFixture(n int) *rampv1.TransactionRequest {
	items := make([]*rampv1.TransactionItem, n)
	for i := range items {
		items[i] = &rampv1.TransactionItem{
			Offer: &rampv1.Offer{Signature: "sig", Exchange: "one.example"},
		}
	}
	return &rampv1.TransactionRequest{
		IdempotencyKey: "idem-1",
		Requester:      &rampv1.Requester{Id: "agent-1", Domain: "agent.example"},
		Items:          items,
	}
}

// The canonicalization cap: a payload at the maximum still signs and verifies,
// one past it is refused before any canonical rendering happens, and the Go
// constant cannot drift from the wire rule.
func TestRequestAcceptance_itemCapEnforcedBeforeCanonicalization(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	atCap, err := helpers.SignRequestAcceptance(priv, oversizedFixture(helpers.MaxRequestAcceptanceItemsForTest))
	if err != nil {
		t.Fatalf("a payload at the maximum must sign: %v", err)
	}
	if _, err := helpers.VerifyRequestAcceptance(oversizedFixture(helpers.MaxRequestAcceptanceItemsForTest), atCap, pub); err != nil {
		t.Fatalf("a payload at the maximum must verify: %v", err)
	}

	over, err := helpers.RequestAcceptancePayload(oversizedFixture(helpers.MaxRequestAcceptanceItemsForTest + 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := helpers.CanonicalRequestAcceptanceBytes(over); err == nil {
		t.Fatal("expected the item cap to refuse maximum+1")
	}

	fd := (&rampv1.AgentRequestAcceptancePayload{}).ProtoReflect().Descriptor().Fields().ByName("items")
	rules, err := protovalidate.ResolveFieldRules(fd)
	if err != nil {
		t.Fatal(err)
	}
	if got := rules.GetRepeated().GetMaxItems(); got != uint64(helpers.MaxRequestAcceptanceItemsForTest) {
		t.Fatalf("wire repeated.max_items = %d, the helper enforces %d — the two bounds drifted",
			got, helpers.MaxRequestAcceptanceItemsForTest)
	}
}

// The signature is decoded and size-checked before canonicalization. The probe
// pairs an over-cap payload with a wrong-size signature: the signature refusal
// winning proves the cheap check ran first, so a caller whose signature cannot
// possibly verify never buys the canonical rendering of a large payload.
func TestRequestAcceptance_signatureCheckedBeforeCanonicalization(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, req)
	if err != nil {
		t.Fatal(err)
	}

	badHex := &rampv1.AgentRequestAcceptance{
		Payload:            acceptance.GetPayload(),
		Signature:          "not-hex",
		SignatureAlgorithm: acceptance.GetSignatureAlgorithm(),
	}
	if _, err := helpers.VerifyRequestAcceptance(req, badHex, pub); err == nil {
		t.Fatal("expected malformed signature hex to be refused")
	}

	overReq := oversizedFixture(helpers.MaxRequestAcceptanceItemsForTest + 1)
	overPayload, err := helpers.RequestAcceptancePayload(overReq)
	if err != nil {
		t.Fatal(err)
	}
	truncated := &rampv1.AgentRequestAcceptance{
		Payload:            overPayload,
		Signature:          "abcd", // valid hex, 2 bytes — not an Ed25519 signature
		SignatureAlgorithm: acceptance.GetSignatureAlgorithm(),
	}
	if _, err := helpers.VerifyRequestAcceptance(overReq, truncated, pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
		t.Fatalf("expected the size check to refuse before the cap could, got %v", err)
	}
}

// The envelope-binding block: a valid acceptance replayed under a request whose
// requester or idempotency key differs is refused before the signature is even
// checked, so an acceptance cannot be transplanted onto another request.
func TestRequestAcceptance_envelopeMismatchRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	cases := map[string]func(*rampv1.TransactionRequest){
		"different requester id":     func(r *rampv1.TransactionRequest) { r.Requester.Id = "agent-2" },
		"different requester domain": func(r *rampv1.TransactionRequest) { r.Requester.Domain = "other.example" },
		"different idempotency key":  func(r *rampv1.TransactionRequest) { r.IdempotencyKey = "idem-2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := requestAcceptanceFixture()
			acceptance, err := helpers.SignRequestAcceptance(priv, req)
			if err != nil {
				t.Fatal(err)
			}
			mutate(req)
			if _, err := helpers.VerifyRequestAcceptance(req, acceptance, pub); !errors.Is(err, helpers.ErrRequestAcceptanceSignatureInvalid) {
				t.Fatalf("expected invalid request acceptance, got %v", err)
			}
		})
	}
}

// The algorithm field is advisory but the verifier still refuses anything that
// does not name the one supported scheme, so a caller cannot smuggle a
// differently-signed envelope past a verifier that assumes Ed25519.
func TestRequestAcceptance_wrongAlgorithmRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := requestAcceptanceFixture()
	acceptance, err := helpers.SignRequestAcceptance(priv, req)
	if err != nil {
		t.Fatal(err)
	}
	acceptance.SignatureAlgorithm = "RS256"
	if _, err := helpers.VerifyRequestAcceptance(req, acceptance, pub); err == nil {
		t.Fatal("expected a refusal for a non-EdDSA algorithm")
	}
}

// notEd25519Signer satisfies helpers.Signer but reports an unsupported
// algorithm, standing in for a KMS configured with the wrong key type.
type notEd25519Signer struct{}

func (notEd25519Signer) KeyID() string     { return "kms.v1" }
func (notEd25519Signer) Algorithm() string { return "rsa-pss-sha512" }
func (notEd25519Signer) Sign(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("must not be reached")
}

// SignRequestAcceptanceWith is the face the connect client calls in production:
// it must produce an acceptance the verifier accepts, and refuse a signer whose
// algorithm is not Ed25519 before asking it to sign anything.
func TestSignRequestAcceptanceWith_roundTripAndAlgorithmGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := requestAcceptanceFixture()

	signer, err := helpers.NewEd25519Signer("agent.v1", priv)
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := helpers.SignRequestAcceptanceWith(context.Background(), signer, req)
	if err != nil {
		t.Fatalf("SignRequestAcceptanceWith: %v", err)
	}
	if _, err := helpers.VerifyRequestAcceptance(req, acceptance, pub); err != nil {
		t.Fatalf("signer-produced acceptance does not verify: %v", err)
	}

	if _, err := helpers.SignRequestAcceptanceWith(context.Background(), notEd25519Signer{}, req); !errors.Is(err, helpers.ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestAgentRequestAcceptancePayload_fieldSetIsPinned(t *testing.T) {
	want := []string{"items", "requester_id", "requester_domain", "idempotency_key"}
	fields := (&rampv1.AgentRequestAcceptancePayload{}).ProtoReflect().Descriptor().Fields()
	if fields.Len() != len(want) {
		t.Fatalf("AgentRequestAcceptancePayload has %d fields, want %d", fields.Len(), len(want))
	}
	for i, name := range want {
		if got := string(fields.Get(i).Name()); got != name {
			t.Errorf("field %d = %q, want %q", i+1, got, name)
		}
	}
}

func TestAgentRequestAcceptanceItem_fieldSetIsPinned(t *testing.T) {
	want := []string{"offer_sig", "exchange"}
	fields := (&rampv1.AgentRequestAcceptanceItem{}).ProtoReflect().Descriptor().Fields()
	if fields.Len() != len(want) {
		t.Fatalf("AgentRequestAcceptanceItem has %d fields, want %d", fields.Len(), len(want))
	}
	for i, name := range want {
		if got := string(fields.Get(i).Name()); got != name {
			t.Errorf("field %d = %q, want %q", i+1, got, name)
		}
	}
}
