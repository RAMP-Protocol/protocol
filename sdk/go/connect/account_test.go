package connect_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// ---------------------------------------------------------------------------
// Origin
// ---------------------------------------------------------------------------

// recordingAccount answers the two account RPCs and keeps what arrived, so a test
// can assert on the message that actually reached the wire rather than on the one
// the caller handed in.
type recordingAccount struct {
	rampv1connect.UnimplementedExchangeServiceHandler

	gotRegister *rampv1.RegisterRequest
	gotStatus   *rampv1.GetAccountStatusRequest
	registers   int

	billingRef string
	active     bool
	// refuse, when set, is returned instead of an answer, so a test can drive the
	// typed-refusal path.
	refuse error
}

func (a *recordingAccount) Register(
	_ context.Context, req *connectrpc.Request[rampv1.RegisterRequest],
) (*connectrpc.Response[rampv1.RegisterResponse], error) {
	a.gotRegister = req.Msg
	a.registers++
	if a.refuse != nil {
		return nil, a.refuse
	}
	return connectrpc.NewResponse(&rampv1.RegisterResponse{
		Ver: helpers.ProtocolVersion, BillingRef: a.billingRef, Active: a.active,
	}), nil
}

func (a *recordingAccount) GetAccountStatus(
	_ context.Context, req *connectrpc.Request[rampv1.GetAccountStatusRequest],
) (*connectrpc.Response[rampv1.GetAccountStatusResponse], error) {
	a.gotStatus = req.Msg
	if a.refuse != nil {
		return nil, a.refuse
	}
	return connectrpc.NewResponse(&rampv1.GetAccountStatusResponse{
		Ver: helpers.ProtocolVersion, BillingRef: a.billingRef, Active: a.active,
	}), nil
}

// registrationData builds the Struct a RegisterRequest carries.
func registrationData(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("build registration_data: %v", err)
	}
	return s
}

const digestAB = "sha256:abababababababababababababababababababababababababababababababab"

// legalEntitySchema requires one member, so a payload without it fails the
// pre-check and a payload with it passes.
const legalEntitySchema = `{"type":"object","required":["legal_entity"],` +
	`"properties":{"legal_entity":{"type":"string"}}}`

// bothShapesSchema fails two ways at once: a required member is absent, which is a
// whole-object violation the wire reports with an EMPTY path, and a member that IS
// present breaks its pattern, which is reported against its own pointer. One
// refusal carrying both is what a consumer has to render, and the empty path is the
// half that is easiest to render wrong.
const bothShapesSchema = `{"type":"object","required":["legal_entity"],` +
	`"properties":{"vat_id":{"type":"string","pattern":"^[A-Z]{2}[0-9]+$"}}}`

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

// The whole first-registration path: the request is signed, `ver` is stamped, the
// caller's recipient survives, and terms_digest is echoed from the manifest the
// Exchange served on THIS call.
func TestRegister_EchoesTheFreshlyFetchedTermsDigest(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{billingRef: "acct-1", active: true}
	digest := digestAB
	domain, _ := selfAdvertisingExchangeWith(t, sig, origin, func() map[string]any {
		return map[string]any{"terms_digest": digest}
	})

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	req := &rampv1.RegisterRequest{
		Exchange:         domain,
		RegistrationData: registrationData(t, map[string]any{"legal_entity": "Acme"}),
	}
	resp, err := client.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.GetBillingRef() != "acct-1" || !resp.GetActive() {
		t.Fatalf("response = %v", resp)
	}
	if got := origin.gotRegister.GetTermsDigest(); got != digest {
		t.Fatalf("terms_digest on the wire = %q, want the manifest's %q", got, digest)
	}
	if got := origin.gotRegister.GetVer(); got != helpers.ProtocolVersion {
		t.Fatalf("ver = %q, want %q", got, helpers.ProtocolVersion)
	}
	if got := origin.gotRegister.GetExchange(); got != domain {
		t.Fatalf("exchange = %q, want the caller's %q", got, domain)
	}
	// The caller's message crossed a package boundary as an argument, not as a
	// buffer to fill in.
	if req.TermsDigest != nil {
		t.Fatalf("the caller's request was modified: terms_digest = %q", *req.TermsDigest)
	}
}

// A caller that sets the digest is managing its own requirements: its value is
// sent unchanged and no requirements read happens at all.
func TestRegister_ACallerSuppliedDigestSuppressesTheRead(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{billingRef: "acct-1"}
	domain, wkHits := selfAdvertisingExchangeWith(t, sig, origin, func() map[string]any {
		return map[string]any{"terms_digest": digestAB}
	})

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	mine := "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	if _, err := client.Register(context.Background(), &rampv1.RegisterRequest{
		Exchange:    domain,
		TermsDigest: &mine,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := origin.gotRegister.GetTermsDigest(); got != mine {
		t.Fatalf("terms_digest = %q, want the caller's %q", got, mine)
	}
	// One manifest fetch, for the endpoint. The requirements read did not happen.
	if n := wkHits.Load(); n != 1 {
		t.Fatalf("manifest fetches = %d, want 1 (endpoint only)", n)
	}
}

// An Exchange publishing no digest is the ordinary pass-through case: the field
// stays absent rather than becoming an empty string, which is a different request.
func TestRegister_NoPublishedDigestLeavesTheFieldAbsent(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{billingRef: "acct-1"}
	domain, _ := selfAdvertisingExchange(t, sig, origin)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	if _, err := client.Register(context.Background(), &rampv1.RegisterRequest{
		Exchange: domain,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if origin.gotRegister.TermsDigest != nil {
		t.Fatalf("terms_digest = %q, want absent", *origin.gotRegister.TermsDigest)
	}
}

// The published schema is the client's pre-check, and it runs before signing: a
// payload the Exchange would refuse never reaches the wire.
func TestRegister_PreChecksThePublishedSchema(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{billingRef: "acct-1"}
	domain, _ := selfAdvertisingExchangeWith(t, sig, origin, func() map[string]any {
		return map[string]any{
			"account_registration": map[string]any{
				"data_schema": json.RawMessage(legalEntitySchema),
			},
		}
	})

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.Register(context.Background(), &rampv1.RegisterRequest{
		Exchange:         domain,
		RegistrationData: registrationData(t, map[string]any{"trading_name": "Acme"}),
	})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallMalformed {
		t.Fatalf("err = %v, want a malformed CallError", err)
	}
	if !strings.Contains(cerr.Error(), "legal_entity") {
		t.Fatalf("refusal does not name the offending member: %v", cerr)
	}
	if origin.gotRegister != nil {
		t.Fatal("a payload refused by the local pre-check reached the wire")
	}

	// The conforming payload goes through against the same schema.
	if _, err := client.Register(context.Background(), &rampv1.RegisterRequest{
		Exchange:         domain,
		RegistrationData: registrationData(t, map[string]any{"legal_entity": "Acme"}),
	}); err != nil {
		t.Fatalf("conforming payload refused: %v", err)
	}
}

// refusedByTheSchema drives a pre-check refusal against schema, so the tests below
// share one arrangement and differ only in what they read off the failure.
func refusedByTheSchema(
	t *testing.T, schema string, payload map[string]any,
) (*rampconnect.CallError, *recordingAccount) {
	t.Helper()
	sig := newSigningFixture(t)
	origin := &recordingAccount{billingRef: "acct-1"}
	domain, _ := selfAdvertisingExchangeWith(t, sig, origin, func() map[string]any {
		return map[string]any{
			"account_registration": map[string]any{
				"data_schema": json.RawMessage(schema),
			},
		}
	})

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)
	_, err := client.Register(context.Background(), &rampv1.RegisterRequest{
		Exchange:         domain,
		RegistrationData: registrationData(t, payload),
	})

	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallMalformed {
		t.Fatalf("err = %v, want a malformed CallError", err)
	}
	if origin.gotRegister != nil {
		t.Fatal("a payload refused by the local pre-check reached the wire")
	}
	return cerr, origin
}

// What the pre-check computed is what the caller gets. An Exchange attaches this
// same list, from this same validator, when it refuses the same payload — so a
// consumer that renders one refusal renders both, and nothing has to parse the
// members back out of a sentence.
func TestRegister_PreCheckRefusalCarriesItsFieldErrors(t *testing.T) {
	cerr, _ := refusedByTheSchema(t, bothShapesSchema, map[string]any{"vat_id": "de1"})

	detail, ok := rampconnect.ErrorDetailFrom(cerr)
	if !ok {
		t.Fatalf("the pre-check refusal carries no typed detail: %v", cerr)
	}
	if got := detail.GetRegistrationFailure().GetReason(); got !=
		rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA {
		t.Fatalf("reason = %v, want INVALID_REGISTRATION_DATA", got)
	}

	// The PATHS are what this asserts, never the constraint prose beside them: that
	// text comes from each language's validator library, and the contract calls it
	// non-authoritative for exactly that reason.
	var paths []string
	for _, f := range detail.GetRegistrationFailure().GetFieldErrors() {
		paths = append(paths, f.GetPath())
	}
	if got, want := strings.Join(paths, ","), ",/vat_id"; got != want {
		t.Fatalf("field-error paths = %q, want %q", got, want)
	}
}

// An empty path addresses the whole object, which is how a missing required member
// is reported. Rendering a bare ": ..." there would read as a member with no name.
func TestRegister_ARootViolationRendersWithNoMemberName(t *testing.T) {
	cerr, _ := refusedByTheSchema(t, bothShapesSchema, map[string]any{"vat_id": "de1"})

	msg := cerr.Error()
	if strings.Contains(msg, "publishes: : ") {
		t.Fatalf("a whole-object violation rendered as a member with no name: %v", msg)
	}
	// The member that HAS a name still carries it, so the fix did not drop the
	// separator everywhere.
	if !strings.Contains(msg, "/vat_id: ") {
		t.Fatalf("refusal does not address the offending member: %v", msg)
	}
}

// refusingRequirements is a reader that declines every read with one error, so the
// classification of that error is the only thing the test varies.
type refusingRequirements struct{ err error }

func (r refusingRequirements) ResolveRegistrationRequirements(
	_ context.Context, _ string,
) (resolvers.RegistrationRequirements, error) {
	return resolvers.RegistrationRequirements{}, r.err
}

// A failed READ is classified the way the routing tier classifies its own: a value
// this deployment or the Exchange refused is FINAL, anything else is a transport
// failure worth retrying. Without the split a caller retries a refusal forever.
//
// All three verdicts are reachable only through an INJECTED reader — the verb's own
// recipient check runs the host rule first, and the SDK's reader applies the other
// two itself — which is exactly why they need a test: nothing else exercises them,
// and a consumer that injects a reader is the case this classification exists for.
func TestRegister_ClassifiesARefusedRequirementsRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want rampconnect.CallErrorKind
	}{
		{"not a host", fmt.Errorf("%w: %q is not a bare domain",
			helpers.ErrInvalidHost, "exchange.test/path"), rampconnect.CallNotSent},
		{"this deployment refused the host", fmt.Errorf("%w: blocked",
			resolvers.ErrExchangeNotPermitted), rampconnect.CallNotSent},
		{"the document is not an Exchange's", fmt.Errorf("%w: wrong role",
			resolvers.ErrManifestNotExchange), rampconnect.CallNotSent},
		{"the read never completed", errors.New("connection reset"),
			rampconnect.CallUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := newSigningFixture(t)
			origin := &recordingAccount{billingRef: "acct-1"}
			domain, _ := selfAdvertisingExchange(t, sig, origin)

			client := rampconnect.NewClient("http://home.invalid",
				append(allowLoopback(t),
					rampconnect.WithSigner(sig.signer),
					rampconnect.WithRegistrationRequirements(refusingRequirements{tc.err}),
				)...)

			_, err := client.Register(context.Background(),
				&rampv1.RegisterRequest{Exchange: domain})

			var cerr *rampconnect.CallError
			if !errors.As(err, &cerr) || cerr.Kind != tc.want {
				t.Fatalf("err = %v, want kind %v", err, tc.want)
			}
			if origin.gotRegister != nil {
				t.Fatal("a registration whose requirements read failed reached the wire")
			}
		})
	}
}

// A schema this SDK refuses must not become a local veto. Refusing here would turn
// a rule about reading a third party's document into a denial of service against
// the caller's own user, so the request is sent and the Exchange decides.
func TestRegister_AnUnusableSchemaDoesNotBlockTheSend(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{billingRef: "acct-1"}
	domain, _ := selfAdvertisingExchangeWith(t, sig, origin, func() map[string]any {
		return map[string]any{
			"account_registration": map[string]any{
				"data_schema": json.RawMessage(
					`{"$schema":"https://json-schema.org/draft/2019-09/schema","type":"object"}`),
			},
		}
	})

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	if _, err := client.Register(context.Background(), &rampv1.RegisterRequest{
		Exchange:         domain,
		RegistrationData: registrationData(t, map[string]any{"anything": "goes"}),
	}); err != nil {
		t.Fatalf("an unusable published schema blocked the send: %v", err)
	}
	if origin.gotRegister == nil {
		t.Fatal("the request never reached the Exchange")
	}
}

// The four bounds on registration_data are checked before anything is signed, and
// a breach is a MALFORMED request rather than a schema failure.
func TestRegister_RefusesAnOutOfBoundsPayloadBeforeSigning(t *testing.T) {
	sig := newSigningFixture(t)

	tooManyMembers := map[string]any{}
	for i := 0; i <= helpers.MaxRegistrationDataMembers; i++ {
		tooManyMembers[string(rune('a'+i%26))+strings.Repeat("x", i)] = "v"
	}
	// One container per level, past the depth cap.
	deep := map[string]any{"leaf": "v"}
	for i := 0; i < helpers.MaxRegistrationDataDepth+2; i++ {
		deep = map[string]any{"n": deep}
	}

	for _, tc := range []struct {
		name string
		data map[string]any
	}{
		{"too many top-level members", tooManyMembers},
		{"nested past the depth cap", deep},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := &recordingAccount{billingRef: "acct-1"}
			domain, wkHits := selfAdvertisingExchange(t, sig, origin)
			client := rampconnect.NewClient("http://home.invalid",
				append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

			_, err := client.Register(context.Background(), &rampv1.RegisterRequest{
				Exchange:         domain,
				RegistrationData: registrationData(t, tc.data),
			})
			var cerr *rampconnect.CallError
			if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallMalformed {
				t.Fatalf("err = %v, want a malformed CallError", err)
			}
			if origin.gotRegister != nil {
				t.Fatal("an out-of-bounds payload reached the wire")
			}
			// A limit that exists to stop work runs before the work it would stop.
			if n := wkHits.Load(); n != 0 {
				t.Fatalf("manifest fetches = %d, want 0; the bound ran after the fetch", n)
			}
		})
	}
}

// A repeat registration is answered from the stored record and returns the same
// account handle. The client neither mints nor stamps an idempotency key, because
// the message carries none.
func TestRegister_ARepeatReturnsTheSameHandle(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{billingRef: "acct-1", active: true}
	domain, _ := selfAdvertisingExchange(t, sig, origin)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	first, err := client.Register(context.Background(), &rampv1.RegisterRequest{Exchange: domain})
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	second, err := client.Register(context.Background(), &rampv1.RegisterRequest{Exchange: domain})
	if err != nil {
		t.Fatalf("repeat register: %v", err)
	}
	if first.GetBillingRef() != second.GetBillingRef() {
		t.Fatalf("repeat returned %q, want %q", second.GetBillingRef(), first.GetBillingRef())
	}
	if origin.registers != 2 {
		t.Fatalf("Exchange saw %d registrations, want 2", origin.registers)
	}
}

// A refused registration travels as a non-OK call carrying a typed reason, and the
// caller reads it through the same accessor every other verb uses.
func TestRegister_TypedRefusalIsReadableThroughErrorDetailFrom(t *testing.T) {
	sig := newSigningFixture(t)
	detail := helpers.RegistrationFailureDetail(
		"ramp.v1.ExchangeService", "terms have moved",
		rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE)
	refusal := rampserver.AttachDetail(
		connectrpc.NewError(connectrpc.CodeFailedPrecondition, errors.New("stale terms")), detail)

	origin := &recordingAccount{refuse: refusal}
	domain, _ := selfAdvertisingExchange(t, sig, origin)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.Register(context.Background(), &rampv1.RegisterRequest{Exchange: domain})
	got, ok := rampconnect.ErrorDetailFrom(err)
	if !ok {
		t.Fatalf("no typed detail on %v", err)
	}
	if got.GetRegistrationFailure().GetReason() !=
		rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE {
		t.Fatalf("reason = %v", got.GetRegistrationFailure().GetReason())
	}
}

// ---------------------------------------------------------------------------
// GetAccountStatus
// ---------------------------------------------------------------------------

// An empty account handle is a NORMAL answer: this agent holds no account there
// yet. It is not a failure and must not be reported as one.
func TestGetAccountStatus_NoAccountIsANormalAnswer(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{}
	domain, _ := selfAdvertisingExchange(t, sig, origin)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	resp, err := client.GetAccountStatus(context.Background(),
		&rampv1.GetAccountStatusRequest{Exchange: domain})
	if err != nil {
		t.Fatalf("get account status: %v", err)
	}
	if resp.GetBillingRef() != "" || resp.GetActive() {
		t.Fatalf("response = %v, want an empty, inactive account", resp)
	}
	if got := origin.gotStatus.GetVer(); got != helpers.ProtocolVersion {
		t.Fatalf("ver = %q, want %q", got, helpers.ProtocolVersion)
	}
	if got := origin.gotStatus.GetExchange(); got != domain {
		t.Fatalf("exchange = %q, want %q", got, domain)
	}
}

// ---------------------------------------------------------------------------
// Both verbs
// ---------------------------------------------------------------------------

// The recipient is the caller's to set, and a request naming none — or naming
// something that is not a bare domain — is refused before anything is signed or
// sent. The shape rule is the contract's, which the routing tier's weaker
// dialability question is not a substitute for.
func TestAccountVerbs_RefuseAnUnaddressedRequest(t *testing.T) {
	sig := newSigningFixture(t)
	client := rampconnect.NewClient("http://home.invalid", rampconnect.WithSigner(sig.signer))

	for _, exchange := range []string{"", "https://exchange.test", "exchange.test/path", "ex_change.test"} {
		name := exchange
		if name == "" {
			name = "no recipient at all"
		}
		t.Run(name, func(t *testing.T) {
			_, err := client.Register(context.Background(),
				&rampv1.RegisterRequest{Exchange: exchange})
			assertNotSent(t, err)
			_, err = client.GetAccountStatus(context.Background(),
				&rampv1.GetAccountStatusRequest{Exchange: exchange})
			assertNotSent(t, err)
		})
	}
}

func assertNotSent(t *testing.T, err error) {
	t.Helper()
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallNotSent {
		t.Fatalf("err = %v, want CallNotSent", err)
	}
	if cerr.Status != 0 {
		t.Fatalf("a refusal that never reached the wire carries status %d", cerr.Status)
	}
}

// A nil request is a request that could not be assembled, not one the peer
// refused.
func TestAccountVerbs_RefuseANilRequest(t *testing.T) {
	client := rampconnect.NewClient("http://home.invalid")
	var cerr *rampconnect.CallError

	_, err := client.Register(context.Background(), nil)
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallMalformed {
		t.Fatalf("register: err = %v, want CallMalformed", err)
	}
	_, err = client.GetAccountStatus(context.Background(), nil)
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallMalformed {
		t.Fatalf("get account status: err = %v, want CallMalformed", err)
	}
}

// The caller's own protocol version wins: `ver` is filled only when empty.
func TestAccountVerbs_CallerVerWins(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingAccount{}
	domain, _ := selfAdvertisingExchange(t, sig, origin)
	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	if _, err := client.Register(context.Background(),
		&rampv1.RegisterRequest{Ver: "9.9", Exchange: domain}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := origin.gotRegister.GetVer(); got != "9.9" {
		t.Fatalf("register ver = %q, want the caller's 9.9", got)
	}
	if _, err := client.GetAccountStatus(context.Background(),
		&rampv1.GetAccountStatusRequest{Ver: "9.9", Exchange: domain}); err != nil {
		t.Fatalf("get account status: %v", err)
	}
	if got := origin.gotStatus.GetVer(); got != "9.9" {
		t.Fatalf("status ver = %q, want the caller's 9.9", got)
	}
}

// A signed call is never redirected: following one would re-sign the caller's
// request for a target the peer chose.
func TestAccountVerbs_RefuseARedirect(t *testing.T) {
	sig := newSigningFixture(t)
	domain, _ := loopbackManifestServerWith(t, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, "http://elsewhere.invalid/", http.StatusFound)
		}), nil)

	client := rampconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), rampconnect.WithSigner(sig.signer))...)

	_, err := client.GetAccountStatus(context.Background(),
		&rampv1.GetAccountStatusRequest{Exchange: domain})
	var cerr *rampconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallUnreachable {
		t.Fatalf("err = %v, want CallUnreachable", err)
	}
}

// A status request carries no varying field, so two calls inside one wall-clock
// second sign IDENTICAL bytes — signature timestamps have one-second resolution —
// and a peer screening replays on (key id, signature) refuses the second.
//
// This is a behaviour test rather than a corpus row on purpose: the hazard cannot
// be expressed as bytes, because demonstrating it needs two sequential calls
// against a server holding a replay store.
//
// The SDK does not pick the window for the caller. A window is one instance per
// CLIENT rather than per call — it carries the running maximum that makes each
// signature unique — so the choice belongs to whoever builds the client, and both
// halves of that choice are pinned here.
func TestGetAccountStatus_IdenticalRequestsCollideUnlessTheWindowMoves(t *testing.T) {
	// One reading, shared by both calls, so they land in the SAME second — which is
	// the condition under test. It has to be a real instant rather than a fixed
	// one, because the server verifies freshness against its own clock.
	now := time.Now()
	frozen := func() time.Time { return now }

	serve := func(t *testing.T, sig signingFixture, svc rampv1connect.ExchangeServiceHandler) string {
		t.Helper()
		path, h := rampserver.NewExchangeServiceHandler(svc,
			rampserver.WithKeyResolver(sig.resolver),
			rampserver.WithReplayStore(newMemReplayStore()))
		rpc := http.NewServeMux()
		rpc.Handle(path, h)
		domain, _ := loopbackManifestServerWith(t, rpc, nil)
		return domain
	}

	call := func(t *testing.T, window core.Window) error {
		t.Helper()
		sig := newSigningFixture(t)
		domain := serve(t, sig, &recordingAccount{})
		client := rampconnect.NewClient("http://home.invalid", append(allowLoopback(t),
			rampconnect.WithSigner(sig.signer),
			rampconnect.WithSignWindow(window),
		)...)
		req := &rampv1.GetAccountStatusRequest{Exchange: domain}
		if _, err := client.GetAccountStatus(context.Background(), req); err != nil {
			t.Fatalf("first call: %v", err)
		}
		_, err := client.GetAccountStatus(context.Background(), req)
		return err
	}

	t.Run("a plain clock window collides", func(t *testing.T) {
		err := call(t, core.ClockWindow(frozen, 5*time.Minute))
		if err == nil {
			t.Fatal("the second identical call was accepted; the hazard this documents is gone " +
				"and the verb doc plus the monotonic case below need revisiting")
		}
		var cerr *rampconnect.CallError
		if !errors.As(err, &cerr) || cerr.Kind != rampconnect.CallRefused {
			t.Fatalf("err = %v, want a refusal from the peer", err)
		}
	})

	t.Run("a monotonic window does not", func(t *testing.T) {
		if err := call(t, core.MonotonicWindow(frozen, 5*time.Minute)); err != nil {
			t.Fatalf("the second call was refused under a monotonic window: %v", err)
		}
	})
}
