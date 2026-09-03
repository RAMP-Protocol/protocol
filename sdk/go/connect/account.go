package connect

import (
	"context"
	"errors"
	"fmt"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// The account-setup verbs.
//
// An agent becomes KNOWN to an Exchange just by sending a signed request; to
// transact for paid content it must REGISTER, and the Exchange mints the opaque
// per-Exchange account handle it will resolve from the request signature on every
// later call. These two verbs are that role's whole surface.
//
// They route like a usage report, not like discovery. An account is per-Exchange,
// and which Exchange is the agent's choice PER CALL: a target routinely arrives at
// runtime — a denial names where to register — rather than from the operator's own
// configuration. So the destination is read off the request's own `exchange` field
// and resolved through that Exchange's own manifest, over the guarded leg, and
// there is no parameter a configured origin could be passed as.
//
// Neither message carries an idempotency_key, so neither verb takes CallOptions.
// That is the contract's choice rather than an omission: registering again for the
// same agent returns the same account handle, so a key would be ceremony rather
// than a guarantee.

// Register creates the calling agent's account at the Exchange the request names.
//
// The caller's identity is the request SIGNATURE. Nothing in the message says who
// is registering, and the business payload is not an identity claim — so a client
// with no signer can build this request and cannot usefully send it.
//
// Four bounds on registration_data are checked before anything is signed, in the
// order the contract fixes: top-level member count, nesting depth, whether the
// payload has a canonical JSON form at all, and the size of that form. They run
// here because a limit that exists to stop work belongs before the work it would
// stop, and because a payload breaking one is a MALFORMED request rather than a
// schema failure — a distinction the Exchange also makes.
//
// terms_digest is filled only when the caller left it UNSET. Submitting a
// registration states which terms the operator accepted, the request signature
// covers that echo, and the contract requires the value to come from a FRESHLY
// fetched manifest — a cached endpoint is fine, a cached digest is not. So the
// fill reads the Exchange's requirements through the uncached reader, which is
// also where the published data_schema comes from, and the payload is pre-checked
// against it before signing. A caller that sets the field is managing its own
// requirements and gets neither the fill nor the pre-check; proto3 presence is
// what lets "unset" and "deliberately empty" be different requests.
//
// The pre-check never becomes a local veto for a schema this SDK refuses. The
// contract is explicit that refusing locally and declining to send would turn a
// rule about reading a third party's document into a denial of service against
// the caller's own user, so an unusable schema is skipped and the Exchange's own
// enforcement decides. A schema that IS usable and that the payload fails is a
// different case: that is the pre-check working, and the request is refused here
// with the offending members named.
//
// Two manifest reads happen on a first registration — one cached, for the
// endpoint, and one fresh, for the digest. That is the contract's own split, and
// registration happens once per Exchange, so the extra fetch is cheap.
//
// A refused registration comes back as a non-OK call whose typed reason is
// readable through ErrorDetailFrom as a RegistrationFailure.
func (c *Client) Register(
	ctx context.Context, req *rampv1.RegisterRequest,
) (*rampv1.RegisterResponse, error) {
	const op = "register"
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	if err := requireRecipient(op, sent.GetExchange()); err != nil {
		return nil, err
	}
	if verdict := helpers.CheckRegistrationDataStruct(
		sent.GetRegistrationData()); verdict != helpers.RegistrationDataAccepted {
		return nil, malformed(op, fmt.Errorf("registration_data: %s", verdict))
	}
	if sent.TermsDigest == nil {
		if err := c.applyRegistrationRequirements(ctx, op, sent); err != nil {
			return nil, err
		}
	}
	endpoint, err := vetExchangeEndpoint(ctx, c.endpoints, sent.GetExchange(), op)
	if err != nil {
		return nil, err
	}
	resp, err := c.exchanges.clientFor(endpoint).Register(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// GetAccountStatus reports whether the calling agent's account at the named
// Exchange is active.
//
// The request carries no field identifying the caller — the Exchange resolves the
// account from the verified signature — so `exchange` is the only thing that says
// which account is being asked about. Accounts are per-Exchange, and that is not
// derivable from anything else in the message.
//
// An answer carrying an empty account handle is a NORMAL answer: it means this
// agent holds no account at that Exchange yet. The response also reports the terms
// revision the account accepted, which is what was agreed rather than what is
// published now; comparing the two is how an agent discovers that an operator's
// terms moved under an account it already holds.
//
// A caveat worth knowing before calling this in a loop. The request has no varying
// field, so two calls to the same Exchange inside one wall-clock second sign
// IDENTICAL bytes — signature timestamps have one-second resolution — and a peer
// screening replays on (key id, signature) refuses the second as a duplicate. This
// verb does not choose the freshness window for you, because a window is one
// instance per client rather than per call and the choice belongs to whoever built
// the client: pass core.MonotonicWindow through WithSignWindow when repeat calls
// are expected.
func (c *Client) GetAccountStatus(
	ctx context.Context, req *rampv1.GetAccountStatusRequest,
) (*rampv1.GetAccountStatusResponse, error) {
	const op = "get account status"
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	if err := requireRecipient(op, sent.GetExchange()); err != nil {
		return nil, err
	}
	endpoint, err := vetExchangeEndpoint(ctx, c.endpoints, sent.GetExchange(), op)
	if err != nil {
		return nil, err
	}
	resp, err := c.exchanges.clientFor(endpoint).GetAccountStatus(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// applyRegistrationRequirements reads what the Exchange asks of a registration and
// applies it to the request being built: the terms digest is echoed, and the
// payload is pre-checked against the published schema.
//
// A failed READ refuses the registration rather than sending without a digest.
// Guessing here is not the cautious option: an Exchange that publishes a digest
// refuses a registration that omits one, so sending anyway trades a local failure
// the caller can act on for a remote one it cannot.
//
// The read's own verdicts are classified the way the routing tier classifies its
// own — a value the Exchange or this deployment refused is final, anything else is
// a transport failure worth retrying — so a caller branches on one taxonomy
// whichever check declined.
func (c *Client) applyRegistrationRequirements(
	ctx context.Context, op string, sent *rampv1.RegisterRequest,
) error {
	reqs, err := c.requirements.ResolveRegistrationRequirements(ctx, sent.GetExchange())
	if err != nil {
		if errors.Is(err, helpers.ErrInvalidHost) ||
			errors.Is(err, resolvers.ErrExchangeNotPermitted) ||
			errors.Is(err, resolvers.ErrManifestNotExchange) {
			return notSent(op, err)
		}
		return &CallError{Kind: CallUnreachable, Op: op, Err: err}
	}
	sent.TermsDigest = reqs.TermsDigest
	// A nil validator reports no failures, which is the behaviour the contract
	// requires both when the Exchange publishes no schema and when it publishes one
	// this SDK refused. One branch, deliberately: distinguishing them here would be
	// distinguishing two cases the caller must treat the same.
	if fails := reqs.Schema.Validate(sent.GetRegistrationData().AsMap()); len(fails) > 0 {
		return malformed(op, fmt.Errorf(
			"registration_data does not match the schema %s publishes: %s",
			sent.GetExchange(), renderFieldErrors(fails)))
	}
	return nil
}

// renderFieldErrors names the offending members in a refusal a human reads. The
// same failures travel to a caller as a typed detail when an Exchange refuses;
// this is the local pre-check's own rendering, and it stays a sentence because
// nothing branches on it.
func renderFieldErrors(fails []*rampv1.RegistrationFieldError) string {
	out := ""
	for i, f := range fails {
		if i > 0 {
			out += "; "
		}
		out += f.GetPath() + ": " + f.GetError()
	}
	return out
}
