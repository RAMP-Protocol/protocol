package connect_test

// Client-request golden-vector emitter: where each verb sends, and what it stamps.
//
// "The same verbs, with the same names" is the whole claim the three clients make to each
// other, and two things have to be identical for it to hold. The ADDRESS — a Connect
// unary path is `/<fully-qualified service>/<method>`, so a verb that picks a different
// method name reaches a different RPC, or none. And the ENVELOPE — `ver` and the
// idempotency key are stamped fill-when-empty, because the key identifies the ACTION
// rather than the attempt and a caller who mints their own for their own dedup must not
// have it discarded, or every retry of theirs is counted as a second purchase.
//
// Neither is visible from the type signatures the parity map compares. A client can
// export `reportUsage` and send it to the wrong method, or overwrite a caller's key, and
// nothing about the exported surface says so.
//
// What is NOT pinned is the body's bytes. Go reaches the wire through protojson while the
// two JSON clients build the object directly, so the same message legitimately serializes
// differently — an emit-unpopulated rendering carries zero-valued fields the others omit.
// The corpus therefore records the envelope PROJECTION, which is the part that is a
// decision rather than an encoding.
//
// Vectors are captured by driving the REAL client against a server that records what
// arrived, so this records what the oracle does rather than a description of it.
//
// Verification no-op by default; (re)writes under RAMP_UPDATE_VECTORS=1. TEST
// INFRASTRUCTURE.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/vectorio"
)

const clientRequestVectorsPath = "testdata/client-request-vectors.json"

// clientRequestVector is one verb's destination and stamped envelope.
type clientRequestVector struct {
	Name string `json:"name"`
	//: The verb, spelled as the API-surface design names it. The three clients spell it
	//: in their own casing (reportUsage / report_usage / ReportUsage); this is the one
	//: name they all mean.
	Verb string `json:"verb"`
	//: The Connect unary path the call is sent to, which every client must reproduce.
	Path string `json:"path"`
	//: The protocol version the client stamped.
	Ver string `json:"ver"`
	//: The idempotency key on the wire when it was the CALLER's or PINNED. Empty means
	//: the client minted one, whose value is fresh per call and so cannot be recorded —
	//: `key_minted` says which of the two happened.
	IdempotencyKey string `json:"idempotency_key"`
	//: Whether the client minted a key rather than carrying one it was given.
	KeyMinted bool `json:"key_minted"`
	//: The requester the client forwarded, empty when the verb carries none.
	RequesterID string `json:"requester_id"`
}

// TestGenerateClientRequestVectors emits the client-request golden corpus.
func TestGenerateClientRequestVectors(t *testing.T) {
	doc := map[string]any{
		"note": "Where each client verb sends and what it stamps, captured from the real " +
			"Go client. The body's BYTES are deliberately not pinned: Go serializes " +
			"through protojson and the JSON clients build the object directly, so the " +
			"same message legitimately renders differently.",
		"vectors": buildClientRequestVectors(t),
	}
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(clientRequestVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", clientRequestVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(clientRequestVectorsPath, doc)
	if err != nil {
		t.Fatalf("read %s: %v", clientRequestVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with RAMP_UPDATE_VECTORS=1 to regenerate",
			clientRequestVectorsPath)
	}
}

// capturedRequest is what the recording server saw.
type capturedRequest struct {
	path string
	body map[string]any
}

// recordingOrigin answers every RAMP method with an empty JSON object and records the
// path and body it was given. It is a bare handler rather than a generated one because
// what is under test is what the CLIENT sent, and a generated handler would parse the
// body away before this could read it.
func recordingOrigin(t *testing.T, seen *capturedRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.path = r.URL.Path
		seen.body = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&seen.body)
		w.Header().Set("Content-Type", helpers.ContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
}

func buildClientRequestVectors(t *testing.T) []clientRequestVector {
	t.Helper()
	requester := &rampv1.Requester{
		Id: "agent-1", Domain: "agent.test", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	// The offer-derived leg dials a loopback recorder here. That leg exists precisely
	// because the address comes off a signed message rather than configuration, and its
	// rule has its own corpus next door; what this one records is the path and the
	// envelope, so the guard is stood down and the endpoint is fixed at the recorder.
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")

	// The client must speak the RAMP JSON wire for the recording server to read what it
	// sent, and in the naming the contract uses: connect-go's own JSON codec renders the
	// lowerCamelCase json_name alias, which is out of contract.
	baseOpts := []rampconnect.ClientOption{
		rampconnect.WithRequester(requester),
		rampconnect.WithClientOptions(
			connectrpc.WithCodec(rampserver.EmitUnpopulatedJSONCodec()),
		),
	}

	var out []clientRequestVector
	// The exchange domain a report names must be the host its endpoint is on — the
	// same-host rule is what stops an offer redirecting a signed call — so the recorder's
	// own host is what the offer-derived verbs address. It carries a port, which is why
	// none of the recorded fields is the exchange.
	capture := func(name, verb string, run func(client *rampconnect.Client, exchange string) error) {
		t.Helper()
		var seen capturedRequest
		srv := recordingOrigin(t, &seen)
		defer srv.Close()
		host := strings.TrimPrefix(srv.URL, "http://")
		opts := append(append([]rampconnect.ClientOption{}, baseOpts...),
			rampconnect.WithEndpointResolver(fixedEndpoint{endpoint: srv.URL}))
		if err := run(rampconnect.NewClient(srv.URL, opts...), host); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		key, _ := seen.body["idempotency_key"].(string)
		ver, _ := seen.body["ver"].(string)
		out = append(out, clientRequestVector{
			Name: name, Verb: verb, Path: seen.path, Ver: ver,
			IdempotencyKey: pinnedOrMinted(name, key),
			KeyMinted:      key != "" && pinnedOrMinted(name, key) == "",
			RequesterID:    requesterIDOf(seen.body),
		})
	}

	capture("discover", "discover", func(c *rampconnect.Client, exchange string) error {
		_, err := c.Discover(context.Background(), &rampv1.ResourceQuery{Exchange: exchange})
		return err
	})
	capture("discover_caller_ver_wins", "discover", func(c *rampconnect.Client, exchange string) error {
		_, err := c.Discover(context.Background(),
			&rampv1.ResourceQuery{Exchange: exchange, Ver: "9.9"})
		return err
	})
	capture("report_usage_key_minted", "reportUsage", func(c *rampconnect.Client, exchange string) error {
		_, err := c.ReportUsage(context.Background(),
			&rampv1.UsageReport{Exchange: exchange, TransactionId: "t-1"})
		return err
	})
	capture("report_usage_caller_key_wins", "reportUsage", func(c *rampconnect.Client, exchange string) error {
		_, err := c.ReportUsage(context.Background(), &rampv1.UsageReport{
			Exchange: exchange, TransactionId: "t-1", IdempotencyKey: pinnedKey,
		})
		return err
	})
	capture("dispute_key_pinned", "dispute", func(c *rampconnect.Client, exchange string) error {
		_, err := c.Dispute(context.Background(), &rampv1.DisputeRequest{
			Exchange:      exchange,
			TransactionId: "t-1",
			ReportId:      "r-1",
			Reason:        rampv1.DisputeReason_DISPUTE_REASON_DELIVERY_FAILED,
		}, rampconnect.WithIdempotencyKey(pinnedKey))
		return err
	})
	out = append(out, executeVector(t, baseOpts))
	out = append(out, brokerResolveVector(t, baseOpts))
	out = append(out, catalogVectors(t, baseOpts)...)
	return out
}

// catalogVectors captures the publisher's three verbs, which live on their own
// client because CatalogService is its own address — an Exchange advertises it
// separately from the ExchangeService endpoint — and its caller is a different
// party with a different key. They carry no idempotency key by design (the catalog
// upsert and delete are naturally idempotent, so a key there would be ceremony)
// and forward no requester (the caller is named by caller_id), so both columns
// record empty: a client that minted a key or stamped the requester it was built
// with would move them.
func catalogVectors(t *testing.T, baseOpts []rampconnect.ClientOption) []clientRequestVector {
	t.Helper()
	var out []clientRequestVector
	capture := func(name, verb string, run func(c *rampconnect.CatalogClient, exchange string) error) {
		t.Helper()
		var seen capturedRequest
		srv := recordingOrigin(t, &seen)
		defer srv.Close()
		host := strings.TrimPrefix(srv.URL, "http://")
		if err := run(rampconnect.NewCatalogClient(srv.URL, baseOpts...), host); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ver, _ := seen.body["ver"].(string)
		key, _ := seen.body["idempotency_key"].(string)
		out = append(out, clientRequestVector{
			Name: name, Verb: verb, Path: seen.path, Ver: ver,
			IdempotencyKey: key, KeyMinted: false, RequesterID: requesterIDOf(seen.body),
		})
	}
	entry := &rampv1.ResourceEntry{Domain: "publisher.test", Path: "/x", Terms: []*rampv1.LicenseTerm{{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0"},
	}}}
	capture("push_resources", "pushResources", func(c *rampconnect.CatalogClient, exchange string) error {
		_, err := c.PushResources(context.Background(), &rampv1.PushResourcesRequest{
			Exchange: exchange, TenantId: "tenant-1", CallerId: "publisher.test",
			Entries: []*rampv1.ResourceEntry{entry},
		})
		return err
	})
	capture("remove_resources", "removeResources", func(c *rampconnect.CatalogClient, exchange string) error {
		_, err := c.RemoveResources(context.Background(), &rampv1.RemoveResourcesRequest{
			Exchange: exchange, TenantId: "tenant-1", Paths: []string{"/x"},
		})
		return err
	})
	capture("refresh_catalog", "refreshCatalog", func(c *rampconnect.CatalogClient, exchange string) error {
		_, err := c.RefreshCatalog(context.Background(), &rampv1.RefreshCatalogRequest{
			Exchange: exchange, TenantId: "tenant-1",
		})
		return err
	})
	return out
}

// executeVector captures the purchase, which is the verb with the most envelope of all:
// it BUILDS the whole request rather than stamping a caller's, so `ver`, the key and the
// requester are all the client's own. It is captured separately because it needs a
// verified offer and a signer, which the discovery verbs do not.
//
// `fetch` has no vector here and no envelope to record: it is a GET against an
// already-issued URL, so nothing on that path mutates state and there is no key to pin.
// What it does carry is pinned by content-fetch-vectors.json.
func executeVector(t *testing.T, baseOpts []rampconnect.ClientOption) clientRequestVector {
	t.Helper()
	sig := newSigningFixture(t)
	offers := newOfferFixture(t)
	var seen capturedRequest
	srv := recordingOrigin(t, &seen)
	defer srv.Close()

	client := rampconnect.NewClient(srv.URL, append(append([]rampconnect.ClientOption{}, baseOpts...),
		rampconnect.WithSigner(sig.signer),
		rampconnect.WithOfferKey(offers.exchangePub),
	)...)
	verified := verifyOne(t, offers)
	if _, err := client.Execute(context.Background(), verified,
		rampconnect.WithIdempotencyKey(pinnedKey)); err != nil {
		t.Fatalf("execute: %v", err)
	}
	ver, _ := seen.body["ver"].(string)
	key, _ := seen.body["idempotency_key"].(string)
	return clientRequestVector{
		Name: "execute_key_pinned", Verb: "execute", Path: seen.path, Ver: ver,
		IdempotencyKey: pinnedOrMinted("execute_key_pinned", key),
		RequesterID:    requesterIDOf(seen.body),
	}
}

// verifyOne runs the fixture's genuine offer through the real Verifier, because Execute
// accepts only what the core minted — a VerifiedOffer cannot be built by hand, which is
// the guard, so the emitter goes the same way a caller does.
func verifyOne(t *testing.T, offers offerFixture) core.VerifiedOffer {
	t.Helper()
	sorted := core.NewVerifier(
		core.Strict,
		helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"": offers.exchangePub}),
		time.Now,
	).Sort(context.Background(), []*rampv1.Offer{offers.good})
	if len(sorted.Verified) != 1 {
		t.Fatalf("fixture offer did not verify: %+v", sorted.Rejected)
	}
	return sorted.Verified[0]
}

// pinnedKey is the one idempotency key the corpus records verbatim. A minted key is fresh
// per call, so recording its value would make the corpus non-deterministic; what matters
// about a minted key is that it exists and is not the caller's.
const pinnedKey = "idem-pinned-1"

func pinnedOrMinted(name, key string) string {
	if key == pinnedKey {
		return key
	}
	return ""
}

func requesterIDOf(body map[string]any) string {
	requester, ok := body["requester"].(map[string]any)
	if !ok {
		return ""
	}
	id, _ := requester["id"].(string)
	return id
}

// brokerResolveVector captures the Broker's verb, which lives on its own client because a
// Broker is not an Exchange: it fans a query out across the Exchanges it knows, so its
// address is the Broker's and not any Exchange's.
func brokerResolveVector(t *testing.T, opts []rampconnect.ClientOption) clientRequestVector {
	t.Helper()
	var seen capturedRequest
	srv := recordingOrigin(t, &seen)
	defer srv.Close()
	if _, err := rampconnect.NewBrokerClient(srv.URL, opts...).
		Resolve(context.Background(), &rampv1.DiscoveryRequest{}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ver, _ := seen.body["ver"].(string)
	return clientRequestVector{
		Name: "resolve", Verb: "resolve", Path: seen.path, Ver: ver,
		RequesterID: requesterIDOf(seen.body),
	}
}
