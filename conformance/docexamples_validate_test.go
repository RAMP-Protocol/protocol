package conformance

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
)

// This file closes the OMISSION class of doc drift: the denylist and the
// remark-proto guard can only reject stale NAMES; neither can see a required
// shape that is silently missing from an example (reflected-offer execute
// examples that omitted expires_at — the exact field the SDK verifier
// fail-closes on).

// reflectedOfferKeyRe / expiresAtRe: data-literal key forms, quoted or unquoted,
// so curl-embedded JSON and walkthrough pseudocode fences are covered as well as
// pure ```json fences. The Go generated forms (req.Msg.IdempotencyKey) do not
// match — Go handler listings are not example payloads.
var (
	idempotencyKeyRe = regexp.MustCompile(`"?idempotency_key"?\s*:`)
	signatureKeyRe   = regexp.MustCompile(`"?signature"?\s*:`)
	expiresAtRe      = regexp.MustCompile(`"?expires_at"?\s*:`)
)

// TestDocReflectedOfferHasExpiresAt: an execute-request example that embeds a
// signed offer MUST show expires_at. The reflected-Offer contract fail-closes on
// a missing expiry (helpers.VerifyPresentedOffer: an offer with no expires_at is
// a forever-token and unsafe to honor), so an example without it teaches a shape
// every conformant Exchange rejects. Detection is fence-level co-occurrence:
// `idempotency_key` marks a transaction-request payload, a `signature` key marks
// an embedded offer.
func TestDocReflectedOfferHasExpiresAt(t *testing.T) {
	fences, flagged := 0, 0
	var bad []string
	walkDocs(t, func(path, content string) {
		for _, f := range codeFences(content) {
			fences++
			if idempotencyKeyRe.MatchString(f) && signatureKeyRe.MatchString(f) && !expiresAtRe.MatchString(f) {
				flagged++
				bad = append(bad, filepath.Base(path)+": execute-request example embeds a signed offer without \"expires_at\" — the reflected-Offer verifier fail-closes on a missing expiry")
			}
		}
	})
	t.Logf("code fences scanned=%d reflected-offer-without-expiry=%d", fences, flagged)
	for _, b := range bad {
		t.Error(b)
	}
}

// markedFenceRe captures every ```json fence together with an OPTIONAL
// `{/* ramp-validate: MessageName */}` MDX comment on the line above it. A
// marked fence is validated as a real instance of that message; an unmarked one
// is checked by the candidate detector below.
var markedFenceRe = regexp.MustCompile("(?s)(?:\\{/\\* ramp-validate: ([A-Za-z0-9]+) \\*/\\}\\s*\\n)?```json[ \t]*\\n(.*?)```")

// TestDocMarkedExamplesValidate: a ```json fence marked with
// `{/* ramp-validate: MessageName */}` MUST strict-unmarshal (unknown fields
// rejected) into ramp.v1.<MessageName> and pass protovalidate — examples are
// INSTANCES of the contract, not lookalike prose. Completeness has two guards:
// an anti-vacuity floor (>=2 marked fences), and a candidate detector — any
// UNMARKED pure-JSON fence whose top-level object carries idempotency_key is a
// transaction-request example that silently opted out, and fails.
func TestDocMarkedExamplesValidate(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	marked := 0
	var bad []string
	flag := func(path, msg string) { bad = append(bad, filepath.Base(path)+": "+msg) }
	walkDocs(t, func(path, content string) {
		for _, m := range markedFenceRe.FindAllStringSubmatch(content, -1) {
			name, body := m[1], m[2]
			if name == "" {
				// Candidate detector: a request example must be marked, so it
				// cannot silently escape validation. Two positive keys: a
				// top-level idempotency_key marks a transaction/report/dispute
				// request, and a top-level requester marks a discovery request
				// (ResourceQuery / DiscoveryRequest carry no idempotency_key —
				// without this key the removed Requester.billing_ref could walk
				// back into an unmarked discovery fence with no gate firing).
				// Scan the balanced {...} spans, not the whole fence — a
				// `POST /path` verb line before the body makes a whole-fence
				// json.Unmarshal fail and let the example opt out silently (the
				// same hole balancedJSONObjects already closes for the
				// items-only guard below). A marked fence must be pure JSON, so
				// a flagged fence also needs its verb line lifted out of the
				// fence.
				for _, obj := range balancedJSONObjects(body) {
					var top map[string]json.RawMessage
					if json.Unmarshal([]byte(obj), &top) != nil {
						continue
					}
					_, isTxShaped := top["idempotency_key"]
					_, isDiscoveryShaped := top["requester"]
					if isTxShaped || isDiscoveryShaped {
						flag(path, "unmarked ```json request example (has idempotency_key or requester) — add {/* ramp-validate: <MessageName> */} above the fence (and move any POST/verb line out of the fence)")
						break
					}
				}
				continue
			}
			marked++
			mt, err := findContractMessage(name)
			if err != nil {
				flag(path, "ramp-validate names unknown message "+name)
				continue
			}
			msg := mt.New().Interface()
			if err := protojson.Unmarshal([]byte(body), msg); err != nil {
				flag(path, "ramp-validate:"+name+" example does not parse as proto-JSON: "+firstLine(err.Error()))
				continue
			}
			if err := v.Validate(msg); err != nil {
				flag(path, "ramp-validate:"+name+" example fails protovalidate: "+firstLine(err.Error()))
			}
		}
	})
	if marked < 2 {
		t.Fatalf("only %d marked example(s) found — the marker scan drifted (expected >=2)", marked)
	}
	t.Logf("marked examples validated=%d", marked)
	for _, b := range bad {
		t.Error(b)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// balancedJSONObjects returns every top-level {...} span in s whose braces
// balance (ignoring braces inside strings). It lets the example guards see a
// payload wrapped by a shell (`curl ... -d '{...}'`) or preceded by an RPC verb
// line (`POST /path` then the body) — spans that a whole-fence json.Unmarshal
// rejects. This is the coverage hole that let the pre-items-only walkthrough
// request/response examples pass the marked-fence guard silently.
func balancedJSONObjects(s string) []string {
	var out []string
	depth, start := 0, -1
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					out = append(out, s[start:i+1])
					start = -1
				}
			}
		}
	}
	return out
}

// The items-only collapse (RAMP-102) moved the single offer into items[].offer
// and the per-result data into items[] TransactionResultItem. A transaction
// example carrying any of these at the TOP LEVEL is the removed single-offer
// shape. Detection is positive-keyed so non-transaction JSON (ramp.json, JWKS,
// ErrorDetail) is never touched: idempotency_key marks a request; results /
// agent_identity_hash / total_cost mark a response.
var (
	removedRequestTopFields  = []string{"offer", "offer_id", "aisystem", "agent_acceptance"}
	removedResponseTopFields = []string{
		"offer_id", "transaction_id", "billing_id", "resource_title", "cost",
		"delivery_method", "reporting_obligation", "expires_at", "subscription_id",
		"subscription_unit_value", "retrieval_endpoint", "denial_reason",
	}
	responseMarkerFields = []string{"results", "agent_identity_hash", "total_cost"}
)

// TestDocTransactionExamplesAreItemsOnly: every transaction request/response
// example in the docs — in a ```json fence, a curl `-d`, or after a verb line —
// must use the items-only shape. A top-level offer/offer_id/aisystem in a
// request, or a top-level per-item result field in a response, is the pre-RAMP-102
// single-offer shape and fails here instead of teaching a removed contract.
func TestDocTransactionExamplesAreItemsOnly(t *testing.T) {
	scanned := 0
	var bad []string
	hasKey := func(top map[string]json.RawMessage, keys []string) (string, bool) {
		for _, k := range keys {
			if _, ok := top[k]; ok {
				return k, true
			}
		}
		return "", false
	}
	walkDocs(t, func(path, content string) {
		for _, f := range codeFences(content) {
			for _, obj := range balancedJSONObjects(f) {
				var top map[string]json.RawMessage
				if json.Unmarshal([]byte(obj), &top) != nil {
					continue
				}
				if _, isReq := top["idempotency_key"]; isReq {
					scanned++
					if k, badField := hasKey(top, removedRequestTopFields); badField {
						bad = append(bad, filepath.Base(path)+": transaction-request example carries removed top-level \""+k+"\" — items-only puts the offer in items[].offer")
					}
					continue
				}
				if _, isResp := hasKey(top, responseMarkerFields); isResp {
					scanned++
					if k, badField := hasKey(top, removedResponseTopFields); badField {
						bad = append(bad, filepath.Base(path)+": transaction-response example carries removed top-level \""+k+"\" — items-only puts per-result data in items[]")
					}
				}
			}
		}
	})
	if scanned < 2 {
		t.Fatalf("only %d transaction example(s) scanned — the fence/JSON extractor drifted (expected >=2)", scanned)
	}
	t.Logf("transaction examples scanned=%d", scanned)
	for _, b := range bad {
		t.Error(b)
	}
}
