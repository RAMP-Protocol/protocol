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

// langFenceRe matches every fenced code block and captures its language tag,
// so the candidate scan below can tell a ```json fence (where marking is the
// convention) from a curl/pseudocode fence (where the payload must be
// extracted before it can be marked).
var langFenceRe = regexp.MustCompile("(?s)```([a-zA-Z0-9]*)[ \t]*\\n(.*?)```")

// requestCandidateKey reports why a balanced top-level JSON object is a
// request-example candidate that must live in a MARKED ```json fence — "" if
// it is not one.
//
// Requester-family keys are markers in EVERY fence language, because a
// requester payload is the walk-back surface for the removed
// Requester.billing_ref:
//   - requester: a discovery request (ResourceQuery / DiscoveryRequest carry
//     no idempotency_key).
//   - type = "REQUESTER_TYPE_*": the Requester message rendered standalone —
//     without this the removed field could re-enter a bare Requester example
//     that carries no requester key.
//
// Two keys are markers in ```json fences only:
//   - idempotency_key: a transaction/report/dispute request. Hands-on pages
//     legitimately teach these as copy-paste curl commands; those payloads
//     are shape-policed by TestDocTransactionExamplesAreItemsOnly (which
//     scans every fence language), so they are not forced into extraction.
//   - billing_ref: the key removed from Requester. It stays live on
//     RegisterResponse/GetAccountStatusResponse, so a JSON fence showing it
//     must be marked and validated instead of trusted, but non-JSON fences
//     (logs, SQL) may legitimately show the server-side handle.
func requestCandidateKey(top map[string]json.RawMessage, inJSONFence bool) string {
	if inJSONFence {
		if _, ok := top["idempotency_key"]; ok {
			return "idempotency_key"
		}
	}
	if _, ok := top["requester"]; ok {
		return "requester"
	}
	var typ string
	if raw, ok := top["type"]; ok && json.Unmarshal(raw, &typ) == nil && strings.HasPrefix(typ, "REQUESTER_TYPE_") {
		return "type = REQUESTER_TYPE_*"
	}
	if inJSONFence {
		if _, ok := top["billing_ref"]; ok {
			return "billing_ref"
		}
	}
	return ""
}

// TestDocMarkedExamplesValidate: a ```json fence marked with
// `{/* ramp-validate: MessageName */}` MUST strict-unmarshal (unknown fields
// rejected) into ramp.v1.<MessageName> and pass protovalidate — examples are
// INSTANCES of the contract, not lookalike prose. Completeness has three
// guards: an anti-vacuity floor (>=2 marked fences), a candidate detector for
// unmarked ```json fences (any balanced object carrying a
// requestCandidateKey marker silently opted out of validation, and fails),
// and the same detector over non-JSON fences (a request payload embedded in a
// curl/pseudocode fence must be extracted into a marked ```json fence).
// TestRequestCandidateDetectorFires pins the detector logic itself.
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
				// cannot silently escape validation. The positive keys live in
				// requestCandidateKey. Scan the balanced {...} spans, not the
				// whole fence — a `POST /path` verb line before the body makes
				// a whole-fence json.Unmarshal fail and let the example opt
				// out silently (the same hole balancedJSONObjects already
				// closes for the items-only guard below). A marked fence must
				// be pure JSON, so a flagged fence also needs its verb line
				// lifted out of the fence.
				for _, obj := range balancedJSONObjects(body) {
					var top map[string]json.RawMessage
					if json.Unmarshal([]byte(obj), &top) != nil {
						continue
					}
					if key := requestCandidateKey(top, true); key != "" {
						flag(path, "unmarked ```json request example (top-level \""+key+"\") — add {/* ramp-validate: <MessageName> */} above the fence (and move any POST/verb line out of the fence)")
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
		// Non-JSON fences: a request payload embedded in a curl -d or a
		// pseudocode fence cannot be marked in place, so it escapes the loop
		// above entirely. Same detector, different remedy: extract the body
		// into its own marked ```json fence.
		for _, m := range langFenceRe.FindAllStringSubmatch(content, -1) {
			lang, body := m[1], m[2]
			if lang == "json" {
				continue // handled by the marked-fence path above
			}
			for _, obj := range balancedJSONObjects(body) {
				var top map[string]json.RawMessage
				if json.Unmarshal([]byte(obj), &top) != nil {
					continue
				}
				if key := requestCandidateKey(top, false); key != "" {
					flag(path, "request payload (top-level \""+key+"\") embedded in a non-JSON fence — extract the JSON body into its own marked ```json fence")
					break
				}
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

// TestRequestCandidateDetectorFires pins the candidate detection itself. The
// doc suite's healthy state is zero findings, so a regression that stops the
// detector from ever matching (a key check drifts, balancedJSONObjects stops
// yielding spans) would keep the suite green with the guard disarmed. The
// probes mirror the injection cases for the removed billing_ref field.
func TestRequestCandidateDetectorFires(t *testing.T) {
	cases := []struct {
		name, body, want string
		inJSONFence      bool
	}{
		{"verb line then requester body", "POST /v1/DiscoverResources\n{\"ver\": \"1.0\", \"requester\": {\"id\": \"a\"}}", "requester", true},
		{"idempotency_key request", "{\"idempotency_key\": \"k\", \"items\": []}", "idempotency_key", true},
		{"bare Requester object", "{\"id\": \"a\", \"type\": \"REQUESTER_TYPE_AGENT\", \"billing_ref\": \"acct-x\"}", "type = REQUESTER_TYPE_*", true},
		{"billing_ref key in a json fence", "{\"billing_ref\": \"acct-x\", \"status\": \"ACTIVE\"}", "billing_ref", true},
		{"billing_ref in a non-json fence is the live server-side handle", "{\"billing_ref\": \"acct-x\", \"status\": \"ACTIVE\"}", "", false},
		{"curl-embedded requester", "curl -X POST https://x/v1/DiscoverResources -d '{\"requester\": {\"id\": \"p\"}}'", "requester", false},
		{"curl transaction payload is items-only-guarded, not marking-forced", "curl -X POST https://x/v1/ExecuteTransaction -d '{\"idempotency_key\": \"k\", \"items\": []}'", "", false},
		{"non-request object", "{\"resources\": [{\"uri\": \"https://x/a\"}]}", "", true},
		{"non-JSON body yields no spans", "Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT", "", false},
	}
	for _, c := range cases {
		got := ""
		for _, obj := range balancedJSONObjects(c.body) {
			var top map[string]json.RawMessage
			if json.Unmarshal([]byte(obj), &top) != nil {
				continue
			}
			if key := requestCandidateKey(top, c.inJSONFence); key != "" {
				got = key
				break
			}
		}
		if got != c.want {
			t.Errorf("%s: candidate key = %q, want %q", c.name, got, c.want)
		}
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

// The items-only collapse moved the single offer into items[].offer
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
// request, or a top-level per-item result field in a response, is the pre-items-only
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
