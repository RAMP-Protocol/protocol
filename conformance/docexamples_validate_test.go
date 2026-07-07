package conformance

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
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
				// Candidate detector: a pure-JSON transaction-request example
				// must be marked, so it cannot silently escape validation.
				var top map[string]json.RawMessage
				if json.Unmarshal([]byte(body), &top) == nil {
					if _, ok := top["idempotency_key"]; ok {
						flag(path, "unmarked ```json request example (has idempotency_key) — add {/* ramp-validate: <MessageName> */} above the fence")
					}
				}
				continue
			}
			marked++
			mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName("ramp.v1." + name))
			if err != nil {
				flag(path, "ramp-validate names unknown message ramp.v1."+name)
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
