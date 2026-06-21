package helpers

import (
	"sync"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
)

// Validation (ADR-014 / ADR-019, ramp-sdk-api.md "Wire-encoding reality"). The
// SDK validates messages against the proto's protovalidate rules — including the
// cross-field message-level CEL (FREE⇒rate 0, REFERENCE_ONLY⇒uri, PER_UNIT⇒unit,
// one-restriction-per-kind, …) — so a client catches a violation before the
// round-trip and a server re-checks on the way in.
//
// In Go, protovalidate-go IS the requirement's executable form (the same engine
// the conformance corpus uses as its oracle), so the Go L1 validator wraps it
// rather than re-authoring the rules — zero drift by construction. The
// hand-authored cross-field rules called for in the api doc are the TS/Python L1
// concern (those clients lack protovalidate); their oracle is
// conformance/corpus/crossfield.json, which this same engine generated.

var sharedValidator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New()
})

// Validate checks msg against its protovalidate rules. It returns nil when msg is
// valid and a *protovalidate.ValidationError (carrying the violated rule ids)
// otherwise. The validator is built once and reused (compiling its CEL is
// expensive); it is safe for concurrent use.
func Validate(msg proto.Message) error {
	v, err := sharedValidator()
	if err != nil {
		return err
	}
	return v.Validate(msg)
}

// ValidationRuleIDs extracts the violated protovalidate rule ids from an error
// returned by Validate (nil/empty when err is not a validation error). Callers
// use it to branch on or log which constraint failed.
func ValidationRuleIDs(err error) []string {
	verr, ok := err.(*protovalidate.ValidationError)
	if !ok {
		return nil
	}
	ids := make([]string, 0, len(verr.Violations))
	for _, vi := range verr.Violations {
		ids = append(ids, vi.Proto.GetRuleId())
	}
	return ids
}
