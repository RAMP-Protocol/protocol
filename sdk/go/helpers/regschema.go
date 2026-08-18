package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Safe validation of a published registration schema.
//
// An Exchange MAY publish AccountRegistration.data_schema in its ramp.json: a JSON
// Schema describing the RegisterRequest.registration_data it expects. Two parties
// read that schema and MUST agree — the Exchange enforcing it on the way in, and a
// client pre-checking a payload before it signs and sends one. A payload that
// passes one and fails the other is the failure this face exists to remove, so the
// rules live here once rather than in each consumer's choice of library.
//
// The client's copy is the harder half: it arrives out of a THIRD PARTY's manifest,
// which makes a schema an attacker-influenced input reached before any signature is
// checked. Three properties follow, and the field's contract states all three:
//
//	Remote $ref is not resolved. A schema that could point at a URL would make
//	every reader an SSRF vector aimed at an address its author chose. Only
//	same-document references are admitted, and the compiler is given an explicitly
//	REFUSING loader, so a reference this package missed fails closed rather than
//	being read off disk — which is what the library does when left to its default.
//
//	The dialect is pinned. Draft 2020-12 only: a validator that silently accepted
//	an older draft would apply DIFFERENT semantics to the same document than a peer
//	that refused it, which is the disagreement this face exists to prevent.
//
//	Resources are bounded. A size cap, a nesting-depth cap, an evaluation-cost cap
//	and a narrowed `pattern` alphabet, all measured before the schema is compiled.
//
// `pattern` needs two different mechanisms, and treating it as one problem is the
// mistake this face made first. Draft 2020-12 patterns are ECMA-262, and the three
// SDKs run three different engines over them.
//
//	Some constructs one engine cannot express at all — RE2 has no lookaround, and
//	JavaScript has no inline flags. Those are REFUSED, because no amount of care at
//	the call site reconciles them.
//
//	Others every engine compiles and then reads DIFFERENTLY. `\d` is Unicode-aware
//	in Python and ASCII in RE2 and ECMA-262; Python's `$` also matches before a
//	trailing newline. Refusing those would gut the feature — they appear in almost
//	every real pattern — so instead the ODD ONE OUT is corrected. Go and JavaScript
//	already agree; the Python port compiles with its ASCII flag and rewrites `$`, so
//	all three match the same strings.
//
// The second kind is the dangerous one, because nothing errors: two conformant
// validators both compile the pattern and then disagree about which payloads
// conform. It is also why the shared corpus records what a pattern MATCHES and not
// only whether the schema was admitted — an alphabet that is merely asserted is one
// nobody can check.
//
// Work is bounded twice, because the two phases have different cost drivers. The
// size and depth caps bound the DOCUMENT; they say nothing about how much work
// checking a payload against it takes, and a 1.6KB schema five levels deep can cost
// tens of seconds. MaxRegistrationSchemaEvaluations bounds that statically, before
// anything runs. A compile timeout bounds the other phase, whose cost lives in regex
// compilation and reference resolution rather than in branch count.
//
// Everything here is pure: bytes in, verdict out, no IO and no state, which is why
// it sits in the IO-free tier and can run before any network or database is touched.

// MaxRegistrationSchemaBytes is the published schema's size cap, measured as the
// UTF-8 bytes of the data_schema member AS SERVED in ramp.json — which is why the
// compile face takes raw bytes rather than a decoded document. A re-encoding is a
// different length than what the origin sent, and the cap is defined over what the
// origin sent.
const MaxRegistrationSchemaBytes = 16384

// MaxRegistrationSchemaDepth bounds how deeply the schema document may nest. It
// counts JSON containers, so a bare `{}` is depth 1. Deep allOf/$ref chains are the
// cheapest way to make a compile expensive, and a registration schema describing a
// business entity is three to five levels deep in practice.
const MaxRegistrationSchemaDepth = 32

// MaxRegistrationFieldErrors is the number of member failures a refusal may carry.
// It is the wire's own bound — RegistrationFailure.field_errors declares
// repeated.max_items = 64 — restated here so the validator never builds a list the
// contract would reject. A conformance guard reads both and fails if they part.
const MaxRegistrationFieldErrors = 64

// MaxRegistrationFieldErrorPathLen and MaxRegistrationFieldErrorTextLen are the
// wire bounds on RegistrationFieldError.path and .error. Same reason as above: the
// validator clamps to them so its output is always a message the contract accepts.
const (
	MaxRegistrationFieldErrorPathLen = 255
	MaxRegistrationFieldErrorTextLen = 255
)

// MaxRegistrationSchemaEvaluations bounds the WORK of checking a payload, which the
// size and depth caps do not. `anyOf` branches multiply along a reference chain, so a
// schema can be small and shallow and still cost an unbounded amount to evaluate: a
// 1,675-byte document five levels deep measures 16.7 million evaluations and takes
// 27 seconds against a two-member payload. Cost is linear in this count at roughly
// 1.5µs per evaluation, so the bound is really a time bound — about 15ms — expressed
// as a number a static walk can compute and a shared corpus can pin, which a
// stopwatch cannot. A registration schema describing a business entity measures a few
// dozen, so the headroom is several hundredfold.
const MaxRegistrationSchemaEvaluations = 10000

// MaxRegistrationSchemaRefHops bounds how long a $ref chain may be, measured as the
// longest path of reference hops rather than as the number of references a document
// contains.
//
// It is a SEPARATE axis from MaxRegistrationSchemaDepth, and the shape that forced it
// shows why: a chain of five hundred definitions, each referring to the next, is three
// JSON containers deep however long it is, so the depth cap never sees it. The
// evaluation cap does not see it either — a flat chain costs one evaluation per link,
// so five hundred links is five hundred against a bound of ten thousand.
//
// What it bounds is the RECURSION every validator does while resolving that chain. This
// package's own cost walk follows references iteratively and does not care, but the
// libraries the three SDKs hand an accepted schema to do not, and one of them exhausted
// its interpreter stack at 495 links — throwing out of a face documented as returning a
// verdict, on a document every SDK had just called valid. A bound in the contract is
// what stops that, because it stops the document being published rather than asking
// three libraries to survive it.
//
// 100 is far above use and far below harm: a realistic registration schema chains one
// or two references, the deepest chain in an accepted conformance vector is eleven, and
// the crash needs about five hundred.
const MaxRegistrationSchemaRefHops = 100

// RegistrationSchemaCompileTimeout bounds the OTHER phase. Compiling is cheap in
// every shape measured (single-digit to tens of milliseconds across the three
// languages), and the evaluation cap above does not bound it at all: compilation
// spends its time in regex compilation, reference resolution, and — in the
// TypeScript port — generating and evaluating JavaScript source. A phase left
// unbounded because a different phase's bound happens to be tighter today is not
// bounded. Generous on purpose: it is a backstop against a shape nobody predicted,
// not a performance budget.
const RegistrationSchemaCompileTimeout = 2 * time.Second

// RegistrationSchemaDialect is the only $schema value a published data_schema may
// name. A document that names none is read as this dialect; one that names another
// is refused rather than validated under semantics its author did not intend.
const RegistrationSchemaDialect = "https://json-schema.org/draft/2020-12/schema"

// utf8BOM is the UTF-8 encoding of U+FEFF, refused at the head of a schema.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// isJSONBlank reports whether raw carries nothing but JSON whitespace, which is what
// "this Exchange publishes no data_schema" looks like in bytes.
//
// The definition is RFC 8259's and nothing wider: space, tab, carriage return and line
// feed. It is deliberately NOT each language's idea of whitespace, because that is
// three different sets — Go's unicode.IsSpace takes U+00A0 and U+3000, a Python
// bytes.strip() takes neither, and JavaScript's String.trim takes both plus a leading
// byte order mark. This gate decides the ENFORCEMENT SWITCH: reading a document as
// blank means reading it as "no schema published", which turns validation off. So it
// has to be the same question in all three, asked over the bytes AS SERVED rather than
// over a decoded string — decoding is itself where one of those disagreements lives,
// and a mark or an ill-formed byte must survive to reach the rule that refuses it.
func isJSONBlank(raw []byte) bool {
	for _, b := range raw {
		if b != 0x20 && b != 0x09 && b != 0x0D && b != 0x0A {
			return false
		}
	}
	return true
}

// SchemaVerdict is the outcome of compiling a published data_schema.
type SchemaVerdict int

const (
	// SchemaNoVerdict is the zero value: nothing was decided. It is first so that a
	// caller who ignores the verdict entirely reads "no answer" rather than an
	// acceptance, and it is never returned.
	SchemaNoVerdict SchemaVerdict = iota

	// SchemaAccepted means the schema passed every rule and is usable.
	SchemaAccepted

	// SchemaMalformed means the bytes are not JSON, or the document is not a JSON
	// object at its top level. 2020-12 would admit a bare boolean as a schema, but
	// data_schema is a google.protobuf.Struct and cannot carry one.
	SchemaMalformed

	// SchemaWrongDialect means a $schema in the document names a dialect other than
	// draft 2020-12.
	SchemaWrongDialect

	// SchemaRemoteRef means a reference points outside the document. Separate from
	// SchemaMalformed because it is the one refusal that describes an attack rather
	// than a mistake, and an operator reading it should look at who authored the
	// schema, not at whether it parses.
	SchemaRemoteRef

	// SchemaTooLarge means the raw bytes exceed MaxRegistrationSchemaBytes.
	SchemaTooLarge

	// SchemaTooDeep means the document nests past MaxRegistrationSchemaDepth.
	SchemaTooDeep

	// SchemaUnsafePattern means a `pattern` uses a construct outside the alphabet
	// all three SDK languages can express identically.
	SchemaUnsafePattern

	// SchemaTooComplex means checking a payload against the schema would cost more
	// than MaxRegistrationSchemaEvaluations. The document itself may be small: this
	// bounds the work, which the size and depth caps do not.
	SchemaTooComplex

	// SchemaRefCycle means a reference chain returns to a schema already on it. The
	// cycle is legal JSON Schema — it is how a recursive structure is written — but
	// its evaluation cost has no static bound, and it is what makes two of the three
	// ports abort rather than answer. Registration data describes a business entity,
	// which is not a recursive shape, so refusing the construct costs nothing real.
	// Separate from SchemaTooComplex because the remedy is different: a cycle is a
	// modelling choice to undo, not a budget to trim.
	SchemaRefCycle

	// SchemaRefChainTooLong means a reference chain is longer than
	// MaxRegistrationSchemaRefHops. It is its own verdict rather than SchemaTooComplex
	// or SchemaTooDeep because it is its own rule: a flat chain is cheap to evaluate and
	// shallow to nest, and neither of those caps can see it.
	SchemaRefChainTooLong

	// SchemaCompileTimeout means compilation ran past RegistrationSchemaCompileTimeout.
	SchemaCompileTimeout

	// SchemaUncompilable means the document is well-formed JSON, passes the rules
	// above, and is still not a valid 2020-12 schema — including a same-document
	// reference that resolves to nothing.
	SchemaUncompilable

	// SchemaNotPublished means there was no schema to compile: the Exchange publishes
	// none. It is a verdict rather than an error because it is a normal, common state
	// with its own contract — registration_data passes through uninspected — and
	// because collapsing it into a refusal would leave a caller unable to tell "there
	// is nothing to enforce" from "I refused to enforce what I was given".
	SchemaNotPublished
)

// String renders the verdict as the stable token the shared conformance vectors
// record, so a port asserts against the same word rather than a number whose
// meaning depends on declaration order.
func (v SchemaVerdict) String() string {
	switch v {
	case SchemaNoVerdict:
		return "no_verdict"
	case SchemaAccepted:
		return "accepted"
	case SchemaMalformed:
		return "malformed"
	case SchemaWrongDialect:
		return "wrong_dialect"
	case SchemaRemoteRef:
		return "remote_ref"
	case SchemaTooLarge:
		return "too_large"
	case SchemaTooDeep:
		return "too_deep"
	case SchemaUnsafePattern:
		return "unsafe_pattern"
	case SchemaTooComplex:
		return "too_complex"
	case SchemaRefCycle:
		return "ref_cycle"
	case SchemaRefChainTooLong:
		return "ref_chain_too_long"
	case SchemaCompileTimeout:
		return "compile_timeout"
	case SchemaUncompilable:
		return "uncompilable"
	case SchemaNotPublished:
		return "not_published"
	default:
		return fmt.Sprintf("SchemaVerdict(%d)", int(v))
	}
}

// RegistrationSchema is a compiled, accepted data_schema. It is immutable and safe
// for concurrent use, so a server compiles the operator's schema once at start-up
// and a client caches one per Exchange.
type RegistrationSchema struct {
	sch *jsonschema.Schema
}

// CompileRegistrationSchema checks a published data_schema against every rule above
// and compiles it.
//
// raw is the schema AS SERVED — the exact UTF-8 bytes of the data_schema member in
// ramp.json — because MaxRegistrationSchemaBytes is defined over those bytes.
//
// The schema is non-nil only on SchemaAccepted. There is no error return: every way
// this can fail is a property of the schema, and both callers need to know WHICH,
// not merely that something went wrong. They read the same refusal differently, and
// that difference is the contract:
//
//	A CLIENT pre-checking a payload treats any non-accepted verdict as "do not
//	pre-check" and sends anyway. The field's contract says so for an oversized
//	schema, and it generalises: a local check that cannot run must not become a
//	local veto, because the Exchange's own enforcement is the deciding one and a
//	client that refused here would block a payload the Exchange would have taken.
//
//	An EXCHANGE compiling its OWN configured schema treats the same verdict as an
//	operator misconfiguration of this deployment. Nothing about a third party is
//	involved, and serving a manifest advertising a schema it cannot itself enforce
//	is the one outcome it must not reach.
func CompileRegistrationSchema(raw []byte) (*RegistrationSchema, SchemaVerdict) {
	// Nothing to compile is its own answer, not a malformed document. An Exchange
	// that publishes no data_schema is the contract's ordinary case.
	if isJSONBlank(raw) {
		return nil, SchemaNotPublished
	}
	// Size first, on the bytes as served and before any parse: an oversized document
	// must not be decoded to find out that it was oversized.
	if len(raw) > MaxRegistrationSchemaBytes {
		return nil, SchemaTooLarge
	}
	// The ENCODING, still on the raw bytes, because every rule below is stated over a
	// document and these two decide which document that is.
	//
	// Invalid UTF-8 is refused rather than repaired. encoding/json silently replaces
	// an ill-formed byte with U+FFFD, so without this check the schema compiled here
	// is not the schema that was served — a `const` or a `pattern` carrying one bad
	// byte would be enforced with a different character in it, and the two ports
	// refuse the same document outright. RFC 8259 requires UTF-8 for interchange.
	//
	// A byte order mark is refused too. RFC 8259 forbids adding one and lets a parser
	// ignore one, so both policies conform and the choice has to be made once for all
	// three: Python's json.loads strips it from bytes and JavaScript's TextDecoder
	// strips it by default, while Go's parser does not, and three implementations
	// disagreeing about the same document is the failure this face exists to prevent.
	// Refusing is the side that keeps MaxRegistrationSchemaBytes honest — a stripped
	// mark would make the cap count three bytes that the schema does not contain. It
	// also cannot legitimately occur on the wire: a mark is only valid at the start of
	// a JSON text, and data_schema is a member INSIDE ramp.json.
	if !utf8.Valid(raw) {
		return nil, SchemaMalformed
	}
	if bytes.HasPrefix(raw, utf8BOM) {
		return nil, SchemaMalformed
	}
	// Depth SECOND, and still on the raw bytes — before the document is handed to a
	// JSON parser rather than after. Every parser here descends recursively, and two
	// of the three abort on a deeply nested document in a way this face cannot map
	// onto a verdict: Python raises RecursionError, which is not the exception a
	// malformed document raises. Checking after the parse therefore means the check
	// that exists to stop a hostile document is reached only for documents that were
	// harmless enough to parse. Lexical counting needs no recursion at all.
	if rawNestingDepth(raw) > MaxRegistrationSchemaDepth {
		return nil, SchemaTooDeep
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, SchemaMalformed
	}
	// A JSON OBJECT and nothing else. 2020-12 admits a bare boolean as a schema, but
	// data_schema is a google.protobuf.Struct, which carries an object — so a boolean
	// cannot reach this face over the wire at all, and admitting one would pin
	// behaviour for a document the contract has no way to transport.
	if _, isObject := doc.(map[string]any); !isObject {
		return nil, SchemaMalformed
	}
	if v := scanRegistrationSchema(doc); v != SchemaAccepted {
		return nil, v
	}
	// The work bound, still before the compiler is involved. This is also where a
	// reference cycle and a same-document reference that resolves to nothing are
	// found, because counting the cost means following every reference to its target.
	if v := checkEvaluationCost(doc); v != SchemaAccepted {
		return nil, v
	}

	c := jsonschema.NewCompiler()
	// An explicitly REFUSING loader, not the absence of one. The library installs a
	// FileLoader by default, so leaving this unset does not mean "resolves nothing" —
	// it means a reference the scan above missed is read off local disk. The scan is
	// the rule the ports implement; this is the backstop under it, and it has to be
	// installed to exist.
	c.UseLoader(refusingSchemaLoader{})
	c.DefaultDraft(jsonschema.Draft2020)
	// format / contentEncoding / contentMediaType stay ANNOTATIONS, never assertions.
	// The three languages' libraries default differently, so leaving this to a
	// default would make the same document conform in one SDK and not in another.
	const schemaURL = "ramp:registration-data-schema"
	if err := c.AddResource(schemaURL, doc); err != nil {
		return nil, SchemaUncompilable
	}
	sch, v := compileWithin(c, schemaURL, RegistrationSchemaCompileTimeout)
	if v != SchemaAccepted {
		return nil, v
	}
	return &RegistrationSchema{sch: sch}, SchemaAccepted
}

// refusingSchemaLoader is the SSRF backstop. Every reference that reaches it has
// already escaped the scan, so the only correct answer is to refuse — never to read
// a file, and never to dial.
type refusingSchemaLoader struct{}

func (refusingSchemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("helpers: refusing to resolve %q: a registration schema must be self-contained", url)
}

// compileWithin runs the compiler under a wall clock.
//
// The goroutine is abandoned rather than cancelled, because the library takes no
// context. That is tolerable HERE and would not be on the validate path: the input
// is already bounded to 16KB, the branch count is already bounded, and compilation
// happens once per schema rather than once per payload — so the abandoned work is
// bounded and terminates on its own. The caller gets an answer either way.
func compileWithin(c *jsonschema.Compiler, url string, budget time.Duration) (*jsonschema.Schema, SchemaVerdict) {
	type result struct {
		sch *jsonschema.Schema
		err error
	}
	done := make(chan result, 1) // buffered: the abandoned goroutine must not block forever
	go func() {
		sch, err := c.Compile(url)
		done <- result{sch: sch, err: err}
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, SchemaUncompilable
		}
		return r.sch, SchemaAccepted
	case <-timer.C:
		return nil, SchemaCompileTimeout
	}
}

// Validate checks a registration_data payload against the schema and names what
// failed. A nil result means the payload conforms.
//
// data is the decoded object — RegisterRequest.GetRegistrationData().AsMap() at a
// call site. The result is ready to hand straight to RegistrationFailureDetail
// alongside REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA.
//
// Two properties of the output are contract, not presentation:
//
//	No entry ever echoes a submitted value. `error` states the CONSTRAINT that was
//	violated and nothing else — the same leakage rule ErrorDetail.message carries,
//	and it has teeth here because a refusal travels back over the wire while
//	registration_data is an operator's business data. The underlying library's own
//	messages quote the offending value, so this face builds its text from the failed
//	keyword instead of rendering the library's.
//
//	The order is deterministic. Entries are deduplicated and sorted by path, then by
//	keyword, before the list is capped. Three validators walk a failing document in
//	three different orders, so an unsorted list is one no shared corpus could pin.
//
// A nil receiver reports no failures, because "no schema" means "nothing to enforce"
// — the pass-through case an Exchange publishing no data_schema is entitled to, and
// the case a client is REQUIRED to fall into when it cannot check locally. Note what
// that implies: a caller that drops the verdict from CompileRegistrationSchema holds
// nil after every refusal too, and this call then reports success. That is correct for
// a client, whose refusal is "send anyway and let the Exchange decide", and wrong for
// an Exchange, which must treat any verdict other than SchemaAccepted or
// SchemaNotPublished as a misconfiguration of its own deployment. The verdict is the
// only thing that separates the two, so an Exchange must not discard it.
func (s *RegistrationSchema) Validate(data map[string]any) []*rampv1.RegistrationFieldError {
	if s == nil || s.sch == nil {
		return nil
	}
	// A validator handed nothing still has a schema to answer against: `required` on
	// an absent object is a failure at the root, not a pass.
	var inst any = data
	if data == nil {
		inst = map[string]any{}
	}
	vs := s.violations(inst)
	if len(vs) == 0 {
		return nil
	}
	out := make([]*rampv1.RegistrationFieldError, 0, len(vs))
	for _, v := range vs {
		out = append(out, &rampv1.RegistrationFieldError{
			Path:  v.Path,
			Error: clampText(v.Text),
		})
	}
	return out
}

// schemaViolation is one constraint failure before it is narrowed to the wire's
// two-field shape. The keyword is kept because it — not the prose — is what the
// shared conformance corpus pins: `error` wording is validator-defined and varies
// across implementations by contract, while the failed keyword is the same word in
// every JSON Schema library.
type schemaViolation struct {
	Path    string
	Keyword string
	Text    string
}

// violations is the whole validation answer, deduplicated, deterministically
// ordered and capped. Validate narrows it to the wire shape; the vector emitter
// reads it whole so the corpus can record the keyword alongside the pointer.
func (s *RegistrationSchema) violations(inst any) []schemaViolation {
	err := s.sch.Validate(inst)
	if err == nil {
		return nil
	}
	verr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		// The library returns only *ValidationError from Validate. If that ever stops
		// being true, report the whole object as failing rather than claim it passed.
		return []schemaViolation{{Path: "", Keyword: "schema", Text: "does not conform to the published schema"}}
	}
	return violationsFrom(verr)
}

// --- schema scan --------------------------------------------------------------

// nonSchemaKeywords hold arbitrary JSON DATA, not subschemas. Their contents are
// never inspected for keywords, so a `const` that happens to carry a "$ref" member
// is a value a payload may equal rather than a reference to resolve. Their nesting
// is still bounded — the lexical depth scan runs over the raw bytes and does not
// care which keyword a container sits under.
var nonSchemaKeywords = map[string]bool{
	"const": true, "default": true, "enum": true, "examples": true,
}

// schemaMapKeywords map NAMES to subschemas. Their child keys are property or
// definition names rather than keywords, so the child object is descended one level
// as a plain container: `{"properties": {"$ref": {...}}}` declares a property called
// "$ref", not a reference.
var schemaMapKeywords = map[string]bool{
	"properties": true, "patternProperties": true, "$defs": true,
	"definitions": true, "dependentSchemas": true,
}

// rawNestingDepth returns the deepest JSON container nesting in raw, counted
// lexically — no parse, no recursion, one pass over the bytes.
//
// It is string-aware, so a brace inside a string literal is text rather than a
// container, and escape-aware so a literal quote does not end the string early. It
// does NOT check that the brackets balance: an unbalanced document is the parser's
// to reject, and this only has to produce an upper bound on how deep a parser would
// have to descend.
//
// Byte-wise rather than rune-wise on purpose. Every delimiter it looks for is
// ASCII, and no continuation byte of a multi-byte UTF-8 sequence can collide with
// one, so decoding first would cost a pass and change nothing.
func rawNestingDepth(raw []byte) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, b := range raw {
		if inString {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case '}', ']':
			depth--
		}
	}
	return deepest
}

// scanRegistrationSchema walks the decoded document once, enforcing the dialect,
// reference and pattern rules. Depth is NOT its business — rawNestingDepth owns
// that bound and has already run, which is what lets this walk recurse freely.
//
// The first failure decides, and the order of the checks within a level is fixed
// (dialect, then references, then patterns) so a document breaking two rules always
// gets the same answer.
func scanRegistrationSchema(node any) SchemaVerdict {
	switch n := node.(type) {
	case map[string]any:
		if v := checkSchemaKeywords(n); v != SchemaAccepted {
			return v
		}
		// Sorted so a document with two faults answers the same way on every run;
		// Go's map order is randomised and the verdict must not be.
		for _, k := range sortedKeys(n) {
			// A non-schema keyword's value is DATA. Its contents are not read as
			// keywords at all, so a `const` carrying a "$ref" member is a value a
			// payload may equal rather than a reference to resolve.
			if nonSchemaKeywords[k] {
				continue
			}
			child := n[k]
			if schemaMapKeywords[k] {
				if sub, ok := child.(map[string]any); ok {
					// The child's KEYS are property or definition names, never
					// keywords, so only its values are read as schemas.
					for _, name := range sortedKeys(sub) {
						if v := scanRegistrationSchema(sub[name]); v != SchemaAccepted {
							return v
						}
					}
					continue
				}
				// Not the shape the keyword takes; fall through and walk it
				// generically rather than guess. An invalid schema is the compiler's
				// to reject.
			}
			if v := scanRegistrationSchema(child); v != SchemaAccepted {
				return v
			}
		}
	case []any:
		for _, item := range n {
			if v := scanRegistrationSchema(item); v != SchemaAccepted {
				return v
			}
		}
	}
	return SchemaAccepted
}

// --- work bound ----------------------------------------------------------------

// branchKeywords hold a LIST of subschemas, each of which may be evaluated against
// the same instance. They are what makes cost multiply along a reference chain:
// nesting an `anyOf` pair ten deep is 2^10 evaluations in a document a reader would
// call small.
var branchKeywords = map[string]bool{
	"anyOf": true, "oneOf": true, "allOf": true, "prefixItems": true,
}

// singleSubschemaKeywords hold exactly one subschema.
var singleSubschemaKeywords = map[string]bool{
	"not": true, "if": true, "then": true, "else": true,
	"items": true, "contains": true, "propertyNames": true,
	"additionalProperties": true, "unevaluatedProperties": true,
	"unevaluatedItems": true, "contentSchema": true,
}

// costCeiling is the saturation point. Counting stops here rather than continuing to
// a number that would overflow: past the cap the exact value carries no information,
// and a chain twenty levels longer than the cap would wrap an int to something small
// and pass.
const costCeiling = MaxRegistrationSchemaEvaluations + 1

// checkEvaluationCost bounds how much work validating a payload can cost, and — as a
// consequence of having to follow every reference to count — decides two more
// questions the compiler would otherwise answer inconsistently across the three
// languages: whether a reference cycle is present, and whether a same-document
// reference resolves at all.
func checkEvaluationCost(doc any) SchemaVerdict {
	w := &costWalker{
		root:    doc,
		anchors: map[string]any{},
		memo:    map[string]int{},
		onStack: map[string]bool{},
		verdict: SchemaAccepted,
	}
	collectAnchors(doc, w.anchors)
	cost := w.cost(doc, 0)
	if w.verdict != SchemaAccepted {
		return w.verdict
	}
	if cost > MaxRegistrationSchemaEvaluations {
		return SchemaTooComplex
	}
	return SchemaAccepted
}

type costWalker struct {
	root    any
	anchors map[string]any
	memo    map[string]int  // resolved reference location -> cost, so a target reached twice is counted once
	onStack map[string]bool // resolved locations currently being counted, which is how a cycle is seen
	verdict SchemaVerdict
}

// fail records the first failure and returns a saturated cost so the walk unwinds
// without doing more work.
func (w *costWalker) fail(v SchemaVerdict) int {
	if w.verdict == SchemaAccepted {
		w.verdict = v
	}
	return costCeiling
}

func addCost(a, b int) int {
	if a >= costCeiling || b >= costCeiling || a+b >= costCeiling {
		return costCeiling
	}
	return a + b
}

// cost is the worst-case number of subschema evaluations `node` can require against
// one instance. A boolean schema is one. An object schema is itself plus everything
// it can delegate to.
//
// $defs and definitions are deliberately NOT counted: they are reachable only
// through a reference, and counting them here as well as at the reference would
// charge a shared definition once per declaration plus once per use.
func (w *costWalker) cost(node any, hops int) int {
	if w.verdict != SchemaAccepted {
		return costCeiling
	}
	obj, ok := node.(map[string]any)
	if !ok {
		// A boolean schema, or a value in a position this walk does not model.
		return 1
	}
	total := 1
	for _, k := range sortedKeys(obj) {
		v := obj[k]
		switch {
		case nonSchemaKeywords[k] || k == "$defs" || k == "definitions":
			// Data, or a declaration that costs nothing until it is referenced.
			continue
		case isReferenceKeyword(k):
			ref, isString := v.(string)
			if !isString {
				continue
			}
			total = addCost(total, w.refCost(ref, hops+1))
		case branchKeywords[k]:
			items, isList := v.([]any)
			if !isList {
				total = addCost(total, w.cost(v, hops))
				continue
			}
			for _, item := range items {
				total = addCost(total, w.cost(item, hops))
			}
		case singleSubschemaKeywords[k]:
			total = addCost(total, w.cost(v, hops))
		case schemaMapKeywords[k]:
			sub, isMap := v.(map[string]any)
			if !isMap {
				total = addCost(total, w.cost(v, hops))
				continue
			}
			for _, name := range sortedKeys(sub) {
				total = addCost(total, w.cost(sub[name], hops))
			}
		}
		if total >= costCeiling {
			return costCeiling
		}
	}
	return total
}

// refCost counts a reference's target once and remembers it. A location already
// being counted is a cycle: its cost is not finite, and every port aborts on it
// rather than answering.
// refCost counts a reference's target once and remembers it.
//
// hops is the number of references already followed to reach this one, tracked
// explicitly rather than read off the size of onStack. The two agree here, where the
// walk recurses and onStack mirrors the path, and they do NOT agree in a port whose walk
// is iterative and whose equivalent set is a search frontier rather than a path. The
// bound is a number in the contract, so the three SDKs have to compute the same quantity
// by construction and not by coincidence.
func (w *costWalker) refCost(ref string, hops int) int {
	if c, seen := w.memo[ref]; seen {
		return c
	}
	if w.onStack[ref] {
		return w.fail(SchemaRefCycle)
	}
	// After the cycle check, so a chain that closes on itself still reports the more
	// specific diagnosis.
	if hops > MaxRegistrationSchemaRefHops {
		return w.fail(SchemaRefChainTooLong)
	}
	target, ok := w.resolve(ref)
	if !ok {
		return w.fail(SchemaUncompilable)
	}
	w.onStack[ref] = true
	c := w.cost(target, hops)
	delete(w.onStack, ref)
	w.memo[ref] = c
	return c
}

// resolve follows a same-document reference. The scan has already refused anything
// that does not begin with "#", so only three forms reach here: the whole document,
// an RFC 6901 pointer into it, and a $anchor name.
func (w *costWalker) resolve(ref string) (any, bool) {
	frag := strings.TrimPrefix(ref, "#")
	if frag == "" {
		return w.root, true
	}
	if !strings.HasPrefix(frag, "/") {
		target, ok := w.anchors[frag]
		return target, ok
	}
	node := w.root
	for _, tok := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		switch n := node.(type) {
		case map[string]any:
			next, ok := n[tok]
			if !ok {
				return nil, false
			}
			node = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(n) {
				return nil, false
			}
			node = n[i]
		default:
			return nil, false
		}
	}
	return node, true
}

// collectAnchors indexes every $anchor in the document so a "#name" reference can be
// resolved without a second walk per reference.
func collectAnchors(node any, out map[string]any) {
	switch n := node.(type) {
	case map[string]any:
		if a, ok := n["$anchor"].(string); ok {
			if _, dup := out[a]; !dup {
				out[a] = n
			}
		}
		for _, k := range sortedKeys(n) {
			collectAnchors(n[k], out)
		}
	case []any:
		for _, item := range n {
			collectAnchors(item, out)
		}
	}
}

func isReferenceKeyword(k string) bool {
	for _, kw := range referenceKeywords {
		if k == kw {
			return true
		}
	}
	return false
}

// referenceKeywords name the members whose value is a reference. $recursiveRef is
// the 2019-09 spelling; it is listed so a document mixing drafts cannot smuggle a
// remote target through a keyword this draft ignores.
var referenceKeywords = []string{"$ref", "$dynamicRef", "$recursiveRef"}

// checkSchemaKeywords applies the per-object rules: the dialect a $schema names,
// whether a reference stays inside the document, and whether a pattern is one all
// three languages express the same way.
func checkSchemaKeywords(obj map[string]any) SchemaVerdict {
	if s, ok := obj["$schema"].(string); ok && !isRegistrationSchemaDialect(s) {
		return SchemaWrongDialect
	}
	for _, kw := range referenceKeywords {
		ref, ok := obj[kw].(string)
		if !ok {
			continue
		}
		// A same-document reference starts at the document root ("#/$defs/x") or at
		// an anchor in it ("#name"). Anything else — an absolute URL, a relative file
		// name, a bare fragmentless URI — names a resource this document does not
		// carry, and resolving it is the fetch the contract forbids.
		if !strings.HasPrefix(ref, "#") {
			return SchemaRemoteRef
		}
	}
	if p, ok := obj["pattern"].(string); ok && !IsSafeSchemaPattern(p) {
		return SchemaUnsafePattern
	}
	// patternProperties states its regexes as KEYS, so they are checked here rather
	// than by the generic pattern branch above.
	if pp, ok := obj["patternProperties"].(map[string]any); ok {
		for _, p := range sortedKeys(pp) {
			if !IsSafeSchemaPattern(p) {
				return SchemaUnsafePattern
			}
		}
	}
	return SchemaAccepted
}

// isRegistrationSchemaDialect accepts the 2020-12 identifier in the two spellings
// that name the same dialect: with and without the empty fragment a URI reference
// to the whole document may carry.
func isRegistrationSchemaDialect(s string) bool {
	return s == RegistrationSchemaDialect || s == RegistrationSchemaDialect+"#"
}

// portableEscapes are the escape letters every engine spells the same way AND reads
// the same way. It is an ALLOWLIST, and that is the whole point: the set of escapes
// the three engines disagree about is open-ended, so enumerating it means adding an
// entry every time somebody finds another one. Two successive reviews found new
// counterexamples by trying, which is the signature of a rule stated from the wrong
// side. The portable set, by contrast, is small, closed and checkable.
//
//	d, D, w, W  the digit and word classes, once Python is pinned to ASCII. These
//	            are the two the whole feature would be useless without.
//	n, r, t, f, v  the control characters, identical everywhere.
//
// `x` is admitted separately, and only as \xHH with exactly two hex digits — see
// hexEscapeLen. Nothing else is: \0 is excluded even though it agrees on its own,
// because admitting it would consume the "\0" of "\012" and leave "12" as literals,
// silently admitting an octal escape the engines do NOT agree on.
//
// What the exclusions cost, and why each is right:
//
//	s, S     the whitespace class: three engines, three different sets. RE2 is
//	         [\t\n\f\r ], Python adds the vertical tab, and ECMA-262 adds both that
//	         and every Unicode space separator — so `^a\sb$` accepts a non-breaking
//	         space in one SDK and refuses it in the other two.
//	b, B     \B disagrees on the empty string: a word boundary is absent there for
//	         RE2 and ECMA-262 and present for Python, so \B matches in two engines
//	         and not the third with nothing logged. \b agrees on its own, but it is
//	         near-useless in a fully anchored field matcher and it cannot be
//	         admitted without also reasoning about [\b], which RE2 rejects outright.
//	1-9, k   backreferences: RE2 has neither, and both are the classic
//	         catastrophic-backtracking construct in the engines that do.
//	p, P     Unicode property classes: RE2 has them and ECMA-262 has them only
//	         under the `u` flag, which is not a portable assumption to build a
//	         published rule on.
//	A, z, Z  text anchors: RE2 spells them, ECMA-262 has only ^ and $.
//	-, _, :, ;, and the rest of the punctuation: escaping a character that is not
//	         a regex metacharacter is an "identity escape". RE2 and Python allow
//	         it; ECMA-262 under the `u` flag REFUSES it, and the TypeScript port's
//	         validator compiles every pattern with that flag. Write the character
//	         itself instead.
//
// The set was derived by measurement, not by reasoning: every ASCII escape was run
// through all three engines in bare, in-class and anchored position, and only those
// that compiled AND matched identically in all three, in every position, are here.
var portableEscapes = map[byte]bool{
	'd': true, 'D': true, 'w': true, 'W': true,
	'n': true, 'r': true, 't': true, 'f': true, 'v': true,
}

// portableSyntaxEscapes are the regex metacharacters an author escapes to mean the
// character itself. Unlike the identity escapes above, every engine accepts these —
// they are the characters that NEED escaping, so no dialect can refuse them.
var portableSyntaxEscapes = map[byte]bool{
	'$': true, '(': true, ')': true, '*': true, '+': true, '.': true,
	'/': true, '?': true, '[': true, '\\': true, ']': true, '^': true,
	'{': true, '|': true, '}': true,
}

// hexEscapeLen reports the length of a \xHH escape at the start of s, or 0 if s does
// not begin with one. Exactly two hex digits: \x41 is read the same by all three
// engines, while the brace form \x{41} is an RE2 spelling that the other two refuse,
// and a short \x4 is refused by all three.
func hexEscapeLen(s string) int {
	if len(s) < 4 || s[0] != '\\' || s[1] != 'x' {
		return 0
	}
	if !isHexDigit(s[2]) || !isHexDigit(s[3]) {
		return 0
	}
	return 4
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// shorthandClassEscapes are the escapes that stand for a SET of characters rather
// than for one. A set cannot be the endpoint of a range, and the engines disagree
// about whether saying so is an error or a reinterpretation.
var shorthandClassEscapes = map[byte]bool{'d': true, 'D': true, 'w': true, 'W': true}

// isRangeHyphenAt reports whether the byte at i is a "-" acting as a range operator
// inside a bracket expression, rather than the literal hyphen a class is allowed to
// end with ("[a-z-]") or begin with ("[-a-z]").
func isRangeHyphenAt(p string, i int) bool {
	return i < len(p) && p[i] == '-' && i+1 < len(p) && p[i+1] != ']'
}

// IsSafeSchemaPattern reports whether a `pattern` uses only constructs all three
// SDK languages express identically.
//
// Draft 2020-12 patterns are ECMA-262, and the three SDKs run three different
// engines over them: Go's RE2, JavaScript's RegExp, and Python's re. The three
// intersect on far less than any one of them accepts, and BOTH directions of the
// gap are a bug this face exists to close. Lookaround, atomic groups and
// backreferences are legal ECMA and refused by RE2, so a schema using them compiles
// in two SDKs and fails in the third. Inline flags, Unicode property classes, text
// anchors and POSIX bracket names run the other way — RE2 (or Python) takes them
// and JavaScript does not, or takes them to mean something else. The second kind is
// the more dangerous, because nothing errors: two SDKs both compile the pattern and
// then disagree about which payloads match it.
//
// So the admitted alphabet is the intersection, expressed as six rules:
//
//  1. an escape names a portable class, control character, \xHH, or a metacharacter
//     standing for itself — see portableEscapes, an ALLOWLIST;
//  2. a group opens with `(` or `(?:` and nothing else;
//  3. `[:` does not appear inside a bracket expression, at any position — it is a
//     POSIX class name to RE2 and the literal characters to JavaScript;
//  4. a bracket expression closes, and does not open with `]`;
//  5. a counted repeat does not exceed maxPortableRepeat;
//  6. no quantified group has a body that can itself repeat or branch.
//
// Rule 6 is aimed at catastrophic backtracking SEPARATELY and deliberately, because
// nothing in rules 1-5 covers it: `(a+)+` needs neither lookaround nor a
// backreference and sits comfortably inside the alphabet. See hasNestedQuantifier.
//
// The scan is syntactic and deliberately a little conservative. It tracks escaping,
// so a literal `\(` is not read as a group, and it tracks bracket-expression
// interiors, because the constructs above mean different things inside a class than
// outside one. Over-refusing costs an author a rewrite; under-refusing costs the SDKs
// the agreement they exist to provide.
func IsSafeSchemaPattern(p string) bool {
	inClass := false // inside a [...] bracket expression
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			if i+1 >= len(p) {
				// A trailing backslash is not a pattern any engine compiles.
				return false
			}
			if n := hexEscapeLen(p[i:]); n > 0 {
				i += n - 1 // the whole \xHH is consumed, never re-read as syntax
				continue
			}
			if !portableEscapes[p[i+1]] && !portableSyntaxEscapes[p[i+1]] {
				return false
			}
			// A range whose endpoint is a shorthand CLASS rather than a character —
			// "[\w-x]". RE2 reads it as a range and compiles; Python and ECMA-262 under
			// the `u` flag both refuse it outright. The escape itself is portable, so
			// only the adjacency is refused, and only when the "-" is a range operator
			// rather than the literal hyphen a class may end with.
			if inClass && shorthandClassEscapes[p[i+1]] && isRangeHyphenAt(p, i+2) {
				return false
			}
			i++ // the escaped character is consumed, never re-read as syntax
		case '-':
			// The mirror of the case above: "[a-\w]".
			if inClass && isRangeHyphenAt(p, i) && i+2 < len(p) && p[i+1] == '\\' && shorthandClassEscapes[p[i+2]] {
				return false
			}
		case '[':
			if inClass {
				// A literal '[' inside a class — EXCEPT when it opens a POSIX name.
				// "[:alpha:]" is a character class to RE2 and the literal characters
				// ":alph" to JavaScript: both compile, and they then match different
				// strings. Checking only at the start of the class (the earlier rule)
				// missed every position but the first, which is where a pattern like
				// "^[a[:alpha:]]+$" slipped through and produced three different
				// answers from the three SDKs.
				if strings.HasPrefix(p[i:], "[:") {
					return false
				}
				continue
			}
			inClass = true
			// A ']' immediately after the opening bracket (or after a leading '^') is
			// a literal in POSIX and an empty class in ECMA — engines disagree about
			// whether that even compiles, so the whole shape is refused.
			rest := p[i+1:]
			rest = strings.TrimPrefix(rest, "^")
			if strings.HasPrefix(rest, "]") || rest == "" {
				return false
			}
			if strings.HasPrefix(p[i:], "[[:") {
				return false
			}
		case ']':
			if !inClass {
				// An unmatched ']' is a literal to RE2 and a syntax error to ajv.
				return false
			}
			inClass = false
		case '(':
			if inClass {
				continue // a literal paren
			}
			if i+1 >= len(p) || p[i+1] != '?' {
				continue // a plain capturing group
			}
			// Everything spelled "(?..." is refused except the non-capturing group,
			// which is the only one all three engines write the same way. That covers
			// lookaround "(?=" "(?!" "(?<=" "(?<!", the atomic group "(?>", inline
			// flags "(?i)", and the named group whose spelling differs ("(?<n>" in
			// ECMA, "(?P<n>" in Go).
			if i+2 >= len(p) || p[i+2] != ':' {
				return false
			}
			i += 2
		case '{':
			if inClass {
				continue
			}
			// A quantifier whose bound is absent or enormous parts the engines: ajv
			// reads a bare "{" as a literal where RE2 errors, and RE2 caps a repeat
			// count that the other two expand.
			n := quantifierLen(p[i:])
			if n == 0 {
				return false
			}
			i += n - 1 // consume through the closing brace
		case '}':
			if inClass {
				continue // a literal brace inside a class
			}
			// Every well-formed quantifier was stepped over above, so a "}" reached
			// here closes nothing. RE2 and Python read it as a literal and ECMA-262
			// under the `u` flag refuses it outright — the same split the unmatched
			// "]" rule above exists for, so it gets the same answer. A literal brace
			// is written "\}", which the alphabet admits.
			return false
		}
	}
	// An unclosed class is a literal '[' to RE2 and a syntax error to ajv.
	if inClass {
		return false
	}
	return !hasNestedQuantifier(p)
}

// hasNestedQuantifier reports whether the pattern quantifies a group whose body can
// itself repeat or branch — the shape that makes a backtracking engine explore
// exponentially many ways to match one input.
//
// This is the OTHER half of the catastrophic-backtracking answer, and the half that
// was missing. Excluding lookaround and backreferences removes one family; nested
// quantifiers need neither, and every classic form — (a+)+, (a|a)*, ([a-z]+)*,
// (?:a*)* — sits comfortably inside the rest of the alphabet. Go is safe regardless
// because RE2 does not backtrack, but Python and JavaScript are not, and a timer
// cannot rescue them: a regex spin holds CPython's interpreter and blocks Node's
// event loop, so the bound has to be static or it does not exist.
//
// The test is deliberately coarse — a quantified group whose body contains any of
// `* + ? { |`. Deciding whether a particular body is genuinely ambiguous is not
// decidable in general, and the conservative answer costs an author a rewrite while
// the permissive one costs a service its availability. Simple repetition still
// works: `(?:ab)+` is admitted, `(?:a|ab)+` is not.
func hasNestedQuantifier(p string) bool {
	inClass := false
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '(':
			if inClass {
				continue
			}
			body, after, ok := groupBody(p, i)
			if !ok {
				continue
			}
			// A non-capturing group's "?:" is syntax, not content — reading it as
			// content would flag every "(?:...)+" as nested.
			body = strings.TrimPrefix(body, "?:")
			if isQuantifier(p, after) && strings.ContainsAny(stripEscapes(body), "*+?{|") {
				return true
			}
		}
	}
	return false
}

// groupBody returns the text between the parenthesis at open and its match, plus the
// index just past the closing parenthesis.
func groupBody(p string, open int) (body string, after int, ok bool) {
	depth, inClass := 0, false
	for i := open; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if inClass {
				continue
			}
			depth--
			if depth == 0 {
				return p[open+1 : i], i + 1, true
			}
		}
	}
	return "", 0, false
}

// isQuantifier reports whether a repetition operator starts at i.
func isQuantifier(p string, i int) bool {
	if i >= len(p) {
		return false
	}
	switch p[i] {
	case '*', '+', '?', '{':
		return true
	}
	return false
}

// stripEscapes removes escaped characters so an escaped metacharacter (`\+`) is not
// read as a quantifier.
func stripEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// maxPortableRepeat is the largest {n,m} bound admitted. RE2 refuses a repeat count
// over 1000 outright while the other two engines expand it, so a larger bound is a
// pattern one SDK compiles and another does not.
const maxPortableRepeat = 1000

// quantifierLen reports the length of the counted repeat starting at s, including its
// closing brace, or 0 if s does not open one every engine reads the same way. A "{"
// that opens no valid quantifier is refused rather than treated as a literal, because
// whether it IS a literal is precisely what the engines disagree about.
//
// It returns a LENGTH rather than a bool so the caller can consume the whole "{n,m}".
// That is what lets an unmatched "}" be refused: once every well-formed quantifier is
// stepped over, a "}" the scan still reaches closes nothing.
//
// The first bound must be present. "a{,5}" is the shape that forced this: RE2 reads it
// as the five literal characters and Python reads it as a repeat of zero to five, so
// both engines compile the pattern and then disagree about which payloads match it,
// with nothing logged. The empty part is still allowed AFTER the comma, because "{n,}"
// is the ordinary open-ended repeat and every engine agrees on it.
func quantifierLen(s string) int {
	end := strings.IndexByte(s, '}')
	if end < 0 {
		return 0
	}
	body := s[1:end]
	if body == "" {
		return 0
	}
	for i, part := range strings.SplitN(body, ",", 2) {
		if part == "" {
			if i == 0 {
				return 0 // "{,5}" — two engines, two readings
			}
			continue // "{n,}" is well formed
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > maxPortableRepeat {
			return 0
		}
	}
	return end + 1
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- failure reporting --------------------------------------------------------

// violationsFrom flattens a validation failure into one entry per violated
// constraint: the leaves of the cause tree are the individual failures, and the
// interior nodes are the composite keywords that grouped them.
func violationsFrom(verr *jsonschema.ValidationError) []schemaViolation {
	// Deduplication is by (pointer, keyword) — a SET, not a list. Two branches of a
	// failing oneOf can both report `required` at the same pointer, and the three
	// libraries disagree about how many such duplicates they surface: one reports
	// every branch, another reports the composite once with the branches as context.
	// A count that varies by library is a count no shared corpus can pin, so the
	// answer is deliberately the set of DISTINCT constraints that failed. Where a key
	// repeats, the lexicographically smallest text wins, so the prose Go emits does
	// not depend on which duplicate the library happened to walk first.
	seen := map[string]int{}
	var flat []schemaViolation

	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c)
			}
			return
		}
		kw, text := describeViolation(e.ErrorKind)
		path := clampPointer(jsonPointerOf(e.InstanceLocation))
		key := path + "\x00" + kw
		if at, ok := seen[key]; ok {
			if text < flat[at].Text {
				flat[at].Text = text
			}
			return
		}
		seen[key] = len(flat)
		flat = append(flat, schemaViolation{Path: path, Keyword: kw, Text: text})
	}
	walk(verr)
	if len(flat) == 0 {
		return nil
	}

	// Deterministic order, then the cap. Sorting before capping means the SAME 64
	// entries survive in every language, which is what lets one corpus pin the
	// truncation case at all.
	sort.Slice(flat, func(i, j int) bool {
		if flat[i].Path != flat[j].Path {
			return flat[i].Path < flat[j].Path
		}
		return flat[i].Keyword < flat[j].Keyword
	})
	if len(flat) > MaxRegistrationFieldErrors {
		flat = flat[:MaxRegistrationFieldErrors]
	}
	return flat
}

// jsonPointerOf renders an instance location as an RFC 6901 pointer. The empty
// location is the empty pointer, which addresses registration_data itself — how a
// whole-object failure (oneOf, minProperties) that belongs to no single member is
// reported.
func jsonPointerOf(loc []string) string {
	if len(loc) == 0 {
		return ""
	}
	var b strings.Builder
	for _, tok := range loc {
		b.WriteByte('/')
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(tok))
	}
	return b.String()
}

// Both bounds below are counted in CHARACTERS — Unicode code points — because that
// is what protovalidate's string.max_len counts. Counting bytes instead (Go's
// natural len) makes this SDK clamp earlier than the wire requires and, worse,
// earlier than the other two SDKs do, so the three name DIFFERENT members for the
// same failure. Counting UTF-16 units, JavaScript's natural length, parts from both.

// clampPointer keeps a pointer inside the wire's length bound WITHOUT truncating it.
// A pointer cut mid-token addresses a different member — or none — so an over-long
// one degrades to the longest ANCESTOR that fits: less precise, still true. The empty
// pointer is the floor, and it is always within the bound.
func clampPointer(p string) string {
	if utf8.RuneCountInString(p) <= MaxRegistrationFieldErrorPathLen {
		return p
	}
	best := ""
	for i, r := range p {
		if r != '/' || i == 0 {
			continue
		}
		if utf8.RuneCountInString(p[:i]) > MaxRegistrationFieldErrorPathLen {
			break
		}
		best = p[:i]
	}
	return best
}

// clampText keeps the constraint text inside the wire's bound, cutting only on a
// character boundary: a byte-wise cut through a multi-byte character produces invalid
// UTF-8, and proto.Marshal then refuses the refusal — a failure that appears only on
// the unhappy path, which is the worst place for one. The field also has a minimum of
// one character, so an empty description becomes a generic one rather than a message
// the contract would reject.
func clampText(s string) string {
	if s == "" {
		return "does not conform to the published schema"
	}
	if utf8.RuneCountInString(s) <= MaxRegistrationFieldErrorTextLen {
		return s
	}
	n := 0
	for i := range s {
		if n == MaxRegistrationFieldErrorTextLen {
			return s[:i]
		}
		n++
	}
	return s
}

// describeViolation turns a failure into (keyword, constraint text).
//
// It reads ONLY the constraint side of each error kind. The library's own message
// rendering is never used, because it quotes the offending value — «"DE12345" does
// not match pattern ...» — and the wire contract forbids a refusal from carrying the
// submitted value back out. Everything below names the keyword and, where it is
// short and comes from the SCHEMA rather than the payload, the bound that was
// violated.
func describeViolation(k jsonschema.ErrorKind) (keyword, text string) {
	switch e := k.(type) {
	case *kind.Required:
		return "required", "required: " + strings.Join(e.Missing, ", ")
	case *kind.Type:
		return "type", "must be of type " + strings.Join(e.Want, " or ")
	case *kind.Pattern:
		return "pattern", "must match " + e.Want
	case *kind.MinLength:
		return "minLength", "minLength: " + strconv.Itoa(e.Want)
	case *kind.MaxLength:
		return "maxLength", "maxLength: " + strconv.Itoa(e.Want)
	case *kind.MinProperties:
		return "minProperties", "minProperties: " + strconv.Itoa(e.Want)
	case *kind.MaxProperties:
		return "maxProperties", "maxProperties: " + strconv.Itoa(e.Want)
	case *kind.MinItems:
		return "minItems", "minItems: " + strconv.Itoa(e.Want)
	case *kind.MaxItems:
		return "maxItems", "maxItems: " + strconv.Itoa(e.Want)
	case *kind.Minimum:
		return "minimum", "minimum: " + e.Want.RatString()
	case *kind.Maximum:
		return "maximum", "maximum: " + e.Want.RatString()
	case *kind.ExclusiveMinimum:
		return "exclusiveMinimum", "exclusiveMinimum: " + e.Want.RatString()
	case *kind.ExclusiveMaximum:
		return "exclusiveMaximum", "exclusiveMaximum: " + e.Want.RatString()
	case *kind.MultipleOf:
		return "multipleOf", "multipleOf: " + e.Want.RatString()
	case *kind.Enum:
		// The allowed values come from the schema, not the payload, but they can be
		// long and they are not needed to act on the refusal.
		return "enum", "must be one of the values the schema enumerates"
	case *kind.Const:
		return "const", "must equal the value the schema fixes"
	case *kind.OneOf:
		return "oneOf", "must match exactly one branch of oneOf"
	case *kind.AnyOf:
		return "anyOf", "must match at least one branch of anyOf"
	case *kind.AllOf:
		return "allOf", "must match every branch of allOf"
	case *kind.Not:
		return "not", "must not match the schema under not"
	case *kind.Contains:
		return "contains", "must contain a matching item"
	case *kind.UniqueItems:
		return "uniqueItems", "items must be unique"
	case *kind.AdditionalProperties:
		// The offending property NAMES are omitted: they come off the payload, and a
		// member name an operator chose is as much their data as its value.
		return "additionalProperties", "additional properties are not allowed"
	case *kind.PropertyNames:
		return "propertyNames", "property name does not match propertyNames"
	case *kind.DependentRequired:
		return "dependentRequired", "dependentRequired: " + strings.Join(e.Missing, ", ")
	case *kind.FalseSchema:
		return "false", "not allowed by the schema"
	}
	// Anything this switch does not name still reports the keyword that failed, which
	// is enough to act on and carries nothing off the payload by construction.
	if kp := k.KeywordPath(); len(kp) > 0 {
		last := kp[len(kp)-1]
		return last, "does not satisfy " + last
	}
	return "schema", "does not conform to the published schema"
}

// MaxRegistrationDataBytes bounds a submitted registration_data payload, measured as
// its RFC 8785 canonical JSON encoding.
//
// The UNIT has to be named, and that is the whole point of this constant. Every other
// cap in this file is over bytes a party actually served; registration_data is not
// served as bytes at all — it arrives as a decoded google.protobuf.Struct — so "16KB"
// means nothing until an encoding is chosen, and two implementations choosing
// privately is the disagreement this package exists to remove. JCS is the choice
// because all three SDKs already compute it for the signing primitive, with a vetted
// canonicalizer each, and because it pins number formatting: a payload carrying 1e300
// is seven bytes to one renderer and three hundred to another.
//
// It bounds WORK, not storage. The schema's own caps bound the schema; nothing bounded
// the payload the schema is applied to, and validation cost is roughly the schema's
// cost multiplied by the elements in the payload — a subschema under `items` is
// counted once by MaxRegistrationSchemaEvaluations and evaluated once per element.
// The multiplier was the unbounded half.
const MaxRegistrationDataBytes = 16384

// MaxRegistrationDataMembers bounds the number of members at the TOP LEVEL of a
// registration_data payload. Top level rather than recursive, deliberately: nested
// bulk is already bounded by the byte cap above, and a recursive count would refuse a
// small document that merely nests, which a business entity legitimately does
// (an address is an object).
const MaxRegistrationDataMembers = 64

// RegistrationDataVerdict is the outcome of checking a submitted registration_data
// payload against the bounds above.
type RegistrationDataVerdict int

const (
	// RegistrationDataNoVerdict is the zero value: nothing was decided. It is first so
	// a caller who ignores the result reads "no answer" rather than an acceptance, and
	// it is never returned.
	RegistrationDataNoVerdict RegistrationDataVerdict = iota

	// RegistrationDataAccepted means the payload is within every bound. It says
	// nothing about whether the payload conforms to a published schema — that is
	// RegistrationSchema.Validate, and it runs after this.
	RegistrationDataAccepted

	// RegistrationDataTooLarge means the canonical encoding exceeds
	// MaxRegistrationDataBytes.
	RegistrationDataTooLarge

	// RegistrationDataTooManyMembers means the top level carries more than
	// MaxRegistrationDataMembers members.
	RegistrationDataTooManyMembers

	// RegistrationDataUncanonicalizable means the payload has no canonical JSON form —
	// a non-finite number is the reachable case, since JSON has no NaN or Infinity and
	// a decoded map can still hold one. It is a verdict rather than an error because
	// this face, like the rest of the registration surface, does not throw.
	RegistrationDataUncanonicalizable
)

// String renders the verdict as the token the shared corpus records.
func (v RegistrationDataVerdict) String() string {
	switch v {
	case RegistrationDataNoVerdict:
		return "no_verdict"
	case RegistrationDataAccepted:
		return "accepted"
	case RegistrationDataTooLarge:
		return "too_large"
	case RegistrationDataTooManyMembers:
		return "too_many_members"
	case RegistrationDataUncanonicalizable:
		return "uncanonicalizable"
	default:
		return "no_verdict"
	}
}

// CheckRegistrationData bounds a submitted registration_data payload.
//
// data is the decoded object — RegisterRequest.GetRegistrationData().AsMap() at a call
// site. A nil or empty payload is accepted: sending no business data is a matter for
// the published schema's `required` list, not for a size bound.
//
// This runs BEFORE RegistrationSchema.Validate, for the same reason the schema's size
// cap runs before the schema is parsed: the bound exists to stop work, so it has to
// precede the work. An Exchange refuses an over-bound payload outright — this is a
// malformed request rather than a schema failure, so it is NOT
// REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA, which names non-conformance
// to a published schema and applies only when one is published.
func CheckRegistrationData(data map[string]any) RegistrationDataVerdict {
	// Members first: it is a length check, and it bounds the document the canonical
	// encoding below then has to walk.
	if len(data) > MaxRegistrationDataMembers {
		return RegistrationDataTooManyMembers
	}
	n, err := registrationDataBytes(data)
	if err != nil {
		return RegistrationDataUncanonicalizable
	}
	if n > MaxRegistrationDataBytes {
		return RegistrationDataTooLarge
	}
	return RegistrationDataAccepted
}

// registrationDataBytes returns the length of the payload's RFC 8785 canonical JSON
// encoding. A nil map encodes as the empty object rather than as `null`, so an absent
// payload and an empty one measure the same.
func registrationDataBytes(data map[string]any) (int, error) {
	if data == nil {
		data = map[string]any{}
	}
	raw, err := json.Marshal(data)
	if err != nil {
		// The reachable case is a non-finite float, which JSON cannot represent.
		return 0, fmt.Errorf("helpers: registration_data has no JSON form: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return 0, fmt.Errorf("helpers: registration_data JCS transform: %w", err)
	}
	return len(canon), nil
}
