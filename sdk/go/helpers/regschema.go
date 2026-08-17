package helpers

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

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
//	same-document references are admitted, and the compiler is built with no
//	URLLoader, so a reference this package missed fails closed rather than dials.
//
//	The dialect is pinned. Draft 2020-12 only: a validator that silently accepted
//	an older draft would apply DIFFERENT semantics to the same document than a peer
//	that refused it, which is the disagreement this face exists to prevent.
//
//	Resources are bounded. A size cap, a nesting-depth cap, and a narrowed `pattern`
//	alphabet, all measured before the schema is compiled.
//
// The pattern rule does double duty and the second job is the load-bearing one.
// Draft 2020-12 `pattern` is ECMA-262, so lookaround and backreferences are legal
// there — and Go's RE2 refuses them at compile time while JavaScript and Python
// accept them. Left alone, the SAME schema compiles in two of this SDK's three
// languages and fails in the third, which is exactly the cross-implementation
// disagreement the shared rules are for. Narrowing the alphabet to what all three
// can express makes the verdict identical everywhere, and removes the largest
// catastrophic-backtracking class as a side effect.
//
// Everything here is pure: bytes in, verdict out, no IO and no state, which is why
// it sits in the IO-free tier and can run before any network or database is
// touched. Bounding compile TIME is deliberately not a timer in Go — the caps above
// bound the work structurally and RE2 matches in linear time, so a wall clock would
// add nondeterminism that the shared conformance vectors could not pin. The ports
// whose engines backtrack carry that bound instead.

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

// RegistrationSchemaDialect is the only $schema value a published data_schema may
// name. A document that names none is read as this dialect; one that names another
// is refused rather than validated under semantics its author did not intend.
const RegistrationSchemaDialect = "https://json-schema.org/draft/2020-12/schema"

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
	// Schema at its top level (2020-12 admits an object or a boolean, nothing else).
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

	// SchemaUncompilable means the document is well-formed JSON, passes the rules
	// above, and is still not a valid 2020-12 schema.
	SchemaUncompilable
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
	case SchemaUncompilable:
		return "uncompilable"
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
	// Size first, on the bytes as served and before any parse: an oversized document
	// must not be decoded to find out that it was oversized.
	if len(raw) > MaxRegistrationSchemaBytes {
		return nil, SchemaTooLarge
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
	switch doc.(type) {
	case map[string]any, bool:
	default:
		return nil, SchemaMalformed
	}
	if v := scanRegistrationSchema(doc); v != SchemaAccepted {
		return nil, v
	}

	c := jsonschema.NewCompiler()
	// No URL loader is installed, deliberately. Without one the library refuses to
	// resolve any reference it does not already hold, so a remote reference the scan
	// above did not recognise fails closed here instead of dialing. The scan is the
	// rule the ports implement; this is the backstop under it, and a guard in the
	// tests pins the absence at the source since it has no runtime footprint.
	c.DefaultDraft(jsonschema.Draft2020)
	// format / contentEncoding / contentMediaType stay ANNOTATIONS, never assertions.
	// The three languages' libraries default differently, so leaving this to a
	// default would make the same document conform in one SDK and not in another.
	const schemaURL = "ramp:registration-data-schema"
	if err := c.AddResource(schemaURL, doc); err != nil {
		return nil, SchemaUncompilable
	}
	sch, err := c.Compile(schemaURL)
	if err != nil {
		return nil, SchemaUncompilable
	}
	return &RegistrationSchema{sch: sch}, SchemaAccepted
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

// divergentEscapes are the escape letters whose meaning is not shared by all three
// engines. Each would otherwise let one SDK accept a schema another refuses, or —
// worse, because it is silent — let two SDKs accept the same schema and disagree
// about which payloads match it.
//
//	1-9, k  backreferences (\1, \k<name>): RE2 has neither, and both are the
//	        classic catastrophic-backtracking construct in the engines that do.
//	p, P    Unicode property classes: RE2 has them, ECMA-262 needs the `u` flag
//	        that a JSON Schema `pattern` is not compiled with.
//	A, z, Z text anchors: RE2 spells them, ECMA-262 has only ^ and $.
//	Q, E    literal spans: RE2 only.
//	C, G, K single-engine escapes with no counterpart anywhere else.
var divergentEscapes = map[byte]bool{
	'1': true, '2': true, '3': true, '4': true, '5': true,
	'6': true, '7': true, '8': true, '9': true,
	'k': true, 'p': true, 'P': true,
	'A': true, 'z': true, 'Z': true,
	'Q': true, 'E': true,
	'C': true, 'G': true, 'K': true,
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
// So the admitted alphabet is the intersection, expressed as three rules: a group
// opens with `(` or `(?:` and nothing else; an escape names a character or one of
// the shared classes; and `[[:` — a POSIX class to RE2 and a literal bracket to
// JavaScript — never appears. Refusing catastrophic backtracking falls out of the
// first rule rather than being aimed at separately.
//
// The scan is syntactic and deliberately a little conservative: it tracks escaping,
// so a literal `\(` is not read as a group, but it does not model character-class
// interiors, where these constructs cannot carry their special meaning anyway.
// Over-refusing costs an author a rewrite; under-refusing costs the SDKs the
// agreement they exist to provide.
func IsSafeSchemaPattern(p string) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			if i+1 >= len(p) {
				// A trailing backslash is not a pattern any engine compiles.
				return false
			}
			if divergentEscapes[p[i+1]] {
				return false
			}
			i++ // the escaped character is consumed, never re-read as syntax
		case '(':
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
		case '[':
			// "[[:alpha:]]" is a POSIX class to RE2 and a bracket expression matching
			// the literal characters ":alph" to JavaScript — the same pattern, two
			// different languages of matching strings, with no error on either side.
			if strings.HasPrefix(p[i:], "[[:") {
				return false
			}
		}
	}
	return true
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

// clampPointer keeps a pointer inside the wire's length bound WITHOUT truncating
// it. A pointer cut mid-token addresses a different member — or none — so an
// over-long one degrades to the longest ANCESTOR that fits: less precise, still
// true. The empty pointer is the floor, and it is always within the bound.
func clampPointer(p string) string {
	if len(p) <= MaxRegistrationFieldErrorPathLen {
		return p
	}
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' && i <= MaxRegistrationFieldErrorPathLen {
			return p[:i]
		}
	}
	return ""
}

// clampText keeps the constraint text inside the wire's bound. The field also has a
// minimum of one character, so an empty description becomes a generic one rather
// than a message the contract would reject.
func clampText(s string) string {
	if s == "" {
		return "does not conform to the published schema"
	}
	if len(s) > MaxRegistrationFieldErrorTextLen {
		return s[:MaxRegistrationFieldErrorTextLen]
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
