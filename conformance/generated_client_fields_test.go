package conformance

// Completeness guard: every contract field reaches BOTH generated clients.
//
// The proto -> JSON Schema -> Pydantic/Zod pipeline has several rewriting steps, and a
// step that removes a key removes it silently — the output is still a valid document,
// still generates, still parses. The corpus cannot see it: corpusgen emits cases only
// for fields carrying a protovalidate rule, so a field with no rule has no case, and a
// field that vanishes from the clients has nothing to round-trip. Every gate stayed
// green while Offer.title, ResourceEntry.title and UsageAsset.title were absent from
// both clients outright — the merge step stripped every key named `title`, meaning to
// remove the JSON-Schema keyword and taking three real fields with it.
//
// So the invariant is stated directly and independently of any rule: for each message
// in the contract, the generated Pydantic model and the generated Zod schema each carry
// a property per proto field, under the proto field's own snake_case name.
//
// It reads the two committed artifacts as TEXT rather than importing them, for the
// reason ver_field_contract_test.go gives: this package is the guard tier BELOW the
// SDKs and the generated clients are Python and TypeScript, which Go cannot import. A
// committed generated file is a data read exactly like the corpus.
//
// The proto is authoritative. On failure the pipeline has dropped something the wire
// declares; fix scripts/sdk-types/ and regenerate — never delete the field here.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	pydanticModels = "../gen/python/wire/models.py"
	zodSchemas     = "../gen/ts/wire/schemas.ts"
)

// pydanticClassRe reads the header of one generated model. The body is taken by
// splitting on the next top-level `class`, not by a lookahead — RE2 has none.
var pydanticClassRe = regexp.MustCompile(`^(\w+)\(WireModel\):\n`)

// pydanticFieldRe finds the field names declared in a model body. datamodel-code-generator
// emits `    <name>: <annotation>` at exactly one level of indentation.
var pydanticFieldRe = regexp.MustCompile(`(?m)^    ([a-z][a-z0-9_]*): `)

// TestGeneratedClientsCarryEveryContractField asserts no proto field is missing from the
// generated Pydantic models or Zod schemas.
func TestGeneratedClientsCarryEveryContractField(t *testing.T) {
	pydantic := pydanticFields(t)
	zod := readFile(t, zodSchemas)

	EachMessage(func(md protoreflect.MessageDescriptor) {
		name := string(md.Name())
		// The merged $defs are keyed by BARE message name, which AssertUniqueBareNames
		// already proves unambiguous, so a bare lookup is the right one here too.
		got, ok := pydantic[name]
		if !ok {
			t.Errorf("message %s has no generated Pydantic model", name)
			return
		}
		schema, ok := zodSchemaOf(zod, name)
		if !ok {
			t.Errorf("message %s has no generated Zod schema", name)
			return
		}
		// The message's OWN keys, not every key on the line. json-schema-to-zod inlines
		// each nested message into the same expression, so a substring search would let a
		// nested field of the same name stand in for a missing outer one — and `ext`,
		// `ver` and `exchange` recur throughout the contract, so that is the common case
		// rather than a corner of it.
		zodKeys := zodTopLevelKeys(schema)
		if len(zodKeys) == 0 {
			t.Errorf("message %s: no properties read out of its generated Zod schema — "+
				"the scan, not the output, is wrong", name)
			return
		}
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			field := string(fields.Get(i).Name())
			if _, ok := got[field]; !ok {
				t.Errorf("%s.%s is declared in the proto and missing from %s",
					name, field, pydanticModels)
			}
			if _, ok := zodKeys[field]; !ok {
				t.Errorf("%s.%s is declared in the proto and missing from %s",
					name, field, zodSchemas)
			}
		}
	})
}

// pydanticFields maps each generated model name to the set of field names it declares.
func pydanticFields(t *testing.T) map[string]map[string]struct{} {
	t.Helper()
	out := map[string]map[string]struct{}{}
	// Each chunk after the split starts at a class header; the rest of it is that
	// class's body, since the next header is where the next chunk begins.
	for _, chunk := range strings.Split(readFile(t, pydanticModels), "\nclass ") {
		header := pydanticClassRe.FindStringSubmatch(chunk)
		if header == nil {
			continue
		}
		fields := map[string]struct{}{}
		for _, f := range pydanticFieldRe.FindAllStringSubmatch(chunk, -1) {
			fields[f[1]] = struct{}{}
		}
		out[header[1]] = fields
	}
	if len(out) == 0 {
		t.Fatalf("no generated models found in %s — the scan, not the output, is wrong", pydanticModels)
	}
	return out
}

// zodSchemaOf returns one generated Zod schema. json-schema-to-zod emits each on a
// single line, so the line IS the schema.
func zodSchemaOf(source, message string) (string, bool) {
	marker := "export const " + message + "Schema = "
	start := strings.Index(source, marker)
	if start < 0 {
		return "", false
	}
	rest := source[start:]
	if end := strings.IndexByte(rest, '\n'); end >= 0 {
		return rest[:end], true
	}
	return rest, true
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// zodTopLevelKeys returns the property names of a generated Zod schema's OWN object.
//
// json-schema-to-zod emits a whole message — nested messages inlined — as one expression
// on one line, so telling the message's own fields from its children's means tracking
// brace depth rather than searching text. Strings are skipped as units: a field
// description is arbitrary prose, and an enum's values sit at the same depth as the keys.
func zodTopLevelKeys(schema string) map[string]struct{} {
	out := map[string]struct{}{}
	open := strings.Index(schema, "z.object({")
	if open < 0 {
		return out
	}
	depth := 1
	for i := open + len("z.object({"); i < len(schema); i++ {
		switch schema[i] {
		case '"':
			end := i + 1
			for end < len(schema) && schema[end] != '"' {
				if schema[end] == '\\' {
					end++ // an escaped byte, including an escaped quote
				}
				end++
			}
			// A property key is a string at this object's own depth followed by a colon.
			// An enum value or a describe() argument sits at the same depth and is not.
			if depth == 1 && end+1 < len(schema) && schema[end+1] == ':' {
				out[schema[i+1:end]] = struct{}{}
			}
			i = end
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return out
			}
		}
	}
	return out
}

// TestZodTopLevelKeysReadsOneMessage proves the scan above distinguishes a message's own
// fields from the nested ones json-schema-to-zod inlines beside them.
//
// Without it the guard was satisfiable by accident: TransactionResponse does not declare
// transaction_id — it lives one level down in TransactionResultItem — yet a substring
// search over the line finds it, so the outer message could lose a field of that name and
// the guard would still pass. `ext`, `ver` and `exchange` recur across the contract the
// same way.
func TestZodTopLevelKeysReadsOneMessage(t *testing.T) {
	schema, ok := zodSchemaOf(readFile(t, zodSchemas), "TransactionResponse")
	if !ok {
		t.Fatal("no generated Zod schema for TransactionResponse")
	}
	keys := zodTopLevelKeys(schema)
	for _, own := range []string{"ver", "items", "agent_identity_hash", "ext"} {
		if _, found := keys[own]; !found {
			t.Errorf("%s is TransactionResponse's own field and was not read", own)
		}
	}
	// Declared by TransactionResultItem, inlined into the same expression.
	if _, found := keys["transaction_id"]; found {
		t.Error("transaction_id is a nested field and must not read as TransactionResponse's own")
	}
	if !strings.Contains(schema, `"transaction_id":`) {
		t.Error("the nested field is absent from the line entirely — this test proves nothing")
	}
}
