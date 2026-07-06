package conformance

import (
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// camelProtoFieldNames returns the set of camelCase json_names of every RAMP proto
// field whose json_name differs from its snake_case proto name (i.e. the multiword
// fields). These are the ONLY camelCase keys that are RAMP wire fields — a doc example
// keying one of them in camelCase is a wire↔client mismatch (dropped by the snake-only
// clients; if the field is required, a hard reject). Single-word fields (amount, rate)
// and non-proto content payloads (mcpServers, companyInfo, …) are intentionally absent.
func camelProtoFieldNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), "ramp.v1") {
			return true
		}
		var visit func(msgs protoreflect.MessageDescriptors)
		visit = func(msgs protoreflect.MessageDescriptors) {
			for i := 0; i < msgs.Len(); i++ {
				md := msgs.Get(i)
				fields := md.Fields()
				for j := 0; j < fields.Len(); j++ {
					f := fields.Get(j)
					if jn := f.JSONName(); jn != string(f.Name()) {
						out[jn] = true
					}
				}
				visit(md.Messages()) // nested
			}
		}
		visit(fd.Messages())
		return true
	})
	if len(out) == 0 {
		t.Fatal("no ramp.v1 multiword proto fields found — are the generated types imported/registered?")
	}
	return out
}

var docJSONKeyRe = regexp.MustCompile(`"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:`)

// TestDocExamplesAreSnakeCase closes the harness blind spot behind RN1: the wire is
// snake_case proto-JSON, but nothing parsed doc code blocks through the client naming,
// so camelCase RAMP field keys (e.g. required `idempotencyKey`) survived in walkthrough
// examples and are hard-rejected by the generated clients. This fails if any doc code
// fence uses the camelCase json_name of a real proto field as a JSON key.
func TestDocExamplesAreSnakeCase(t *testing.T) {
	camel := camelProtoFieldNames(t)
	walkDocs(t, func(path, content string) {
		for _, fence := range codeFences(content) {
			for _, m := range docJSONKeyRe.FindAllStringSubmatch(fence, -1) {
				key := m[1]
				if camel[key] {
					t.Errorf("%s: doc example uses camelCase RAMP field key %q — the wire is snake_case proto-JSON; the snake-only clients drop it (and hard-reject if the field is required)", path, key)
				}
			}
		}
	})
}
