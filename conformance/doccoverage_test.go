// Package conformance — doccoverage_test.go holds the doc-completeness guard.
//
// The existing doc-conformance gate (scripts/check-doc-conformance.sh) is a
// denylist: it catches a REMOVED or RENAMED identifier that lingers in the docs.
// It is structurally blind to the opposite failure — a type, field, RPC, or enum
// that was ADDED to the contract but never documented. That omission class is
// exactly what slipped through review (a whole service and a response field
// absent from the reference page while every guard stayed green).
//
// This test closes it: it walks the descriptor and asserts the reference page
// (reference/proto-ramp.mdx) documents every service+method, every top-level
// message and its fields, and every enum. Scope is the descriptor, so a newly
// added symbol is in scope the instant it exists. The only hand-maintained
// surface is docCoverageExempt, which the test proves is necessary on every run.
package conformance

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

const refPagePath = "../website/src/content/docs/reference/proto-ramp.mdx"

// docCoverageExempt lists "Type" or "Type.field" symbols that are intentionally
// not documented on the reference page, each with a reason. The test proves each
// entry is still real (the type/field exists) and still needed (it is in fact
// absent from its section) — self-cleaning in both directions.
var docCoverageExempt = map[string]string{}

// headingRe matches a markdown section heading and captures its text.
var headingRe = regexp.MustCompile(`(?m)^#{2,6}\s+(.+?)\s*$`)

// refSections splits the reference page into sections keyed by their heading
// text, each section's body running until the next heading of equal-or-higher
// level. Fenced code blocks are stripped first so a `#` inside a fence is never
// mistaken for a heading.
func refSections(t *testing.T) (sections map[string]string, whole string) {
	t.Helper()
	b, err := os.ReadFile(refPagePath)
	if err != nil {
		t.Fatalf("reading reference page %s: %v (wrong working directory?)", refPagePath, err)
	}
	whole = string(b)
	// Strip fenced code blocks for heading detection.
	noFence := regexp.MustCompile("(?s)```.*?```").ReplaceAllString(whole, "")
	idx := headingRe.FindAllStringSubmatchIndex(noFence, -1)
	sections = map[string]string{}
	for i, m := range idx {
		name := strings.TrimSpace(noFence[m[2]:m[3]])
		bodyStart := m[1]
		bodyEnd := len(noFence)
		if i+1 < len(idx) {
			bodyEnd = idx[i+1][0]
		}
		sections[name] = noFence[bodyStart:bodyEnd]
	}
	if len(sections) == 0 {
		t.Fatalf("no headings parsed from %s — format drifted; this guard would be vacuous.", refPagePath)
	}
	return
}

// backticked reports whether `tok` appears wrapped in backticks anywhere in body
// (the table-cell form the reference page uses for field/RPC names).
func backticked(body, tok string) bool {
	return strings.Contains(body, "`"+tok+"`")
}

func TestReferencePageCoversContract(t *testing.T) {
	sections, whole := refSections(t)
	used := map[string]bool{}
	exempt := func(key string) bool {
		if _, ok := docCoverageExempt[key]; ok {
			used[key] = true
			return true
		}
		return false
	}

	var missing []string
	flag := func(format, key string) {
		missing = append(missing, format)
		_ = key
	}

	f := rampv1.File_ramp_v1_ramp_proto

	// A `::proto-message|service|enum{name=X}` directive renders X (and ALL its
	// members) straight from the descriptor — coverage by construction. Collect
	// the generated targets; a generated type needs no per-member check.
	directiveRe := regexp.MustCompile(`::proto-(?:message|service|enum)\{name=([A-Za-z0-9]+)`)
	generated := map[string]bool{}
	for _, m := range directiveRe.FindAllStringSubmatch(whole, -1) {
		generated[m[1]] = true
	}

	// ── Services + methods ───────────────────────────────────────────────────
	svcs := f.Services()
	for i := 0; i < svcs.Len(); i++ {
		svc := svcs.Get(i)
		name := string(svc.Name())
		if generated[name] || exempt(name) {
			continue
		}
		body, ok := sections[name]
		if !ok {
			flag("service "+name+" is neither generated (::proto-service) nor a `### "+name+"` section on the reference page", name)
			continue
		}
		ms := svc.Methods()
		for j := 0; j < ms.Len(); j++ {
			m := string(ms.Get(j).Name())
			key := name + "." + m
			if !backticked(body, m) && !exempt(key) {
				flag("RPC "+key+" is not listed in the `### "+name+"` section", key)
			}
		}
	}

	// ── Top-level messages + fields ──────────────────────────────────────────
	msgs := f.Messages()
	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		name := string(md.Name())
		if generated[name] || exempt(name) {
			continue
		}
		body, ok := sections[name]
		if !ok {
			flag("message "+name+" is neither generated (::proto-message) nor a `### "+name+"` section on the reference page", name)
			continue
		}
		fs := md.Fields()
		for j := 0; j < fs.Len(); j++ {
			fname := string(fs.Get(j).Name())
			key := name + "." + fname
			if !backticked(body, fname) && !exempt(key) {
				flag("field "+key+" is missing from the `### "+name+"` field table", key)
			}
		}
	}

	// ── Enums (generated via ::proto-enum, or a `### EnumName` heading) ───────
	enums := f.Enums()
	for i := 0; i < enums.Len(); i++ {
		name := string(enums.Get(i).Name())
		_, hasHeading := sections[name]
		if !generated[name] && !hasHeading && !exempt(name) {
			flag("enum "+name+" is neither generated (::proto-enum) nor a `### "+name+"` section on the reference page", name)
		}
	}

	// ── Self-cleaning exemptions ─────────────────────────────────────────────
	for key, reason := range docCoverageExempt {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("docCoverageExempt[%q] has an empty reason; every exemption must say why.", key)
		}
		if !used[key] {
			t.Errorf("docCoverageExempt[%q] is stale: the symbol is documented (or no longer exists) — remove it.", key)
		}
	}

	sort.Strings(missing)
	t.Logf("checked reference coverage for %d services, %d top-level messages, %d enums",
		svcs.Len(), msgs.Len(), enums.Len())
	for _, m := range missing {
		t.Error("undocumented: " + m)
	}
}

// guard against an unused import if the descriptor handle changes shape.
var _ protoreflect.FileDescriptor = rampv1.File_ramp_v1_ramp_proto
