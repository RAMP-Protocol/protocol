package conformance

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
)

// docRoots are scanned for example payloads. Paths are relative to this package
// directory (conformance/).
var docRoots = []string{"../website/src"}

// placeholder values in examples (e.g. "<sig>", "...", "${x}") are not real
// tokens and are skipped by the value checks.
func isPlaceholder(s string) bool {
	if s == "" {
		return true
	}
	return strings.ContainsAny(s, "<>{}$") || strings.Contains(s, "...") || strings.Contains(s, "…")
}

func walkDocs(t *testing.T, fn func(path, content string)) {
	t.Helper()
	seen := 0
	for _, root := range docRoots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".mdx") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			seen++
			fn(path, string(b))
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if seen == 0 {
		t.Fatalf("scanned 0 .mdx files under %v — wrong working directory?", docRoots)
	}
	t.Logf("scanned %d .mdx files under %v", seen, docRoots)
}

// codeFenceRe matches the body of ANY fenced code block regardless of language
// tag (```json, ```go, an unlabeled ```, …). The semantics check uses this
// rather than jsonFences because LicenseTerm shapes also appear in unlabeled
// pseudocode fences (walkthroughs), which the json-only scan could not see
// (R6-7). The language tag, if any, is consumed up to the first newline.
var codeFenceRe = regexp.MustCompile("(?s)```[a-zA-Z0-9]*\\s*\\n(.*?)```")

func codeFences(content string) []string {
	var out []string
	for _, m := range codeFenceRe.FindAllStringSubmatch(content, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestDocUnitsRegistered: every `unit` / `consumed_unit` value used in the docs
// must be a registered Pricing unit (bare token) — or a vendor:namespaced /
// placeholder value, which are skipped. Bare unregistered tokens (e.g.
// "articles", "reports", "studies") are rejected at ingest by the generated
// IsRegistered, so a reader copy-pasting the example would fail. The denylist
// gate cannot catch this — the token is a valid identifier, just not registered.
func TestDocUnitsRegistered(t *testing.T) {
	// Matches both JSON ("unit": "x") and prose (unit: "x"); the key may be quoted.
	re := regexp.MustCompile(`"?(?:consumed_unit|unit)"?\s*:\s*"([^"]+)"`)
	// SubscriptionQuotaInfo.unit is a quota DIMENSION (not a Pricing unit) and
	// has its own small vocabulary; those values are not pricing tokens.
	quotaDimension := map[string]bool{"spend_cents": true, "burst": true}
	checked, skipped := 0, 0
	var bad []string
	walkDocs(t, func(path, content string) {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			val := m[1]
			if isPlaceholder(val) || strings.Contains(val, ":") || quotaDimension[val] { // vendor:namespaced + quota dims allowed
				skipped++
				continue
			}
			checked++
			if !pricingunits.IsRegistered(val) {
				bad = append(bad, filepath.Base(path)+": unit \""+val+"\" is not a registered Pricing unit")
			}
		}
	})
	t.Logf("unit tokens checked=%d skipped(placeholder/vendor)=%d", checked, skipped)
	for _, b := range bad {
		t.Error(b)
	}
}

// TestDocSignatureAlgorithm checks the two DETERMINISTIC forms of the Offer
// signature algorithm in doc examples — the `signature_algorithm` JSON field and
// the PascalCase Go `SignatureAlgorithm = "…"` — both of which are JOSE/JWS and
// must be "EdDSA".
//
// An earlier version also tried to classify bare `alg=…` tokens (ed25519 for RFC
// 9421 request signatures vs EdDSA for JOSE) by sniffing same-line context for
// keyword families, and "skipped ambiguous lines rather than guess" — i.e. it
// could silently NOT check the very tokens it existed for, giving false
// confidence. That heuristic branch was removed; only the two unambiguous,
// field-anchored checks remain.
func TestDocSignatureAlgorithm(t *testing.T) {
	jsonField := regexp.MustCompile(`"?signature_algorithm"?\s*:\s*"([^"]+)"`)
	goField := regexp.MustCompile(`\bSignatureAlgorithm\s*[:=]+\s*"([^"]+)"`)

	checked := 0
	var bad []string
	flag := func(path string, n int, msg string) {
		bad = append(bad, filepath.Base(path)+":"+strconv.Itoa(n)+": "+msg)
	}
	walkDocs(t, func(path, content string) {
		for i, line := range strings.Split(content, "\n") {
			n := i + 1
			// signature_algorithm JSON field — the Offer field, always EdDSA.
			if m := jsonField.FindStringSubmatch(line); m != nil && !isPlaceholder(m[1]) {
				checked++
				if m[1] != "EdDSA" {
					flag(path, n, "signature_algorithm \""+m[1]+"\" should be \"EdDSA\" (JOSE/JWS)")
				}
			}
			// PascalCase Go form: Offer.SignatureAlgorithm = "…" — JOSE ⇒ EdDSA.
			if m := goField.FindStringSubmatch(line); m != nil && !isPlaceholder(m[1]) {
				checked++
				if m[1] != "EdDSA" {
					flag(path, n, "SignatureAlgorithm = \""+m[1]+"\" should be \"EdDSA\" (Offer signature is JOSE/JWS)")
				}
			}
		}
	})
	t.Logf("algorithm-name sites checked=%d", checked)
	for _, b := range bad {
		t.Error(b)
	}
}

// TestDocLicenseTermSemantics: a LicenseTerm example MUST set the `semantics`
// discriminator — `TermSemantics` UNSPECIFIED=0 is rejected by protovalidate
// itself (the license_term.semantics_specified CEL), so a term example without
// it would not validate. The scan covers ALL code fences (not just ```json) and
// matches quoted or unquoted keys, because term shapes also appear in unlabeled
// pseudocode fences in the walkthroughs (R6-7b). A term shape is a `terms: [`
// array (lowercase data-literal key, not the Go `.Terms` field) that carries at
// least one term-only key (`restrictions`/`quotas`/`obligations`). If such a
// fence has no `semantics` anywhere, flag it.
var (
	termsArrayRe = regexp.MustCompile(`(^|[^.\w])"?terms"?\s*:\s*\[`)
	termBodyRe   = regexp.MustCompile(`"?(restrictions|quotas|obligations)"?\s*:\s*\[`)
	semanticsRe  = regexp.MustCompile(`"?semantics"?\s*:`)
)

func TestDocLicenseTermSemantics(t *testing.T) {
	fences, flagged := 0, 0
	var bad []string
	walkDocs(t, func(path, content string) {
		for _, f := range codeFences(content) {
			fences++
			hasTerm := termsArrayRe.MatchString(f) && termBodyRe.MatchString(f)
			if hasTerm && !semanticsRe.MatchString(f) {
				flagged++
				bad = append(bad, filepath.Base(path)+": LicenseTerm example (terms[] with restrictions/quotas/obligations) is missing the required \"semantics\" discriminator")
			}
		}
	})
	t.Logf("code fences scanned=%d term-shaped-without-semantics=%d", fences, flagged)
	for _, b := range bad {
		t.Error(b)
	}
}
