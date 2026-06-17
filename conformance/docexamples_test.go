package conformance

import (
	"os"
	"path/filepath"
	"regexp"
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

var jsonFenceRe = regexp.MustCompile("(?s)```json\\s*\\n(.*?)```")

func jsonFences(content string) []string {
	var out []string
	for _, m := range jsonFenceRe.FindAllStringSubmatch(content, -1) {
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

// TestDocSignatureAlgorithm: the Offer signature algorithm is "EdDSA"
// (RFC 7515 JWS alg). Examples using the lowercase JWK curve name "ed25519" for
// a `signature_algorithm` value drift from the wire contract.
func TestDocSignatureAlgorithm(t *testing.T) {
	re := regexp.MustCompile(`"?signature_algorithm"?\s*:\s*"([^"]+)"`)
	checked := 0
	var bad []string
	walkDocs(t, func(path, content string) {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			val := m[1]
			if isPlaceholder(val) {
				continue
			}
			checked++
			if val != "EdDSA" {
				bad = append(bad, filepath.Base(path)+": signature_algorithm \""+val+"\" should be \"EdDSA\"")
			}
		}
	})
	t.Logf("signature_algorithm values checked=%d", checked)
	for _, b := range bad {
		t.Error(b)
	}
}

// TestDocLicenseTermSemantics: a LicenseTerm example (a JSON object carrying
// both `pricing` and `restrictions`) MUST set the `semantics` discriminator —
// `TermSemantics` UNSPECIFIED=0 is rejected at ingest, so a term example without
// it would not validate. Heuristic at the fence level: if a fence contains a
// term shape and no `semantics` anywhere, flag it.
func TestDocLicenseTermSemantics(t *testing.T) {
	fences, flagged := 0, 0
	var bad []string
	walkDocs(t, func(path, content string) {
		for _, f := range jsonFences(content) {
			fences++
			hasTerm := strings.Contains(f, `"pricing"`) && strings.Contains(f, `"restrictions"`)
			if hasTerm && !strings.Contains(f, `"semantics"`) {
				flagged++
				bad = append(bad, filepath.Base(path)+": term example (pricing+restrictions) is missing the required \"semantics\" discriminator")
			}
		}
	})
	t.Logf("json fences scanned=%d term-shaped-without-semantics=%d", fences, flagged)
	for _, b := range bad {
		t.Error(b)
	}
}
