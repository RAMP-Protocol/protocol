package helpers

// Utility-face golden-vector emitter.
//
// The sdk/ts and sdk/python DETERMINISTIC utility faces — NormalizeScopes /
// ScopesSubset, CanonicalizeMoney (Parse+Format), ValidateIdempotencyKey,
// HashURL, and the wire constants — assert byte-parity against this Go oracle.
// Rather than hand-author any expected value, this emitter DERIVES every field
// by CALLING the REAL Go face (self-contained oracle), exactly as
// gen_multisig_vectors_test.go derives its outcomes from the real verifier.
//
// The randomness/clock faces (NewIdempotencyKey mint, ClockWindow /
// MonotonicWindow) carry entropy or a wall clock and are NOT vector-gated —
// they are behaviour-tested in the port suites, not here.
//
// buildMoneyVectors enumerates the leading-zero and
// high-precision-fraction inputs that trigger the Go shopspring round-trip
// (007→7, 00.5→0.5, 0010.20→10.2, 0.0000001 stays plain) plus the invalid
// inputs (empty, negative, leading '+', exponent, leading dot) so a divergent
// port cannot pass green. An all-empty scopes input exercises Go's nil →
// JSON-null normalization.
//
// Like TestGenerateVectors this test is a verification no-op by default (it
// asserts the committed files match a fresh emit) and (re)writes them under
// RAMP_UPDATE_VECTORS=1 — the emitter is both generator and drift gate. It is
// TEST INFRASTRUCTURE, not the code under test.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// scopesNormalizeVector is one NormalizeScopes case: an input scope list and
// the normalized result the REAL NormalizeScopes returns. Go returns nil for an
// empty/all-empty input, which marshals to JSON `null` — the empty case.
type scopesNormalizeVector struct {
	Name       string   `json:"name"`
	Input      []string `json:"input"`
	Normalized []string `json:"normalized"`
}

// scopesSubsetVector is one ScopesSubset case: (sub ⊆ super) as the REAL
// ScopesSubset computes it. Empty sub ⇒ true.
type scopesSubsetVector struct {
	Name     string   `json:"name"`
	Sub      []string `json:"sub"`
	Super    []string `json:"super"`
	Expected bool     `json:"expected"`
}

// moneyVector is one CanonicalizeMoney case: an input wire string, the canonical
// form the REAL face returns (empty when invalid), and whether it is valid.
type moneyVector struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	Canonical string `json:"canonical"`
	Valid     bool   `json:"valid"`
}

// idempotencyValidateVector is one ValidateIdempotencyKey case: a key and
// whether the REAL face accepts it (only rule: non-empty).
type idempotencyValidateVector struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Valid bool   `json:"valid"`
}

// hashURLVector is one HashURL case: a signed-URL string and the hex-encoded
// SHA-256 digest the REAL HashURL returns (the transaction_log.signed_url_hash).
type hashURLVector struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	SHA256Hex string `json:"sha256_hex"`
}

// wireConstantVector is one wire constant: its identifier name and value,
// referenced from the REAL exported constant (never hand-typed here).
type wireConstantVector struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// buildScopesNormalizeVectors emits the NormalizeScopes corpus, deriving every
// normalized result from the REAL NormalizeScopes: drop-empty, first-seen dedup,
// lexicographic sort, nil (→ JSON null) for empty/all-empty.
func buildScopesNormalizeVectors() []scopesNormalizeVector {
	inputs := []struct {
		name  string
		input []string
	}{
		{"empty_input", []string{}},
		{"all_empty_strings", []string{"", "", ""}},
		{"single", []string{"read"}},
		{"already_sorted", []string{"read", "write"}},
		{"unsorted", []string{"write", "read", "admin"}},
		{"duplicates", []string{"read", "read", "write", "read"}},
		{"drop_empty_entries", []string{"write", "", "read", ""}},
		{"dedup_then_sort", []string{"zeta", "alpha", "zeta", "mid"}},
		{"case_sensitive_no_fold", []string{"Read", "read", "READ"}},
	}
	out := make([]scopesNormalizeVector, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, scopesNormalizeVector{
			Name:       in.name,
			Input:      in.input,
			Normalized: NormalizeScopes(in.input), // REAL face
		})
	}
	return out
}

// buildScopesSubsetVectors emits the ScopesSubset corpus, deriving expected from
// the REAL ScopesSubset (sub ⊆ super; empty sub ⇒ true).
func buildScopesSubsetVectors() []scopesSubsetVector {
	cases := []struct {
		name       string
		sub, super []string
	}{
		{"empty_sub_is_subset", nil, []string{"read", "write"}},
		{"empty_of_empty", nil, nil},
		{"proper_subset", []string{"read"}, []string{"read", "write"}},
		{"equal_sets", []string{"read", "write"}, []string{"write", "read"}},
		{"not_subset_missing_member", []string{"admin"}, []string{"read", "write"}},
		{"partial_overlap_not_subset", []string{"read", "admin"}, []string{"read", "write"}},
		{"sub_nonempty_super_empty", []string{"read"}, nil},
		{"case_sensitive_not_subset", []string{"Read"}, []string{"read"}},
	}
	out := make([]scopesSubsetVector, 0, len(cases))
	for _, c := range cases {
		out = append(out, scopesSubsetVector{
			Name:     c.name,
			Sub:      c.sub,
			Super:    c.super,
			Expected: ScopesSubset(c.sub, c.super), // REAL face
		})
	}
	return out
}

// buildMoneyVectors emits the CanonicalizeMoney corpus. Every canonical +
// valid field is DERIVED from the REAL CanonicalizeMoney — the leading-zero and
// high-precision cases are what catch a naive TS string surface or a Python
// str(Decimal) scientific-notation divergence.
func buildMoneyVectors() []moneyVector {
	valid := []struct{ name, input string }{
		{"leading_zero_integer", "007"},
		{"leading_zero_fraction", "00.5"},
		{"leading_zeros_and_trailing", "0010.20"},
		{"high_precision_small_fraction", "0.0000001"},
		{"zero_point_zero", "0.0"},
		{"double_zero_point_zero", "00.0"},
		{"all_zeros_integer", "000"},
		{"trailing_zeros_integer_frac", "1.00"},
		{"trailing_zero_fraction", "0.050"},
		{"plain_integer", "10"},
		{"plain_integer_large", "123456789"},
		{"plain_zero", "0"},
	}
	invalid := []struct{ name, input string }{
		{"empty_string", ""},
		{"negative", "-1"},
		{"leading_plus", "+1"},
		{"exponent_form", "1e3"},
		{"leading_dot", ".5"},
		// 33 digits: pattern-valid but exceeds max_len=32 — the client helper must
		// reject it too, or it splits from the server's protovalidate (DRY-1).
		{"over_max_len", "123456789012345678901234567890123"},
	}
	out := make([]moneyVector, 0, len(valid)+len(invalid))
	for _, v := range valid {
		canonical, err := CanonicalizeMoney(v.input) // REAL face
		if err != nil {
			// An input listed as valid that the real face rejects is an emitter
			// bug — surface it loudly rather than emit a wrong golden.
			panic("buildMoneyVectors: expected valid but face rejected " + v.input + ": " + err.Error())
		}
		out = append(out, moneyVector{Name: v.name, Input: v.input, Canonical: canonical, Valid: true})
	}
	for _, v := range invalid {
		canonical, err := CanonicalizeMoney(v.input) // REAL face
		if err == nil {
			panic("buildMoneyVectors: expected invalid but face accepted " + v.input + " → " + canonical)
		}
		out = append(out, moneyVector{Name: v.name, Input: v.input, Canonical: "", Valid: false})
	}
	return out
}

// buildIdempotencyValidateVectors emits the ValidateIdempotencyKey corpus; the
// only rule is non-empty, derived from the REAL face.
func buildIdempotencyValidateVectors() []idempotencyValidateVector {
	keys := []struct{ name, key string }{
		{"empty_rejected", ""},
		{"typical_22char_b64url", "AAAAAAAAAAAAAAAAAAAAAA"},
		{"single_char", "x"},
		{"with_dash_underscore", "a-b_c"},
		{"long_key", "0123456789abcdef0123456789abcdef"},
	}
	out := make([]idempotencyValidateVector, 0, len(keys))
	for _, k := range keys {
		out = append(out, idempotencyValidateVector{
			Name:  k.name,
			Key:   k.key,
			Valid: ValidateIdempotencyKey(k.key) == nil, // REAL face
		})
	}
	return out
}

// buildHashURLVectors emits the HashURL corpus, deriving the digest from the
// REAL HashURL (sha256 over the verbatim URL bytes; hex-encoded per the
// gen_vectors_test hex convention). A local sha256 recompute cross-checks that
// the recorded hex is the true digest of the URL bytes.
func buildHashURLVectors(t *testing.T) []hashURLVector {
	t.Helper()
	urls := []struct{ name, url string }{
		{"empty", ""},
		{"simple_https", "https://cdn.example.com/a.jpg"},
		{"with_query", "https://cdn.example.com/a.jpg?Expires=1700000000&Signature=abc"},
		{"unicode_path", "https://cdn.example.com/naïve/résumé.pdf"},
		{"opaque_bytes_no_renorm", "https://cdn.example.com/a//b/../c?x=%20&y=+"},
	}
	out := make([]hashURLVector, 0, len(urls))
	for _, u := range urls {
		digest := HashURL(u.url) // REAL face
		recompute := sha256.Sum256([]byte(u.url))
		if hex.EncodeToString(digest) != hex.EncodeToString(recompute[:]) {
			t.Fatalf("HashURL(%q) diverges from raw sha256 recompute", u.url)
		}
		out = append(out, hashURLVector{
			Name:      u.name,
			URL:       u.url,
			SHA256Hex: hex.EncodeToString(digest),
		})
	}
	return out
}

// buildWireConstantsVectors emits the seven wire constants by REFERENCING the real
// exported constants — never by re-typing their string values.
func buildWireConstantsVectors() []wireConstantVector {
	return []wireConstantVector{
		{"ContentTypeProto", ContentTypeProto},
		{"ContentTypeJSON", ContentTypeJSON},
		{"ConnectProtocolVersionHeader", ConnectProtocolVersionHeader},
		{"ConnectProtocolVersion", ConnectProtocolVersion},
		{"ProtocolVersion", ProtocolVersion},
		{"RequestIDHeader", RequestIDHeader},
		{"SignatureAgentHeader", SignatureAgentHeader},
		// The two signature-algorithm labels. They are here for a reason the
		// others are not: ramp.admin.v1 pins each of them as a string.const on
		// the evidence row's algorithm fields, so the value exists twice — once
		// as the constant that WRITES it, once as the rule that ACCEPTS it — and
		// nothing connected the copies. Exporting them through this file lets
		// the conformance layer compare each constant against the descriptor's
		// const without importing sdk/go, which it deliberately never does.
		{"OfferSignatureAlgorithm", OfferSignatureAlgorithm},
		{"AcceptanceSignatureAlgorithm", AcceptanceSignatureAlgorithm},
	}
}

// TestGenerateUtilVectors emits the utility-face golden corpus (scopes, money,
// idempotency-validate, hashurl, wire-constants). Verification no-op by default,
// (re)writes under RAMP_UPDATE_VECTORS=1.
func TestGenerateUtilVectors(t *testing.T) {
	scopesDoc := map[string]any{
		"normalize": buildScopesNormalizeVectors(),
		"subset":    buildScopesSubsetVectors(),
	}
	moneyDoc := map[string]any{"vectors": buildMoneyVectors()}
	idempotencyDoc := map[string]any{"vectors": buildIdempotencyValidateVectors()}
	hashURLDoc := map[string]any{"vectors": buildHashURLVectors(t)}
	wireDoc := map[string]any{"vectors": buildWireConstantsVectors()}

	docs := []struct {
		file string
		doc  any
	}{
		{"scopes-vectors.json", scopesDoc},
		{"money-vectors.json", moneyDoc},
		{"idempotency-validate-vectors.json", idempotencyDoc},
		{"hashurl-vectors.json", hashURLDoc},
		{"wire-constants-vectors.json", wireDoc},
	}
	for _, d := range docs {
		path := filepath.Join("testdata", d.file)
		if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
			writeJSON(t, path, d.doc)
			continue
		}
		assertMatches(t, path, d.doc)
	}
}
