package main

import "testing"

func TestConstName(t *testing.T) {
	cases := []struct {
		token   string
		want    string
		wantErr bool
	}{
		// normal tokens
		{token: "accesses", want: "Accesses"},
		{token: "tokens", want: "Tokens"},
		{token: "units-manufactured", want: "UnitsManufactured"},
		{token: "sq-km", want: "SqKm"},
		{token: "news_publisher", want: "NewsPublisher"},
		{token: "input-tokens", want: "InputTokens"},
		{token: "text-and-data-mining", want: "TextAndDataMining"},
		// special-cased tokens
		{token: "*", want: "Worldwide"},
		{token: "all", want: "AllUses"},
		// invalid / reserved → error
		{token: "", wantErr: true},              // empty
		{token: "3d-model", wantErr: true},      // leading digit
		{token: "is-registered", wantErr: true}, // collides with IsRegistered
	}
	for _, c := range cases {
		got, err := constName(c.token)
		if c.wantErr {
			if err == nil {
				t.Errorf("constName(%q) = %q, want error", c.token, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("constName(%q) unexpected error: %v", c.token, err)
			continue
		}
		if got != c.want {
			t.Errorf("constName(%q) = %q, want %q", c.token, got, c.want)
		}
	}
}

func TestConstNameSpecialValidation(t *testing.T) {
	// A constNameSpecial mapping must itself resolve to a valid, non-reserved
	// exported identifier; a bad entry must error rather than emit broken Go.
	cases := map[string]string{
		"bad-empty":    "",          // not exported
		"bad-lower":    "worldwide", // not exported (lowercase)
		"bad-reserved": "All",       // collides with the emitted All slice
	}
	for token, badValue := range cases {
		constNameSpecial[token] = badValue
		_, err := constName(token)
		delete(constNameSpecial, token)
		if err == nil {
			t.Errorf("constNameSpecial[%q]=%q: expected error, got nil", token, badValue)
		}
	}
}

func TestPyConstName(t *testing.T) {
	cases := []struct {
		token   string
		want    string
		wantErr bool
	}{
		{token: "accesses", want: "ACCESSES"},
		{token: "units-manufactured", want: "UNITS_MANUFACTURED"},
		{token: "sq-km", want: "SQ_KM"},
		{token: "news_publisher", want: "NEWS_PUBLISHER"},
		// special-cased tokens
		{token: "*", want: "WORLDWIDE"},
		{token: "all", want: "ALL_USES"}, // bare ALL would shadow the emitted ALL tuple
		// invalid → error
		{token: "", wantErr: true},         // empty
		{token: "3d-model", wantErr: true}, // leading digit
	}
	for _, c := range cases {
		got, err := pyConstName(c.token)
		if c.wantErr {
			if err == nil {
				t.Errorf("pyConstName(%q) = %q, want error", c.token, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("pyConstName(%q) unexpected error: %v", c.token, err)
			continue
		}
		if got != c.want {
			t.Errorf("pyConstName(%q) = %q, want %q", c.token, got, c.want)
		}
	}
}

func TestConstEntriesCollision(t *testing.T) {
	// "ai-train" and "ai_train" both PascalCase to "AiTrain".
	if _, err := constEntries([]string{"ai-train", "ai_train"}); err == nil {
		t.Fatal("expected collision error for ai-train / ai_train")
	}
	// The same tokens UPPER_SNAKE to "AI_TRAIN" — the per-language collision
	// check must catch it under the Python identifier scheme too.
	if _, err := constEntriesFor([]string{"ai-train", "ai_train"}, pyConstName); err == nil {
		t.Fatal("expected collision error for ai-train / ai_train under pyConstName")
	}
}

func TestConstEntriesOK(t *testing.T) {
	entries, err := constEntries([]string{"fetches", "accesses", "*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []constEntry{
		{ident: "Fetches", token: "fetches"},
		{ident: "Accesses", token: "accesses"},
		{ident: "Worldwide", token: "*"},
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for i, e := range entries {
		if e != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, e, want[i])
		}
	}
}

func TestConstEntriesPropagatesError(t *testing.T) {
	if _, err := constEntries([]string{"accesses", "2fast"}); err == nil {
		t.Fatal("expected error for invalid token 2fast")
	}
}

func TestParseAliasesOK(t *testing.T) {
	tokens := []string{"ai-train", "ai-input", "modify"}
	got, err := parseAliases(tokens, []string{"train-ai=ai-train", "generative-ai=ai-input", "adapt=modify", "derivative=modify"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Alias-sorted so the generated files are stable regardless of authoring order.
	want := []aliasEntry{
		{alias: "adapt", canonical: "modify"},
		{alias: "derivative", canonical: "modify"},
		{alias: "generative-ai", canonical: "ai-input"},
		{alias: "train-ai", canonical: "ai-train"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// No aliases at all is a valid axis: an empty (not nil-panicking) result.
	if none, err := parseAliases(tokens, nil); err != nil || len(none) != 0 {
		t.Fatalf("parseAliases(nil) = %v, %v; want empty, nil", none, err)
	}
}

func TestParseAliasesRefusesWhatCanonicalCannotHonour(t *testing.T) {
	tokens := []string{"ai-train", "ai-input"}
	for name, raw := range map[string][]string{
		"malformed_no_equals":       {"train-ai"},
		"malformed_empty_alias":     {"=ai-train"},
		"malformed_empty_canonical": {"train-ai="},
		"malformed_two_equals":      {"train-ai=ai-train=x"},
		"canonical_not_registered":  {"train-ai=ai-training"},
		"alias_is_a_token":          {"ai-input=ai-train"},
		"duplicate_alias":           {"train-ai=ai-train", "train-ai=ai-input"},
		"alias_not_lowercase":       {"Train-AI=ai-train"},
		"alias_not_trimmed":         {" train-ai=ai-train"},
	} {
		if _, err := parseAliases(tokens, raw); err == nil {
			t.Errorf("%s: parseAliases(%q) accepted, want error", name, raw)
		}
	}
}

// The fold direction is the axis's own, not an assumption that every axis folds
// lower. GEOGRAPHY registers uppercase tokens and the SDK folds a geography token
// UP before looking it up, so a lowercase geography alias is dead on arrival — it
// is the exact class this check exists to catch, and reading the rule as
// "lowercase" would have waved it through.
func TestParseAliasesFoldsTheWayTheAxisDoes(t *testing.T) {
	lower := []string{"ai-train", "ai-input"}
	upper := []string{"*", "EU", "EEA"}

	if _, err := parseAliases(upper, []string{"europe=EU"}); err == nil {
		t.Error("a lowercase alias on an uppercase axis was accepted; the SDK folds up, so it could never match")
	}
	if got, err := parseAliases(upper, []string{"EUROPE=EU"}); err != nil {
		t.Errorf("an uppercase alias on an uppercase axis was refused: %v", err)
	} else if len(got) != 1 || got[0].alias != "EUROPE" || got[0].canonical != "EU" {
		t.Errorf("parseAliases = %v, want one EUROPE->EU entry", got)
	}
	if _, err := parseAliases(lower, []string{"TRAIN-AI=ai-train"}); err == nil {
		t.Error("an uppercase alias on a lowercase axis was accepted")
	}
}

// A caseless axis decides nothing about case; a mixed-case one is refused outright,
// because no fold leaves every token unchanged and Canonical could not then be the
// fixed point NormalizeLicenseTerm's idempotency depends on.
func TestAxisFold(t *testing.T) {
	for name, tc := range map[string]struct {
		tokens  []string
		want    asciiFold
		wantErr bool
	}{
		"lower":               {[]string{"ai-train", "ai-input"}, foldLower, false},
		"upper":               {[]string{"EU", "EEA"}, foldUpper, false},
		"caseless":            {[]string{"*", "1", "-"}, foldEither, false},
		"upper_with_caseless": {[]string{"*", "EU"}, foldUpper, false},
		"mixed_token":         {[]string{"AiTrain"}, foldEither, true},
		"disagreeing_tokens":  {[]string{"ai-train", "EU"}, foldEither, true},
	} {
		got, err := axisFold(tc.tokens)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: axisFold(%q) accepted, want error", name, tc.tokens)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: axisFold(%q) = %v", name, tc.tokens, err)
		} else if got != tc.want {
			t.Errorf("%s: axisFold(%q) = %v, want %v", name, tc.tokens, got, tc.want)
		}
	}
}

func TestAliasFaceNamesAreReserved(t *testing.T) {
	// A token spelled like the emitted alias face must fail loudly in every
	// language rather than shadow it.
	if _, err := constName("aliases"); err == nil {
		t.Error("constName(\"aliases\") = ok, want reserved-identifier error (Aliases)")
	}
	if _, err := constName("canonical"); err == nil {
		t.Error("constName(\"canonical\") = ok, want reserved-identifier error (Canonical)")
	}
	if _, err := pyConstName("aliases"); err == nil {
		t.Error("pyConstName(\"aliases\") = ok, want reserved-identifier error (ALIASES)")
	}
}
