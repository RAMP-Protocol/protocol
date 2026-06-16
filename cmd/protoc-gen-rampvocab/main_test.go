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
		{token: "", wantErr: true},               // empty
		{token: "3d-model", wantErr: true},       // leading digit
		{token: "is-registered", wantErr: true},  // collides with IsRegistered
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
		"bad-empty":    "",             // not exported
		"bad-lower":    "worldwide",    // not exported (lowercase)
		"bad-reserved": "All",          // collides with the emitted All slice
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

func TestConstEntriesCollision(t *testing.T) {
	// "ai-train" and "ai_train" both PascalCase to "AiTrain".
	if _, err := constEntries([]string{"ai-train", "ai_train"}); err == nil {
		t.Fatal("expected collision error for ai-train / ai_train")
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
