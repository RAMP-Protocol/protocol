package helpers_test

import (
	"errors"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"
)

func TestParseMoney_valid(t *testing.T) {
	cases := map[string]string{
		"0":         "0",
		"0.05":      "0.05",
		"19.99":     "19.99",
		"0.0001234": "0.0001234",
		"100":       "100",
		"0.050":     "0.05", // trailing zero is accepted on input, normalized on output
	}
	for in, wantCanonical := range cases {
		d, err := helpers.ParseMoney(in)
		if err != nil {
			t.Errorf("ParseMoney(%q) error: %v", in, err)
			continue
		}
		got, err := helpers.FormatMoney(d)
		if err != nil {
			t.Errorf("FormatMoney(parse %q) error: %v", in, err)
			continue
		}
		if got != wantCanonical {
			t.Errorf("round-trip %q -> %q, want %q", in, got, wantCanonical)
		}
	}
}

func TestParseMoney_empty(t *testing.T) {
	if _, err := helpers.ParseMoney(""); !errors.Is(err, helpers.ErrEmptyMoney) {
		t.Errorf("ParseMoney(\"\") err = %v, want ErrEmptyMoney", err)
	}
}

func TestParseMoney_rejectsNonCanonical(t *testing.T) {
	// All forbidden by the wire pattern even though shopspring would accept them.
	for _, bad := range []string{"-1", "1e3", "1E3", ".5", "1.", "+1", "0x10", "1,000", " 1", "1 ", "abc"} {
		if _, err := helpers.ParseMoney(bad); err == nil {
			t.Errorf("ParseMoney(%q) = nil error, want rejection", bad)
		}
	}
}

func TestFormatMoney_canonical(t *testing.T) {
	cases := []struct {
		in   decimal.Decimal
		want string
	}{
		{decimal.RequireFromString("0.050"), "0.05"},
		{decimal.RequireFromString("1.00"), "1"},
		{decimal.RequireFromString("10"), "10"},
		{decimal.NewFromInt(0), "0"},
		{decimal.RequireFromString("0.0001234"), "0.0001234"},
	}
	for _, c := range cases {
		got, err := helpers.FormatMoney(c.in)
		if err != nil {
			t.Errorf("FormatMoney(%s) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("FormatMoney(%s) = %q, want %q", c.in, got, c.want)
		}
		// Canonical output must itself re-parse (idempotence).
		if _, err := helpers.ParseMoney(got); err != nil {
			t.Errorf("canonical output %q does not re-parse: %v", got, err)
		}
	}
}

func TestFormatMoney_rejectsNegative(t *testing.T) {
	if _, err := helpers.FormatMoney(decimal.RequireFromString("-0.01")); err == nil {
		t.Error("FormatMoney(negative) = nil error, want rejection")
	}
}

func TestMoney_exactArithmetic(t *testing.T) {
	// The whole point of decimal: 0.1 + 0.2 == 0.3 exactly, no float drift.
	a, _ := helpers.ParseMoney("0.1")
	b, _ := helpers.ParseMoney("0.2")
	got, err := helpers.FormatMoney(a.Add(b))
	if err != nil {
		t.Fatal(err)
	}
	if got != "0.3" {
		t.Errorf("0.1 + 0.2 = %q, want \"0.3\"", got)
	}
}

func TestCanonicalizeMoney(t *testing.T) {
	got, err := helpers.CanonicalizeMoney("0.050")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0.05" {
		t.Errorf("CanonicalizeMoney(\"0.050\") = %q, want \"0.05\"", got)
	}
}
