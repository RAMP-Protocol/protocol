package helpers

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/shopspring/decimal"
)

// Money is decimal at the surface and a canonical decimal string on the wire.
//
// RAMP money fields (Pricing.rate, Cost.amount, *.unit_cost) are exact decimal
// strings — never floats — to avoid binary rounding and to allow arbitrary
// sub-cent precision. The wire form is constrained by protovalidate to the
// pattern below: non-negative, no sign, no exponent, optional fractional part,
// and the empty string for "unset". ParseMoney/FormatMoney are the single place
// the SDK crosses between that wire string and shopspring/decimal so no caller
// hand-parses a decimal string or risks a float rounding bug.

// moneyWire is the proto wire pattern for rate/amount/unit_cost. It mirrors the
// protovalidate constraint `^([0-9]+([.][0-9]+)?)?$` exactly (kept in lockstep;
// see ramp.proto Pricing.rate). The empty string is a valid wire value meaning
// "unset" — ParseMoney rejects it so callers check presence explicitly.
var moneyWire = regexp.MustCompile(`^([0-9]+([.][0-9]+)?)?$`)

// ErrEmptyMoney is returned by ParseMoney for the empty (unset) wire string.
var ErrEmptyMoney = errors.New("helpers: empty money string (field is unset)")

// ParseMoney parses a canonical wire decimal string into an exact decimal.
// It rejects the empty string (ErrEmptyMoney) and any value the wire pattern
// forbids — signs, exponents, a leading dot — so a value that would fail the
// server's protovalidate never silently parses here.
func ParseMoney(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Decimal{}, ErrEmptyMoney
	}
	if !moneyWire.MatchString(s) {
		return decimal.Decimal{}, fmt.Errorf("helpers: %q is not a canonical money string (want %s)", s, moneyWire.String())
	}
	d, err := decimal.NewFromString(s)
	if err != nil {
		return decimal.Decimal{}, fmt.Errorf("helpers: parse money %q: %w", s, err)
	}
	return d, nil
}

// FormatMoney renders an exact decimal as the canonical wire string: no sign,
// no exponent, and insignificant trailing fractional zeros stripped ("0.050" ->
// "0.05", "1.00" -> "1", "10" -> "10"). A negative value is rejected — RAMP
// money is non-negative. The result always satisfies the wire pattern.
func FormatMoney(d decimal.Decimal) (string, error) {
	if d.IsNegative() {
		return "", fmt.Errorf("helpers: negative money %s is not representable on the wire", d.String())
	}
	s := d.String() // shopspring never emits exponent notation for finite values.
	if strings.ContainsRune(s, '.') {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
	}
	if s == "" { // d.String() can't actually be "", but stay defensive.
		s = "0"
	}
	return s, nil
}

// CanonicalizeMoney normalizes a wire decimal string to its canonical form
// (parse then format). It is the convenience used when echoing a money value
// back onto the wire without doing arithmetic.
func CanonicalizeMoney(s string) (string, error) {
	d, err := ParseMoney(s)
	if err != nil {
		return "", err
	}
	return FormatMoney(d)
}
