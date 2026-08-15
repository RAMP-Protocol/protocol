// Money — TS port of the sdk/go oracle (helpers/money.go). RAMP money
// fields (Pricing.rate, Cost.amount, *.unit_cost) are exact decimal strings —
// never floats — constrained by protovalidate to the wire pattern below:
// non-negative, no sign, no exponent, optional fractional part, empty string
// for "unset". The Go oracle round-trips shopspring decimal (NewFromString then
// String); TS has no stdlib decimal, so the surface is a validated canonical
// STRING. canonicalizeMoney reproduces the Go bytes: strip insignificant
// LEADING integer zeros AND trailing fractional zeros + a bare trailing dot.

// moneyWire mirrors the protovalidate constraint `^([0-9]+([.][0-9]+)?)?$`
// exactly (kept in lockstep with ramp.proto Pricing.rate). The empty string
// matches the pattern but is rejected by parseMoney as "unset".
const moneyWire = /^([0-9]+([.][0-9]+)?)?$/;

/**
 * parseMoney validates a canonical wire decimal string, rejecting the empty
 * (unset) string and any value the wire pattern forbids — signs, exponents, a
 * leading dot — so a value that would fail the server's protovalidate never
 * silently parses here. Returns the validated string (the TS decimal surface).
 */
export function parseMoney(s: string): string {
	if (s === "") {
		throw new Error("money: empty money string (field is unset)");
	}
	// Mirror protovalidate string.max_len = 32 (ramp.proto Pricing.rate) so a
	// pattern-valid but over-length value is rejected here, not only server-side.
	if (s.length > 32) {
		throw new Error(`money: string length ${s.length} exceeds max 32`);
	}
	if (!moneyWire.test(s)) {
		throw new Error(
			`money: ${JSON.stringify(s)} is not a canonical money string`,
		);
	}
	return s;
}

/**
 * formatMoney renders a validated money string as the canonical wire form: no
 * sign, no exponent, insignificant LEADING integer zeros dropped ("007" -> "7",
 * "00.5" -> "0.5", "000" -> "0") and insignificant trailing fractional zeros +
 * a bare trailing dot stripped ("0.050" -> "0.05", "1.00" -> "1"). A negative
 * value is rejected — RAMP money is non-negative.
 */
export function formatMoney(s: string): string {
	if (s.startsWith("-")) {
		throw new Error(
			`money: negative money ${JSON.stringify(s)} is not representable on the wire`,
		);
	}
	const dot = s.indexOf(".");
	let intPart = dot === -1 ? s : s.slice(0, dot);
	let fracPart = dot === -1 ? "" : s.slice(dot + 1);
	intPart = intPart.replace(/^0+/, "");
	if (intPart === "") intPart = "0";
	fracPart = fracPart.replace(/0+$/, "");
	return fracPart === "" ? intPart : `${intPart}.${fracPart}`;
}

/**
 * canonicalizeMoney normalizes a wire decimal string to its canonical form
 * (parse then format) — the convenience used when echoing a money value back
 * onto the wire without doing arithmetic.
 */
export function canonicalizeMoney(s: string): string {
	return formatMoney(parseMoney(s));
}
