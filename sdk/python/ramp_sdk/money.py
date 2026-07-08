"""Money (ADR-020) — Python port of the sdk/go oracle (helpers/money.go).

RAMP money fields (Pricing.rate, Cost.amount, *.unit_cost) are exact decimal
strings — never floats — constrained by protovalidate to the wire pattern below:
non-negative, no sign, no exponent, optional fractional part, empty string for
"unset". The surface is stdlib ``decimal.Decimal``; ``canonicalize_money``
reproduces the Go shopspring round-trip byte-for-byte: strip insignificant
LEADING integer zeros AND trailing fractional zeros + a bare trailing dot, in
PLAIN notation (``format(d, "f")`` — never ``str(d)``, which emits scientific
notation for small fractions where Go does not, e.g. ``str(Decimal("0.0000001"))``
== ``"1E-7"``).
"""

from __future__ import annotations

import re
from decimal import Decimal

# _MONEY_WIRE mirrors the protovalidate constraint ``^([0-9]+([.][0-9]+)?)?$``
# exactly (kept in lockstep with ramp.proto Pricing.rate). The empty string
# matches the pattern but is rejected by parse_money as "unset".
_MONEY_WIRE = re.compile(r"^([0-9]+([.][0-9]+)?)?$")


def parse_money(s: str) -> Decimal:
    """Parse a canonical wire decimal string into an exact ``Decimal``.

    Rejects the empty (unset) string and any value the wire pattern forbids —
    signs, exponents, a leading dot — so a value that would fail the server's
    protovalidate never silently parses here.
    """
    if s == "":
        msg = "money: empty money string (field is unset)"
        raise ValueError(msg)
    # Mirror protovalidate string.max_len = 32 (ramp.proto Pricing.rate) so a
    # pattern-valid but over-length value is rejected here, not only server-side.
    if len(s) > 32:
        msg = f"money: string length {len(s)} exceeds max 32"
        raise ValueError(msg)
    if not _MONEY_WIRE.match(s):
        msg = f"money: {s!r} is not a canonical money string"
        raise ValueError(msg)
    return Decimal(s)


def format_money(d: Decimal) -> str:
    """Render an exact ``Decimal`` as the canonical wire string: no sign, no
    exponent, insignificant LEADING integer zeros dropped and insignificant
    trailing fractional zeros + a bare trailing dot stripped. A negative value is
    rejected — RAMP money is non-negative.
    """
    if d < 0:
        msg = f"money: negative money {d} is not representable on the wire"
        raise ValueError(msg)
    s = format(d, "f")  # plain notation — never scientific, matching Go's String().
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def canonicalize_money(s: str) -> str:
    """Normalize a wire decimal string to its canonical form (parse then format)."""
    return format_money(parse_money(s))
