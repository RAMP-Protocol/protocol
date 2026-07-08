# Code generated from the RAMP proto (via conformance/uniquegen). DO NOT EDIT.
# Regenerate: scripts/gen-sdk-types.sh   Enforcement seam: wire/base.py
"""Message -> field names whose repeated items must be unique on the wire.

Mirrors (buf.validate.field).repeated.unique. wire.base.WireModel reads this to reject a
duplicate item exactly where Go protovalidate does; the Zod client gets the same rule from
`uniqueItems` in the generated JSON Schema.
"""

UNIQUE_ITEM_FIELDS: dict[str, tuple[str, ...]] = {
    "SetReportingPolicyRequest": ("required_fields",),
    "SetReportingPolicyResponse": ("required_fields",),
}
