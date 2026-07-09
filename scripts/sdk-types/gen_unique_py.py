#!/usr/bin/env python3
"""Emit gen/python/wire/unique.py from the Go uniquegen manifest.

datamodel-code-generator drops JSON Schema's `uniqueItems` for pydantic v2 (its only
option, --use-unique-items-as-set, rewrites list[str] as set[str] and loses the wire
ordering), so the (buf.validate.field).repeated.unique rule cannot ride into models.py
the way every other field rule does. It rides here instead: this generated map is read
by the hand-written wire/base.py seam, which rejects duplicates on every model at once.

The Zod side needs no equivalent — merge_schema.py injects `uniqueItems` into the JSON
Schema and json-schema-to-zod compiles it into a `.refine(...)` inline in schemas.ts.

No rule is restated by hand: both the map and the injected `uniqueItems` come from the
same conformance/uniquegen manifest, which reads Go protovalidate.

    gen_unique_py.py <unique_items.json> <out.py>
"""
import json
import sys

HEADER = """# Code generated from the RAMP proto (via conformance/uniquegen). DO NOT EDIT.
# Regenerate: scripts/gen-sdk-types.sh   Enforcement seam: wire/base.py
\"\"\"Message -> field names whose repeated items must be unique on the wire.

Mirrors (buf.validate.field).repeated.unique. wire.base.WireModel reads this to reject a
duplicate item exactly where Go protovalidate does; the Zod client gets the same rule from
`uniqueItems` in the generated JSON Schema.
\"\"\"
"""


def main(manifest_path: str, out_path: str) -> None:
    manifest = json.load(open(manifest_path))
    lines = [HEADER, "UNIQUE_ITEM_FIELDS: dict[str, tuple[str, ...]] = {"]
    for msg in sorted(manifest):
        fields = ", ".join(f'"{f}"' for f in sorted(manifest[msg]))
        trailing = "," if len(manifest[msg]) == 1 else ""
        lines.append(f'    "{msg}": ({fields}{trailing}),')
    lines.append("}")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {len(manifest)} unique-item message(s) -> {out_path}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
