#!/usr/bin/env python3
# Merge the per-message JSON Schemas that protoc-gen-jsonschema emits into ONE
# document with clean, AUTHORITATIVE names, ready for datamodel-code-generator and
# json-schema-to-zod. Two name sources matter:
#   - messages: the $defs key is the proto message name (clean already).
#   - enums: protoc-gen-jsonschema inlines enums with no name, so datamodel-codegen
#     would invent Reason1/Reason2/Kind1. We instead HOIST every inline enum into a
#     shared $def named from the PROTO DESCRIPTOR (gen/descriptor.binpb) — matched by
#     value set — so it is exactly `DenialReason`, `ObligationTrigger`, `C2PAStatus`,
#     one definition referenced everywhere (no dupes, hierarchy preserved).
#
# *_UNSPECIFIED enum values are dropped: they are the proto zero-sentinel, never a
# valid wire value (rejected at ingest / by enum.not_in), so the generated enum omits
# them and rejects "unset" uniformly. google.protobuf.* well-known types map to
# idiomatic JSON Schema. Uses the NON-strict variant (no additionalProperties:false)
# so `extra` policy is controlled once on the WireModel base, not baked per class.
import json, glob, re, os, sys
from google.protobuf import descriptor_pb2

WKT = {
    "Struct": {"type": "object", "additionalProperties": True},
    "Value": {}, "ListValue": {"type": "array"},
    "Timestamp": {"type": "string", "format": "date-time"},
    "Duration": {"type": "string"},
    "Any": {"type": "object", "additionalProperties": True},
    "FieldMask": {"type": "string"}, "Empty": {"type": "object"},
}


def enum_names_from_descriptor(desc_path):
    """frozenset(value names, sans *_UNSPECIFIED) -> proto enum simple name."""
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(open(desc_path, "rb").read())
    out = {}

    def take(enums):
        for e in enums:
            vals = [v.name for v in e.value if not v.name.endswith("_UNSPECIFIED")]
            if vals:
                out[frozenset(vals)] = e.name

    def walk_msgs(msgs):
        for m in msgs:
            take(m.enum_type)
            walk_msgs(m.nested_type)

    for f in fds.file:
        if f.package != "ramp.v1":
            continue
        take(f.enum_type)
        walk_msgs(f.message_type)
    return out


def strip_titles(o):
    if isinstance(o, dict):
        return {k: strip_titles(v) for k, v in o.items() if k != "title"}
    if isinstance(o, list):
        return [strip_titles(x) for x in o]
    return o


# The decimal-string pattern carried by every money field in the proto
# (Pricing.rate/unit_cost, Cost.amount/unit_cost, TransactionItem.max_unit_cost).
MONEY_PATTERN = "^([0-9]+([.][0-9]+)?)?$"


def mark_money_decimal(o):
    """Money is a decimal STRING on the wire (exact, never a float). Tag those
    fields format: decimal so datamodel-codegen emits `Decimal` — parsed via
    model_validate_json it is exact and wire-exact. The pattern is kept so
    json-schema-to-zod still emits z.string().regex(...) (TS has no Decimal type;
    money is a validated decimal string there). The pattern is the format-only
    guard; presence/zero-rules live in CEL (server-authoritative)."""
    if isinstance(o, dict):
        if o.get("type") == "string" and o.get("pattern") == MONEY_PATTERN:
            node = dict(o)
            node["format"] = "decimal"
            return node
        return {k: mark_money_decimal(v) for k, v in o.items()}
    if isinstance(o, list):
        return [mark_money_decimal(x) for x in o]
    return o


def collapse_int_strings(o):
    """proto-JSON accepts an integer as a number OR a string (and emits int64 as a
    string, to protect JS from >2^53 precision loss), so protoc-gen-jsonschema models
    every integer field as anyOf[{integer}, {string, pattern ^-?[0-9]+$}]. Collapse to
    the integer branch: datamodel-codegen emits a clean `int`/`conint` (Pydantic lax
    parsing still coerces the wire string), instead of an `int | str` union. The Zod
    side accepts the string via z.coerce.number() (see gen_zod.mjs). Go is unaffected —
    protobuf-go uses native int64 and protojson does the string conversion."""
    if isinstance(o, dict):
        aof = o.get("anyOf")
        if isinstance(aof, list) and any(
            isinstance(b, dict) and b.get("type") == "string" and b.get("pattern") == "^-?[0-9]+$"
            for b in aof
        ):
            intb = next((b for b in aof if isinstance(b, dict) and b.get("type") == "integer"), None)
            if intb is not None:
                node = dict(intb)
                if "description" in o:
                    node["description"] = o["description"]
                return node
        return {k: collapse_int_strings(v) for k, v in o.items()}
    if isinstance(o, list):
        return [collapse_int_strings(x) for x in o]
    return o


def fix_refs(o):
    if isinstance(o, dict):
        r = o.get("$ref")
        if isinstance(r, str):
            m = re.match(r"ramp\.v1\.([A-Za-z0-9_]+)\.jsonschema\.json$", r)
            if m:
                o = dict(o); o["$ref"] = "#/$defs/" + m.group(1)
                return {k: fix_refs(v) for k, v in o.items()}
            g = re.match(r"google\.protobuf\.([A-Za-z0-9_]+)\.jsonschema\.json$", r)
            if g and g.group(1) in WKT:
                o = dict(o); o.pop("$ref"); o.update(WKT[g.group(1)])
                return {k: fix_refs(v) for k, v in o.items()}
        return {k: fix_refs(v) for k, v in o.items()}
    if isinstance(o, list):
        return [fix_refs(x) for x in o]
    return o


def main(src_dir, desc_path, out_file):
    enum_name = enum_names_from_descriptor(desc_path)
    enum_defs = {}   # name -> {"type":"string","enum":[...]}
    unnamed = []

    proto_enum = re.compile(r"^[A-Z][A-Z0-9_]*$")  # proto enum value style

    def hoist_enums(o):
        if isinstance(o, dict):
            vals = o.get("enum")
            # Only hoist SCREAMING_SNAKE proto-enum value sets; leave non-proto string
            # enums inline (e.g. the Infinity/-Infinity/NaN double-as-string set).
            if isinstance(vals, list) and vals and all(isinstance(x, str) and proto_enum.match(x) for x in vals):
                clean = [v for v in vals if not v.endswith("_UNSPECIFIED")]
                name = enum_name.get(frozenset(clean))
                if name:
                    enum_defs.setdefault(name, {"type": "string", "enum": clean})
                    ref = {"$ref": "#/$defs/" + name}
                    if "description" in o:
                        ref["description"] = o["description"]
                    return ref
                unnamed.append(sorted(clean)[:3])
            return {k: hoist_enums(v) for k, v in o.items()}
        if isinstance(o, list):
            return [hoist_enums(x) for x in o]
        return o

    defs = {}
    # sorted() so the $defs order — and therefore the generated class order — is
    # deterministic across machines (glob order is filesystem-dependent: macOS vs CI).
    for f in sorted(glob.glob(os.path.join(src_dir, "ramp.v1.*.jsonschema.json"))):
        if ".strict." in f:
            continue
        name = os.path.basename(f).split(".jsonschema")[0].replace("ramp.v1.", "")
        d = strip_titles(json.load(open(f)))
        d.pop("$id", None); d.pop("$schema", None)
        defs[name] = d
    defs = mark_money_decimal(collapse_int_strings(hoist_enums(fix_refs(defs))))
    defs.update(enum_defs)

    combined = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {k: defs[k] for k in sorted(defs)},  # stable key order → stable codegen
    }
    json.dump(combined, open(out_file, "w"), indent=2)

    leftover = sorted(set(re.findall(r'"\$ref":\s*"([^"#][^"]*)"', json.dumps(combined))))
    if leftover:
        sys.exit(f"unresolved external $refs (add to WKT map): {leftover}")
    if unnamed:
        sys.exit(f"inline enums with no descriptor match (value sets): {unnamed[:5]}")
    print(f"merged {len([k for k in defs if k not in enum_defs])} messages + "
          f"{len(enum_defs)} enums -> {out_file}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
