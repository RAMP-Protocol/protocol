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


def doubles_to_decimal(o):
    """protoc-gen-jsonschema models a proto `double` as
    anyOf[{number}, {string enum Infinity/-Infinity/NaN}, {string}] — proto-JSON's
    permissive float encoding. Every `double` in RAMP is MONEY (rate, unit_cost,
    amount, max_unit_cost), so collapse such a field to {number, format: decimal}:
      - datamodel-codegen emits `Decimal` (never float — money must not be a float);
        parsed via model_validate_json it is exact, and serializes to a JSON string,
        which proto-JSON accepts for a double.
      - json-schema-to-zod ignores the format → `z.number()` (TS has no Decimal).
    This also drops the Infinity/NaN string-enum the codegen would otherwise turn into
    field-named Enum classes (Rate/UnitCost). int64-as-string anyOf is left untouched —
    that string form IS the canonical proto-JSON int64 wire encoding."""
    if isinstance(o, dict):
        aof = o.get("anyOf")
        if isinstance(aof, list) and any(
            isinstance(b, dict) and set(b.get("enum") or []) == {"Infinity", "-Infinity", "NaN"}
            for b in aof
        ):
            node = {"type": "number", "format": "decimal"}
            if "description" in o:
                node["description"] = o["description"]
            return node
        return {k: doubles_to_decimal(v) for k, v in o.items()}
    if isinstance(o, list):
        return [doubles_to_decimal(x) for x in o]
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
    for f in glob.glob(os.path.join(src_dir, "ramp.v1.*.jsonschema.json")):
        if ".strict." in f:
            continue
        name = os.path.basename(f).split(".jsonschema")[0].replace("ramp.v1.", "")
        d = strip_titles(json.load(open(f)))
        d.pop("$id", None); d.pop("$schema", None)
        defs[name] = d
    defs = doubles_to_decimal(hoist_enums(fix_refs(defs)))
    defs.update(enum_defs)

    combined = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": defs}
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
