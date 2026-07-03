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
# idiomatic JSON Schema. Uses the NON-strict variant, then strips the
# additionalProperties:false it still carries (see open_messages) so `extra` policy
# is controlled once on the WireModel base / the Zod wire() seam, not baked per class.
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


def fix_string_null_default(o):
    """A proto `bytes` field renders as {type: string, pattern: <base64>, default: null}.
    A JSON-Schema string node must never carry a non-string default: its proto3 zero is
    "" (an empty base64 string, which the pattern accepts). Left as null, json-schema-to-zod
    emits .default(null), and Zod's ZodDefault re-validates that default against z.string(),
    so an OMITTED field is wrongly rejected. Normalize null -> "" on string nodes."""
    if isinstance(o, dict):
        o = {k: fix_string_null_default(v) for k, v in o.items()}
        if o.get("type") == "string" and o.get("default", "") is None:
            o["default"] = ""
        return o
    if isinstance(o, list):
        return [fix_string_null_default(x) for x in o]
    return o


def open_messages(o):
    """protoschema's non-strict variant STILL closes every message object two ways,
    both of which defeat forward-compat (an unknown top-level field from a newer
    protocol version must be ACCEPTED and dropped, governed once by the WireModel
    base / the Zod wire() seam):

      1. additionalProperties:false -> per-class extra='forbid' (Pydantic) / .strict()
         (Zod). Stripped ONLY where the value is exactly False; additionalProperties:true
         (Struct/ext) and schema-valued maps (e.g. ErrorDetail.metadata) stay OPEN.
      2. patternProperties: {"^(snake_name)$": ...} — the original snake_case field-name
         aliases (every field carries one; all 121 are anchored ^(name)$, none are maps —
         maps use additionalProperties). json-schema-to-zod compiles these into a
         .catchall(...) + superRefine that REJECTS any key not matching an alias, so
         messages with multiword fields reject unknowns even after (1). We drop
         patternProperties: the canonical wire is camelCase (protojson emits camelCase;
         the corpus is camelCase-only) and Pydantic already ignores these, so removing
         them makes every message uniformly open and tightens canonicalization. The
         camelCase `properties` are untouched."""
    if isinstance(o, dict):
        return {k: open_messages(v) for k, v in o.items()
                if k != "patternProperties"
                and not (k == "additionalProperties" and v is False)}
    if isinstance(o, list):
        return [open_messages(x) for x in o]
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


def close_enum_unions(o, enum_names):
    """proto enum fields are emitted as anyOf[{$ref: Enum}, {type: integer}] to
    mirror proto-JSON's name-OR-number form. The open integer branch admits ANY
    int — including 0 (the UNSPECIFIED sentinel) and undefined values — which
    silently defeats enum.not_in / enum.defined_only once the schema is generated
    into Pydantic/Zod (the field becomes `Enum | int`, so a bad number passes).
    Collapse to the closed string enum ($ref only) so the generated validators
    reject anything outside the defined, non-UNSPECIFIED set. The wire form is the
    enum NAME (protojson default); the numeric form is intentionally not accepted
    by the typed clients (the Go server still accepts it). The stray default: 0 (an
    UNSPECIFIED int that is not even a valid member) is dropped with the union.

    SCOPE — this closes ONLY `not_in: [0]` discriminators. Those drop their
    UNSPECIFIED member, so protoschema emits a 2-branch anyOf[{$ref}, {integer}]
    that this collapses. An enum field WITHOUT `not_in: [0]` keeps its UNSPECIFIED
    member and is emitted as a 3-branch anyOf[{UNSPECIFIED name}, {$ref}, {integer}]
    (len != 2), which this deliberately leaves OPEN — it stays name-OR-number and
    admits raw ints, matching proto's open-enum forward-compat. So "closed enums"
    means the discriminators only, not every enum field."""
    if isinstance(o, dict):
        aof = o.get("anyOf")
        if isinstance(aof, list) and len(aof) == 2:
            ref = next((b for b in aof if isinstance(b, dict) and isinstance(b.get("$ref"), str)
                        and b["$ref"].rsplit("/", 1)[-1] in enum_names), None)
            integ = next((b for b in aof if isinstance(b, dict) and b.get("type") == "integer"), None)
            if ref is not None and integ is not None:
                node = {"$ref": ref["$ref"]}
                if "description" in o:
                    node["description"] = o["description"]
                return node
        return {k: close_enum_unions(v, enum_names) for k, v in o.items()}
    if isinstance(o, list):
        return [close_enum_unions(x, enum_names) for x in o]
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


def mark_required(defs, required_fields):
    """A field whose proto zero value is rejected by its own rule (enum not_in:[0],
    string min_len/non-empty pattern, numeric gte≥1, explicit required) is required
    on the wire, but protoschema leaves it optional. required_fields (from the Go
    requiredgen manifest — the authoritative protovalidate view) names them per
    message by JSON field name; add each to the message's `required` and drop its
    zero default, so generated Pydantic/Zod reject omission like the Go server."""
    for msg, names in required_fields.items():
        d = defs.get(msg)
        if not isinstance(d, dict) or "properties" not in d:
            continue
        req = set(d.get("required", []))
        for jname in names:
            prop = d["properties"].get(jname)
            if prop is None:
                continue
            req.add(jname)
            if isinstance(prop, dict):
                prop.pop("default", None)
        if req:
            d["required"] = sorted(req)
    return defs


def main(src_dir, desc_path, out_file, required_path=None):
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
    defs = fix_string_null_default(open_messages(collapse_int_strings(hoist_enums(fix_refs(defs)))))
    # hoist_enums has now populated enum_defs, so their names are known; close the
    # open name-OR-integer enum unions down to the closed string enum.
    defs = close_enum_unions(defs, set(enum_defs))
    if required_path:
        mark_required(defs, json.load(open(required_path)))
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
    main(*sys.argv[1:5])
