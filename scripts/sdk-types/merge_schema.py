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
#
# A third source matters, and it is the one that used to lose text: protoschema splits a
# multi-paragraph proto comment across `title` (paragraph one) and `description` (the
# rest), and fills `title` in from the field's own TYPE name when the comment has only
# one paragraph. So a title is either the head of the documentation or a restatement of
# the type, and the two need opposite handling — see resolve_titles / carry_title.
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


def load_descriptor(desc_path):
    """The compiled FileDescriptorSet, read once and shared by every reader below."""
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(open(desc_path, "rb").read())
    return fds


# proto field types whose `type_name` names an enum or a message; a scalar has none.
_FIELD_TYPE_ENUM = descriptor_pb2.FieldDescriptorProto.TYPE_ENUM
_FIELD_TYPE_MESSAGE = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE


def field_type_names_from_descriptor(fds):
    """message simple name -> {proto field name -> the field's enum/message simple name}.

    A scalar field maps to "", which never matches a title. Keyed by SIMPLE name because
    that is what the merged $defs uses; the contract's only nested message is the
    synthetic ErrorDetail.MetadataEntry map entry, which has no schema of its own.
    """
    out = {}

    def walk(msgs):
        for m in msgs:
            out[m.name] = {
                f.name: (
                    f.type_name.rsplit(".", 1)[-1]
                    if f.type in (_FIELD_TYPE_ENUM, _FIELD_TYPE_MESSAGE)
                    else ""
                )
                for f in m.field
            }
            walk(m.nested_type)

    for f in fds.file:
        if f.package in ("ramp.v1", "ramp.admin.v1"):
            walk(f.message_type)
    return out


def enum_names_from_descriptor(fds):
    """frozenset(value names, sans *_UNSPECIFIED) -> proto enum simple name."""
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
        if f.package not in ("ramp.v1", "ramp.admin.v1"):
            continue
        take(f.enum_type)
        walk_msgs(f.message_type)
    return out


def title_is_type_derived(title, type_name):
    """Whether protoschema derived this `title` from the field's TYPE rather than its comment.

    When a field's comment supplies no first paragraph, protoschema fills the title in
    from the enum or message the field carries, spelled with spaces: `DisputeReason`
    becomes "Dispute Reason". Spaces are the only difference, so stripping them and
    comparing case-insensitively is EXACT. A Title-Case shape test is not: it reads
    "C2PA Status" as three words and never matches `C2PAStatus`, and it would also
    misread any genuine comment paragraph that happens to be a short unpunctuated phrase.
    """
    return bool(type_name) and title.replace(" ", "").lower() == type_name.lower()


def carry_title(node, type_name):
    """Fold a comment-derived `title` into `description`; drop a type-derived one.

    protoschema splits a multi-paragraph proto comment: paragraph one becomes `title`
    and the remainder becomes `description`. Dropping every title therefore deleted the
    FIRST paragraph of any comment carrying a blank line — `Offer.signature` lost
    "REQUIRED. JWS (alg=EdDSA) over the canonical serialization of the ENTIRE Offer",
    so the generated types stated the canonical-signing rules without ever saying the
    field is the signature or that it is required. Go was unaffected (ramp.pb.go carries
    the whole comment), so the loss showed only in the Pydantic and Zod export.

    A type-derived title is still dropped: it repeats the field's own type name, so
    prepending it would inject "Dispute Reason" into a field whose comment lost nothing.
    """
    title = node.get("title")
    if not isinstance(title, str) or not title.strip():
        return node
    out = {k: v for k, v in node.items() if k != "title"}
    if title_is_type_derived(title, type_name):
        return out
    desc = out.get("description")
    out["description"] = f"{title}\n\n{desc}" if isinstance(desc, str) and desc else title
    return out


def resolve_property_titles(prop, type_name):
    """Apply carry_title to one property, and to the `items` of a repeated one.

    A repeated field's element schema carries the SAME type name one level down, which
    is where protoschema puts the type-derived title for a `repeated` enum.
    """
    if not isinstance(prop, dict):
        return prop
    prop = carry_title(prop, type_name)
    items = prop.get("items")
    if isinstance(items, dict):
        prop = dict(prop)
        prop["items"] = resolve_property_titles(items, type_name)
    return prop


def resolve_titles(schema, msg_name, field_types):
    """Resolve every title in one message schema: the root's, then each property's.

    The root title is compared against the MESSAGE's own name, on the same rule — so
    "Offer — A single resource offer from an Exchange." is carried and "Reporting
    Policy" (protoschema's fill-in for `ReportingPolicy`) is dropped.

    Titles under `patternProperties` are deliberately left alone: that whole key is the
    camelCase json_name alias set, which open_messages removes further down the pipeline
    — the wire is snake_case proto-JSON, so the aliases are not a supported input form.
    """
    schema = carry_title(schema, msg_name)
    props = schema.get("properties")
    if not isinstance(props, dict):
        return schema
    schema = dict(schema)
    schema["properties"] = {
        name: resolve_property_titles(prop, field_types.get(name, ""))
        for name, prop in props.items()
    }
    return schema


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
      2. patternProperties: {"^(camelName)$": ...} — the alternate field-name aliases.
         We consume the proto-names (snake_case) `.schema.json` variant, so `properties`
         are snake_case and the aliases protoschema emits are the camelCase json_names.
         json-schema-to-zod compiles those into a .catchall(...) + superRefine that
         REJECTS any key not matching an alias, so messages with multiword fields reject
         unknowns even after (1). We drop patternProperties entirely: the wire is
         snake_case proto-JSON everywhere (proto, docs, corpus via protojson
         UseProtoNames=true, and both clients), so the camelCase aliases are not a
         supported input form — dropping them makes every message uniformly open AND
         keeps the clients snake-only. The snake_case `properties` are untouched."""
    if isinstance(o, dict):
        return {k: open_messages(v) for k, v in o.items()
                if k != "patternProperties"
                and not (k == "additionalProperties" and v is False)}
    if isinstance(o, list):
        return [open_messages(x) for x in o]
    return o


# The string forms proto-JSON accepts for a numeric field, as protoschema emits them:
# integers (int32/int64/…) and floating point (double/float).
INT_STR_PATTERN = r"^-?[0-9]+$"
FLOAT_STR_PATTERN = r"^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$"
NUMERIC_STR_PATTERNS = {INT_STR_PATTERN, FLOAT_STR_PATTERN}
NUMERIC_TYPES = ("integer", "number")


def collapse_numeric_strings(o):
    """proto-JSON accepts a number as a JSON number OR a string (and emits int64 as a
    string, to protect JS from >2^53 precision loss), so protoc-gen-jsonschema models
    every numeric field as anyOf[{integer|number}, {string, pattern <numeric>}]. Collapse
    to the numeric branch: datamodel-codegen emits a clean `int`/`conint`/`confloat`
    (Pydantic lax parsing still coerces the wire string), instead of a `int | str` union.
    The Zod side accepts the string via z.coerce.number() (see gen_zod.mjs). Go is
    unaffected — protobuf-go uses native int64/float64 and protojson does the conversion.

    THIS IS LOAD-BEARING, not cosmetic: protoschema puts minimum/maximum on the NUMERIC
    arm only. Leave the string arm standing and a bounded field is bypassable through its
    wire string form — the clients accept "1000" for a [0,1] double the Go server rejects.
    assert_no_numeric_string_arms below fails the build if any survives."""
    if isinstance(o, dict):
        aof = o.get("anyOf")
        if isinstance(aof, list) and any(
            isinstance(b, dict) and b.get("type") == "string" and b.get("pattern") in NUMERIC_STR_PATTERNS
            for b in aof
        ):
            numb = next((b for b in aof if isinstance(b, dict) and b.get("type") in NUMERIC_TYPES), None)
            if numb is not None:
                node = dict(numb)
                if "description" in o:
                    node["description"] = o["description"]
                return node
        return {k: collapse_numeric_strings(v) for k, v in o.items()}
    if isinstance(o, list):
        return [collapse_numeric_strings(x) for x in o]
    return o


def assert_no_surviving_titles(combined):
    """Loud guard for resolve_titles. Every `title` must have been either CARRIED into
    its description (comment-derived) or dropped (type-derived) before the write.

    A survivor means a title site the resolver does not reach, and the two downstream
    generators handle that site differently — datamodel-code-generator would name a
    class from it while json-schema-to-zod ignores it — so the two clients would
    disagree about a message they generated from the same document.

    It looks for `title` whose VALUE is a string, which is the JSON-Schema keyword. A
    message with a field NAMED title has properties["title"] mapping to that field's
    SCHEMA, an object, so it is not confused for the keyword — the distinction matters,
    because the blanket key-strip this replaced deleted Offer.title, ResourceEntry.title
    and UsageAsset.title from both clients outright.
    """
    bad = []

    def walk(node, path):
        if isinstance(node, dict):
            if isinstance(node.get("title"), str):
                bad.append(path)
            for k, v in node.items():
                walk(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(combined, "")
    if bad:
        sys.exit("JSON-Schema `title` survived the merge, so a comment's first paragraph "
                 f"is being dropped — extend resolve_titles: {bad[:5]}")


def assert_no_numeric_string_arms(combined):
    """Loud guard for the collapse above. A surviving anyOf that pairs a numeric arm with
    a plain string arm means the field's bound (minimum/maximum) rides on ONE arm only:
    the generated clients accept an out-of-range value in proto-JSON's string form while
    Go protovalidate rejects it. That is a silent client/server divergence, which the
    typed-contract pipeline exists to make impossible.

    Structural, not a pattern allowlist: a future numeric encoding (a uint64's ^[0-9]+$,
    a float's Infinity/NaN set) trips this instead of shipping unnoticed, and the money
    fields — standalone {type: string, pattern: <decimal>} nodes, not anyOf arms — are
    never touched. Enum unions legitimately pair an integer with a string, and always
    carry a $ref arm; they are exempt."""
    bad = []

    def walk(node, path):
        if isinstance(node, dict):
            aof = node.get("anyOf")
            if isinstance(aof, list):
                arms = [b for b in aof if isinstance(b, dict)]
                if not any("$ref" in b for b in arms) \
                        and any(b.get("type") in NUMERIC_TYPES for b in arms) \
                        and any(b.get("type") == "string" for b in arms):
                    bad.append(path)
            for k, v in node.items():
                walk(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(combined, "")
    if bad:
        sys.exit("numeric field(s) keep a proto-JSON string arm, so their bounds are "
                 f"bypassable in the clients — extend collapse_numeric_strings: {bad}")


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
            m = re.match(r"ramp\.(?:admin\.)?v1\.([A-Za-z0-9_]+)\.schema\.json$", r)
            if m:
                o = dict(o); o["$ref"] = "#/$defs/" + m.group(1)
                return {k: fix_refs(v) for k, v in o.items()}
            g = re.match(r"google\.protobuf\.([A-Za-z0-9_]+)\.schema\.json$", r)
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


def mark_unique(defs, unique_items):
    """A repeated field carrying (buf.validate.field).repeated.unique is a SET on the wire:
    Go protovalidate rejects a duplicate item. protoschema-plugins emits no `uniqueItems`
    keyword at all, so without this the rule reaches neither client while the proto declares
    it. unique_items (from the Go uniquegen manifest — the authoritative protovalidate view)
    names them per message by JSON field name.

    Downstream: json-schema-to-zod compiles `uniqueItems` into a `.refine(...)`, so Zod is
    covered for free. datamodel-code-generator DROPS it for pydantic v2 (its only option,
    --use-unique-items-as-set, would rewrite list[str] as set[str] and lose wire ordering),
    so the Pydantic side is enforced by gen/python/wire/base.py from the generated
    gen/python/wire/unique.py — emitted from this same manifest."""
    for msg, names in unique_items.items():
        d = defs.get(msg)
        if not isinstance(d, dict) or "properties" not in d:
            continue
        for jname in names:
            prop = d["properties"].get(jname)
            if isinstance(prop, dict) and prop.get("type") == "array":
                prop["uniqueItems"] = True
    return defs


def main(src_dir, desc_path, out_file, required_path=None, unique_path=None):
    fds = load_descriptor(desc_path)
    enum_name = enum_names_from_descriptor(fds)
    field_types = field_type_names_from_descriptor(fds)
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
    # The `.schema.json` variant carries the proto (snake_case) field names as primary
    # (protoschema's default); the `.jsonschema.json` variant is the camelCase json_name
    # form. We consume snake_case: it is the one wire naming shared by the proto, the
    # docs, the corpus (protojson UseProtoNames=true), and both generated clients.
    for f in sorted(glob.glob(os.path.join(src_dir, "ramp.v1.*.schema.json"))
                    + glob.glob(os.path.join(src_dir, "ramp.admin.v1.*.schema.json"))):
        base = os.path.basename(f)
        if "jsonschema" in base or ".strict." in base or ".bundle." in base:
            continue
        name = re.sub(r"^ramp\.(?:admin\.)?v1\.", "", base.split(".schema")[0])
        d = resolve_titles(json.load(open(f)), name, field_types.get(name, {}))
        d.pop("$id", None); d.pop("$schema", None)
        defs[name] = d
    defs = fix_string_null_default(open_messages(collapse_numeric_strings(hoist_enums(fix_refs(defs)))))
    # hoist_enums has now populated enum_defs, so their names are known; close the
    # open name-OR-integer enum unions down to the closed string enum.
    defs = close_enum_unions(defs, set(enum_defs))
    if required_path:
        mark_required(defs, json.load(open(required_path)))
    if unique_path:
        mark_unique(defs, json.load(open(unique_path)))
    defs.update(enum_defs)

    combined = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {k: defs[k] for k in sorted(defs)},  # stable key order → stable codegen
    }

    # Guards run BEFORE the write: a doc that fails one of them must never reach disk,
    # where a later pipeline step would happily generate clients from it.
    leftover = sorted(set(re.findall(r'"\$ref":\s*"([^"#][^"]*)"', json.dumps(combined))))
    if leftover:
        sys.exit(f"unresolved external $refs (add to WKT map): {leftover}")
    if unnamed:
        sys.exit(f"inline enums with no descriptor match (value sets): {unnamed[:5]}")
    assert_no_numeric_string_arms(combined)
    assert_no_surviving_titles(combined)

    json.dump(combined, open(out_file, "w"), indent=2)
    print(f"merged {len([k for k in defs if k not in enum_defs])} messages + "
          f"{len(enum_defs)} enums -> {out_file}")


if __name__ == "__main__":
    main(*sys.argv[1:6])
