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
        if f.package not in ("ramp.v1", "ramp.admin.v1"):
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


def base64_encoded_form(n):
    """(payload_chars, pad_chars) of the base64 encoding of exactly n bytes.
    The SINGLE derivation of the padding length: the exact-length pattern tail
    and its maxLength are both built from pad_chars, so they cannot disagree."""
    full, rem = divmod(int(n), 3)
    return 4 * full + (0, 2, 3)[rem], (0, 2, 1)[rem]


# The two base64 alphabets, as JSON-Schema (ECMA-262 / RE2-compatible) character
# classes. They are kept SEPARATE, never merged into one class: Go's protojson
# picks the alphabet by presence of '-' or '_' and then decodes strictly, so a
# string mixing '+' with '_' is refused. A merged [A-Za-z0-9+/_-] class accepts
# that mix, which is the accept-direction divergence these patterns exist to
# close. ('-' sits last in the url class so it is a literal, not a range.)
BASE64_ALPHABETS = ("A-Za-z0-9+/", "A-Za-z0-9_-")


def base64_block_forms(chars, pad):
    """Regex branches for base64 of an EXACT payload length: `chars` payload
    characters, then the padding that completes the 4-character block (none, one
    '=', or two). Padding is OPTIONAL because protojson decodes the unpadded
    (raw) form too."""
    tail = {0: "", 1: "=?", 2: "(?:==)?"}[pad]
    return ["[%s]{%d}%s" % (a, chars, tail) for a in BASE64_ALPHABETS]


def base64_floor_forms(chars):
    """Regex branches for base64 of AT LEAST `chars` payload characters.

    A base64 string is p payload characters plus padding, and Go accepts it only
    when p % 4 != 1 — 4k characters carry no padding, 4k+2 take an optional '==',
    4k+3 an optional '='. (4k+1 is not a legal encoded length in any form, which
    is why "AA=", "AAA==" and "AAAAA" are all refused.) So each accepted residue
    gets its own branch, anchored at the smallest payload length that both has
    that residue and clears the floor; `(?:[A]{4})*` then walks it up in whole
    blocks. This is plain arithmetic in the pattern — no lookahead — because
    Pydantic v2 compiles patterns with the Rust regex engine, which has none."""
    out = []
    for a in BASE64_ALPHABETS:
        for residue, tail in ((0, ""), (2, "(?:==)?"), (3, "=?")):
            floor = chars + (residue - chars) % 4  # smallest p >= chars, p % 4 == residue
            out.append("[%s]{%d}(?:[%s]{4})*%s" % (a, floor, a, tail))
    return out


def tighten_bytes_len(defs, bytes_len):
    """A bytes field with a length rule arrives from protoschema too loose in
    both rule kinds, so the generated clients accept values the Go server
    rejects:

      - bytes.len = N ({"len": N} in the manifest): rendered as base64 with a
        minLength/maxLength CHARACTER window (43..44 for N=32) that also admits
        an N+1-byte value — 33 bytes encode to 44 unpadded chars, inside the
        window. Rewrite to the EXACT encoded forms of N bytes: the unpadded
        encoding, optionally completed to the base64 block with its exact
        padding.
      - bytes.min_len = N ({"min_len": N} in the manifest): rendered as a
        pattern with a free padding tail plus a CHARACTER minLength, so for N=1
        the two-character string "==" (pure padding, zero payload bytes) passes
        while Go protojson refuses to decode it. Rewrite to require at least
        the encoded payload characters of N bytes BEFORE the padding tail.

    bytes_len (from the Go bytesgen manifest — the authoritative protovalidate
    view) names the fields; bytesgen fails closed on any other bytes rule
    shape, so every manifest entry is one of the two kinds above. Byte length
    becomes enforceable at the schema layer without decoding.

    Both patterns are an ALTERNATION of the two base64 alphabets, standard (+/)
    and url-safe (-_), never one merged character class. Go's protojson accepts
    either alphabet on decode — so a client rejecting base64url (a JWK "x" value
    pasted verbatim) would refuse input the server takes — but it accepts only
    ONE of them per value: it selects url-safe when the string contains '-' or
    '_', then decodes strictly, so a mixed string is refused. Length arithmetic
    is alphabet-independent, so the length guarantees are the same in both arms.
    Padding is derived from the payload length mod 4 rather than left as a free
    ={0,2} tail, which is what makes "AA=", "AAA==" and "AAAAA" — none of them
    legal encoded lengths — rejected here as they are by Go.

    Loud guards: every manifest entry MUST match a string property in the
    rendered schema, and MUST carry a rule kind this function translates. A
    silent skip would mean a protoschema rendering change (or a manifest format
    change) reopened the loose length window with no build failure — the parity
    corpus would catch it only later and less legibly."""
    missing = []
    for msg, fields in bytes_len.items():
        d = defs.get(msg)
        if not isinstance(d, dict) or "properties" not in d:
            missing.extend(f"{msg}.{jname} (message not in schema)" for jname in fields)
            continue
        for jname, rule in fields.items():
            prop = d["properties"].get(jname)
            if not isinstance(prop, dict) or prop.get("type") != "string":
                missing.append(f"{msg}.{jname} (no string property in schema)")
                continue
            if not isinstance(rule, dict) or set(rule) not in ({"len"}, {"min_len"}):
                missing.append(f"{msg}.{jname} (untranslatable rule {rule!r})")
                continue
            n = next(iter(rule.values()))
            if not isinstance(n, int) or n < 1:
                # bytesgen panics on a zero-valued length rule; this is the same
                # check on the consuming side, so a manifest that lost its value
                # (or carries a zero) cannot produce a pattern the empty string
                # satisfies.
                missing.append(f"{msg}.{jname} (rule value must be a positive integer: {rule!r})")
                continue
            if "len" in rule:
                chars, pad = base64_encoded_form(rule["len"])
                prop["pattern"] = "^(?:%s)$" % "|".join(base64_block_forms(chars, pad))
                # unpadded (chars) .. padded to the block (chars + pad)
                prop["minLength"] = chars
                prop["maxLength"] = chars + pad
            else:
                chars, _ = base64_encoded_form(rule["min_len"])
                # Open-ended: at least the encoded payload characters of min_len
                # bytes, extended a whole 4-character block at a time. No
                # exact-length arithmetic applies, so no maxLength.
                prop["pattern"] = "^(?:%s)$" % "|".join(base64_floor_forms(chars))
                prop["minLength"] = chars
                prop.pop("maxLength", None)
    if missing:
        sys.exit("bytes_len manifest entries this pipeline cannot apply — the "
                 f"length tightening would silently not happen: {missing}")
    return defs


def assert_defaults_valid(combined):
    """Loud guard: no string node may keep a default its OWN constraints reject.
    Such a pairing means a wire-required field slipped through as optional-with-
    invalid-default — the clients then either reject omission inconsistently
    (Zod 3 re-validates a ZodDefault, Zod 4 does not) or materialize a value the
    server refuses. The fix is never to relax the constraint but to mark the
    field required (requiredgen) so the default is dropped; this guard fails the
    build until that happens."""
    bad = []

    def walk(node, path):
        if isinstance(node, dict):
            d = node.get("default")
            if isinstance(d, str) and node.get("type") == "string":
                if len(d) < node.get("minLength", 0):
                    bad.append(f"{path} (default {d!r} under minLength)")
                elif "maxLength" in node and len(d) > node["maxLength"]:
                    bad.append(f"{path} (default {d!r} over maxLength)")
                else:
                    p = node.get("pattern")
                    if p and not re.search(p, d):
                        bad.append(f"{path} (default {d!r} fails pattern)")
            for k, v in node.items():
                walk(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(combined, "")
    if bad:
        sys.exit("string default(s) rejected by the field's own constraints — the field "
                 f"is wire-required; extend requiredgen instead of shipping them: {bad}")


def main(src_dir, desc_path, out_file, required_path, unique_path, bytes_len_path):
    """Merge the per-message schemas into one file, tightened by three manifests.

    The three manifest parameters are REQUIRED positionals on purpose. They used
    to default to None, so calling this with too few arguments skipped the
    matching tightening pass and exited 0 — a caller that dropped an argument got
    a smaller, laxer schema and a green build, which is the failure the guard at
    the bottom of this file says must raise.
    """
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
        d = strip_titles(json.load(open(f)))
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
    if bytes_len_path:
        tighten_bytes_len(defs, json.load(open(bytes_len_path)))
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
    assert_defaults_valid(combined)

    json.dump(combined, open(out_file, "w"), indent=2)
    print(f"merged {len([k for k in defs if k not in enum_defs])} messages + "
          f"{len(enum_defs)} enums -> {out_file}")


if __name__ == "__main__":
    # No slice bound: an argument-count mismatch with gen-sdk-types.sh must raise
    # TypeError and fail the pipeline. A silent truncation (the old [1:6]) would
    # instead run with a manifest parameter defaulted to None, disabling that
    # tightening pass with exit code 0. The defaults are gone too, so too FEW
    # arguments now raise for the same reason too many do.
    main(*sys.argv[1:])
