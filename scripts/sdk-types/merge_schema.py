#!/usr/bin/env python3
# Merge the per-message JSON Schemas that protoc-gen-jsonschema emits (one file per
# message, cross-referencing by filename) into ONE document whose $defs are keyed by
# clean message name — so datamodel-code-generator and json-schema-to-zod produce
# `LicenseTerm`, not `RampV1LicenseTermJsonschemaStrictJson` or `Json`.
#
# Uses the `*.jsonschema.strict.json` variant: JSON-name (camelCase) fields, matching
# the Connect/JSON wire, and additionalProperties:false. google.protobuf.* well-known
# types are mapped to idiomatic JSON Schema (Struct→object, Timestamp→date-time, …).
# Field-level `title` (which the plugin fills with the proto doc comment) is stripped
# so it can't become a class name; descriptions are kept for docstrings.
import json, glob, re, os, sys

WKT = {
    "Struct": {"type": "object", "additionalProperties": True},
    "Value": {},
    "ListValue": {"type": "array"},
    "Timestamp": {"type": "string", "format": "date-time"},
    "Duration": {"type": "string"},
    "Any": {"type": "object", "additionalProperties": True},
    "FieldMask": {"type": "string"},
    "Empty": {"type": "object"},
}


def strip_titles(o):
    if isinstance(o, dict):
        return {k: strip_titles(v) for k, v in o.items() if k != "title"}
    if isinstance(o, list):
        return [strip_titles(x) for x in o]
    return o


def fix_refs(o):
    if isinstance(o, dict):
        r = o.get("$ref")
        if isinstance(r, str):
            m = re.match(r"ramp\.v1\.([A-Za-z0-9_]+)\.jsonschema\.strict\.json$", r)
            if m:
                o = dict(o); o["$ref"] = "#/$defs/" + m.group(1)
                return {k: fix_refs(v) for k, v in o.items()}
            g = re.match(r"google\.protobuf\.([A-Za-z0-9_]+)\.jsonschema(\.strict)?\.json$", r)
            if g and g.group(1) in WKT:
                o = dict(o); o.pop("$ref"); o.update(WKT[g.group(1)])
                return {k: fix_refs(v) for k, v in o.items()}
        return {k: fix_refs(v) for k, v in o.items()}
    if isinstance(o, list):
        return [fix_refs(x) for x in o]
    return o


def main(src_dir, out_file):
    defs = {}
    for f in glob.glob(os.path.join(src_dir, "ramp.v1.*.jsonschema.strict.json")):
        name = os.path.basename(f).split(".jsonschema")[0].replace("ramp.v1.", "")
        d = strip_titles(json.load(open(f)))
        d.pop("$id", None); d.pop("$schema", None)
        defs[name] = d
    defs = fix_refs(defs)
    combined = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": defs}
    json.dump(combined, open(out_file, "w"), indent=2)
    leftover = sorted(set(re.findall(r'"\$ref":\s*"([^"#][^"]*)"', json.dumps(combined))))
    if leftover:
        sys.exit(f"unresolved external $refs (add to WKT map): {leftover}")
    print(f"merged {len(defs)} messages -> {out_file}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
