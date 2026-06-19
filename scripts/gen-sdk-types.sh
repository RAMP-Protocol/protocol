#!/usr/bin/env bash
# Generate the TypeScript (Zod) and Python (Pydantic) TYPES EXPORT from the proto,
# via JSON Schema. This is NOT a full SDK — it is the message types + per-field
# validation (shape + protovalidate standard constraints: enum.not_in, string.pattern,
# min/max, …). Cross-field rules stay server-authoritative (Go protovalidate).
#
# Pipeline:  proto --buf/protoschema--> JSON Schema (per message, protovalidate-aware)
#            --merge_schema.py--------> ONE $defs doc: clean message names + enums
#                                       named/deduped from the proto descriptor
#            --datamodel-code-generator--> gen/python/wire/models.py (Pydantic v2,
#                                       every model extends wire.base.WireModel)
#            --json-schema-to-zod--------> gen/ts/wire/schemas.ts   (Zod)
#
# gen/python/wire/base.py is hand-written (the seam) and NOT generated.
# Prereqs: go, python3, node/npm. Provisions a throwaway venv + node_modules under
# .sdk-types-work/ (gitignored).
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=.sdk-types-work
JS="$WORK/jsonschema"
COMBINED="$WORK/combined.json"
PY="$WORK/venv/bin/python"
rm -rf "$WORK"; mkdir -p "$WORK" gen/python/wire gen/ts/wire

echo "==> 1/4 JSON Schema from proto (bufbuild/protoschema)"
(cd proto && buf generate --template ../scripts/sdk-types/buf.jsonschema.yaml -o "../$WORK")

echo "==> 2/4 tools + merge (clean names; enums named from the descriptor)"
python3 -m venv "$WORK/venv"
# Pinned: generated output is byte-compared in CI, so the generator versions must be
# fixed (an unpinned datamodel-code-generator drifts the models in CI).
"$WORK/venv/bin/pip" install -q --disable-pip-version-check "datamodel-code-generator==0.64.0" protobuf
# required_fields.json: the authoritative protovalidate view of which fields are
# required on the wire (their zero value is rejected). merge_schema marks those
# `required` so the generated clients reject omission, matching the Go server.
go run ./conformance/requiredgen "$WORK/required_fields.json"
"$PY" scripts/sdk-types/merge_schema.py "$JS" gen/descriptor.binpb "$COMBINED" "$WORK/required_fields.json"

echo "==> 3/4 Pydantic v2 (datamodel-code-generator, --base-class + --collapse-root-models)"
"$WORK/venv/bin/datamodel-codegen" \
  --input "$COMBINED" --input-file-type jsonschema \
  --output gen/python/wire/models.py --output-model-type pydantic_v2.BaseModel \
  --base-class wire.base.WireModel --collapse-root-models --formatters black \
  --custom-file-header "# Code generated from the RAMP proto (via JSON Schema). DO NOT EDIT.
# Regenerate: scripts/gen-sdk-types.sh   Base class / extension seam: wire/base.py"

# Postprocess: drop the stray `class Model(RootModel[Any])` datamodel-codegen emits as
# the root of the (rootless) $defs document — it is unused noise.
"$PY" - gen/python/wire/models.py <<'PYEOF'
import re, sys
p = sys.argv[1]; s = open(p).read()
s = re.sub(r"\n\nclass Model\(RootModel\[Any\]\):\n    root: Any\n", "\n", s, count=1)
open(p, "w").write(s)
PYEOF

echo "==> 4/4 Zod (json-schema-to-zod)"
printf '{"name":"ramp-sdk-types-work","private":true,"type":"module"}\n' > "$WORK/package.json"
(cd "$WORK" && npm install --no-save json-schema-to-zod@2.8.1 zod)
cp scripts/sdk-types/gen_zod.mjs "$WORK/gen_zod.mjs"
node "$WORK/gen_zod.mjs" "$COMBINED" gen/ts/wire/schemas.ts

echo "==> done: gen/python/wire/models.py, gen/ts/wire/schemas.ts"
