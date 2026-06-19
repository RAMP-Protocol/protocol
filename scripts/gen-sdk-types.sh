#!/usr/bin/env bash
# Generate the TypeScript (Zod) and Python (Pydantic) TYPES EXPORT from the proto,
# via JSON Schema. This is NOT a full SDK — it is the message types + per-field
# validation (shape + protovalidate standard constraints: enum.not_in, string.pattern,
# min/max, …). Cross-field rules stay server-authoritative (Go protovalidate).
#
# Pipeline:  proto --buf/protoschema--> JSON Schema --merge--> one $defs doc
#            --datamodel-code-generator--> gen/python/ramp/models.py   (Pydantic v2)
#            --json-schema-to-zod--------> gen/ts/ramp/schemas.ts       (Zod)
#
# Prerequisites: go, python3, node/npm (npx). The script provisions its own throwaway
# venv + node_modules under .sdk-types-work/ (gitignored).
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=.sdk-types-work
JS="$WORK/jsonschema"
COMBINED="$WORK/combined.json"
rm -rf "$WORK"; mkdir -p "$WORK" gen/python/ramp gen/ts/ramp

echo "==> 1/4 JSON Schema from proto (bufbuild/protoschema)"
(cd proto && buf generate --template ../scripts/sdk-types/buf.jsonschema.yaml -o "../$WORK")

echo "==> 2/4 merge into one \$defs doc (clean message names)"
python3 scripts/sdk-types/merge_schema.py "$JS" "$COMBINED"

echo "==> 3/4 Pydantic v2 (datamodel-code-generator)"
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q --disable-pip-version-check datamodel-code-generator
"$WORK/venv/bin/datamodel-codegen" \
  --input "$COMBINED" --input-file-type jsonschema \
  --output gen/python/ramp/models.py --output-model-type pydantic_v2.BaseModel \
  --formatters black \
  --custom-file-header "# Code generated from the RAMP proto (via JSON Schema). DO NOT EDIT.
# Regenerate: scripts/gen-sdk-types.sh"

echo "==> 4/4 Zod (json-schema-to-zod)"
printf '{"name":"ramp-sdk-types-work","private":true,"type":"module"}\n' > "$WORK/package.json"
(cd "$WORK" && npm install --no-save json-schema-to-zod zod)
# Run the generator from inside the work dir so ESM resolves json-schema-to-zod from
# its node_modules (ESM ignores NODE_PATH); paths are passed relative to repo root.
cp scripts/sdk-types/gen_zod.mjs "$WORK/gen_zod.mjs"
node "$WORK/gen_zod.mjs" "$COMBINED" gen/ts/ramp/schemas.ts

echo "==> done: gen/python/ramp/models.py, gen/ts/ramp/schemas.ts"
