#!/usr/bin/env bash
#
# Canonical proto-JSON interop gate. Drives the generated clients (Pydantic + Zod)
# to re-serialize every valid corpus instance, then runs the Go conformance test
# that asserts each re-emission decodes — through Go protojson — to the same proto
# message as the original (TestCanonicalRoundTrip). This proves the clients' wire
# output is loss-free and ingestible by the Go server.
#
# Prereq: scripts/gen-sdk-types.sh has run (it provisions .sdk-types-work with the
# venv + zod node_modules and regenerates the clients). Usage: ./scripts/check-canonical.sh
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=.sdk-types-work
if [ ! -d "$WORK/venv" ] || [ ! -d "$WORK/node_modules/zod" ]; then
  echo "::error:: run scripts/gen-sdk-types.sh first (it provisions $WORK with the venv + zod)."
  exit 1
fi
PY="$WORK/venv/bin/python"
"$WORK/venv/bin/pip" install -q --disable-pip-version-check "pydantic>=2.0" >/dev/null 2>&1

CORPUS_ABS="$(pwd)/conformance/corpus/cases.json"
# Absolute: the Go test runs with cwd = ./conformance, so relative paths would miss.
PYEMIT="$(pwd)/$WORK/roundtrip_py.json"
TSEMIT="$(pwd)/$WORK/roundtrip_ts.json"

echo "==> Pydantic round-trip emission"
PYTHONPATH=gen/python "$PY" scripts/sdk-types/roundtrip_py.py "$CORPUS_ABS" > "$PYEMIT"

echo "==> Zod round-trip emission"
# Run from $WORK so the `zod` import inside schemas.ts resolves against its node_modules.
cp gen/ts/wire/schemas.ts "$WORK/schemas.ts"
cp scripts/sdk-types/roundtrip_ts.ts "$WORK/roundtrip_ts.ts"
( cd "$WORK" && node --experimental-strip-types roundtrip_ts.ts schemas.ts "$CORPUS_ABS" ) > "$TSEMIT"

echo "==> Go canonical round-trip assertion"
CANONICAL_PY="$PYEMIT" CANONICAL_TS="$TSEMIT" go test ./conformance -run TestCanonicalRoundTrip "$@"
