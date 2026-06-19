#!/usr/bin/env bash
#
# The single source of the proto gating sequence — runs the full set in ONE
# command so the "I only ran a subset of the checks" failure mode cannot recur.
# .github/workflows/proto-ci.yml invokes THIS script (it does not re-list the
# steps), so CI and local cannot drift.
#
# Non-destructive: it does not modify your git index or working tree (the drift
# check compares the regenerated output against HEAD rather than `git add -A`).
#
# Usage:  ./scripts/ci-local.sh
# Exit:   0 = all gating steps pass; 1 = at least one failed.

set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
note() { printf '    %s\n' "$1"; }

step "buf lint"
(cd proto && buf lint) || fail=1

step "buf generate"
(cd proto && buf generate) || fail=1
# The docs site reads the schema from the compiler's descriptor (comments + custom
# options included), not from hand-written tables. Emit it as a committed, drift-gated
# artifact so the Amplify build needs only the file, never buf. See docs/design-history.md.
(cd proto && buf build -o ../gen/descriptor.binpb) || fail=1

step "assert no generated drift"
# gen/ is generated output; after `buf generate` it MUST match the committed
# tree. This is the load-bearing gate (CI's git-add-A + diff). We compare
# against HEAD and also flag untracked generated files (e.g. a new vocab axis
# whose gen/.../<axis>/ was generated but never committed).
if ! git diff --quiet HEAD -- gen/ || [ -n "$(git ls-files --others --exclude-standard -- gen/)" ]; then
  echo "::error:: generated code is out of sync with the proto/plugin. Run 'cd proto && buf generate' and commit gen/."
  git status --short -- gen/
  fail=1
else
  note "no drift"
fi

step "go build / vet / test"
go build ./... || fail=1
go vet ./... || fail=1
go test ./... || fail=1

step "doc conformance"
./scripts/check-doc-conformance.sh || fail=1

step "docs guards (remark-proto fail-path)"
# Proves the build-gating doc guard still bites (throws on an unknown proto
# reference). Skipped only if the docs deps aren't installed locally.
if [ -d website/node_modules ]; then
  (cd website && npm test --silent) || fail=1
else
  note "skipped — run 'npm install' in website/ to enable"
fi

step "buf breaking (informational, pre-v1 — non-blocking)"
# Matches CI: continue-on-error. Never affects the exit status.
(cd proto && buf breaking \
  --against 'https://github.com/RAMP-Protocol/protocol.git#branch=main,subdir=proto') \
  || note "(informational only — does not gate)"

if [ "$fail" -ne 0 ]; then
  printf '\n\033[31m==> CI-local: FAIL\033[0m\n'
  exit 1
fi
printf '\n\033[32m==> CI-local: PASS\033[0m\n'
