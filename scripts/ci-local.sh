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

# Pin buf so the committed gen/descriptor.binpb (a byte-exact, drift-gated
# artifact) is reproducible. A newer buf re-encodes the descriptor with no
# schema change and fails the drift gate (the H1 class). CI pins the same
# version in proto-ci.yml; keep the two in lockstep.
want_buf=1.66.1
have_buf=$(buf --version 2>/dev/null || echo 'not-found')
if [ "$have_buf" != "$want_buf" ]; then
  echo "::error:: buf ${have_buf} != pinned ${want_buf} — the committed gen/ is built with ${want_buf}; install it (the drift gate compares bytes, so a different buf fails)."
  fail=1
fi

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
  echo "::error:: generated code is out of sync with the proto/plugin. Run 'cd proto && buf generate && buf build -o ../gen/descriptor.binpb' (descriptor.binpb comes from buf build, not buf generate) and commit gen/."
  git status --short -- gen/
  fail=1
else
  note "no drift"
fi

step "regenerate validation corpus"
# conformance/corpus/cases.json is the generated cross-language oracle (proto-JSON
# instances + Go protovalidate's verdict). Regenerate and gate on drift, exactly
# like gen/: a proto change that shifts a constraint must reflow into the corpus.
go run ./conformance/corpusgen || fail=1
if ! git diff --quiet HEAD -- conformance/corpus/ || [ -n "$(git ls-files --others --exclude-standard -- conformance/corpus/)" ]; then
  echo "::error:: validation corpus out of sync — run 'go run ./conformance/corpusgen' and commit conformance/corpus/."
  git status --short -- conformance/corpus/
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
