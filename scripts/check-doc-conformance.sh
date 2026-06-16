#!/usr/bin/env bash
# Doc-conformance gate.
#
# Fails if an identifier that was REMOVED or RENAMED from the wire contract
# reappears in the docs. This is the documentation counterpart to the gen-drift
# gate: just as a stale `gen/` fails the build, stale prose should too.
#
# Maintenance: when you remove or rename a proto identifier, add the old name
# here. Historical-record files (changelogs, design-history) are excluded — they
# legitimately say "X was removed".
set -uo pipefail
cd "$(dirname "$0")/.."

# Removed / renamed identifiers that must not appear in current docs.
patterns=(
  # Requester reshape
  'license_id' 'licenseId' 'BuyerLicenseID'
  'IntermediaryHop' '"intermediaries"'
  # request signatures live in HTTP headers (RFC 9421), not message fields
  'caller_signature' 'agent_signature' 'orchestrator_signature' 'broker_signature'
  'offer_signature_algorithm'
  # token / vocabulary
  'biscuit-v2'
  'PER_ACCESS' 'REVENUE_SHARE' 'revshare'
  'PRICING_MODEL_ATTRIBUTION' 'PRICING_MODEL_CONTRIBUTION'
  'spdx_expression'
  # collapsed reason enums
  'FUNCTION_PROHIBITED' 'GEO_RESTRICTED' 'USER_CATEGORY_PROHIBITED'
  'INVALID_LICENSE' 'EXPIRED_LICENSE' 'DELEGATION_EXPIRED'
  # CoMP Package is an ext profile, not a core Offer field
  '"package":'
  # real-company example names that must stay generic
  '[Bb]loomberg'
)

# Files where naming a removed identifier is legitimate (they record history).
exclude_re='(reference/changelog\.mdx|docs/design-history\.md|proto/CHANGELOG\.md)'

status=0
for p in "${patterns[@]}"; do
  hits=$(grep -rEn -- "$p" website/src docs 2>/dev/null | grep -Ev "$exclude_re" || true)
  if [ -n "$hits" ]; then
    echo "::error::removed/renamed identifier still present in docs: ${p}"
    echo "$hits"
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "doc-conformance: clean"
fi
exit "$status"
