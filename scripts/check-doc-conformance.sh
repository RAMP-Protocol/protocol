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
  # 'revshare' is intentionally NOT denylisted: it is a live CoMP ext identifier
  # (comp.license[].revshare) and scope prefix (revshare:...). The retired RAMP
  # *pricing model* is guarded via the enum-constant patterns below instead.
  'PER_ACCESS' 'REVENUE_SHARE'
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

# Search roots. `proto/ramp` is included so the gate also catches stale wire
# identifiers / orphan comments in the source of truth itself (the R3-6 class:
# a banner that survived the message it described). Only `proto/ramp` — NOT
# `proto/comp` — because comp.proto mirrors the external CoMP standard, which
# has its own vocabulary (e.g. a legitimate `revshare` field) that the RAMP
# removal denylist must not police.
roots=(website/src docs proto/ramp)

status=0

# --- 1. Denylist: removed/renamed identifiers must not reappear -------------
for p in "${patterns[@]}"; do
  hits=$(grep -rEn -- "$p" "${roots[@]}" 2>/dev/null | grep -Ev "$exclude_re" || true)
  if [ -n "$hits" ]; then
    echo "::error::removed/renamed identifier still present: ${p}"
    echo "$hits"
    status=1
  fi
done

# --- 2. Positive facts: required identifiers MUST be documented -------------
# A denylist is necessary but not sufficient: it cannot catch a value that was
# silently dropped from a "closed enum" table or a registry that drifted. These
# assertions fail the build when a live wire value is missing from the doc that
# claims to enumerate it.

proto_ramp='proto/ramp/v1/ramp.proto'
event_types='website/src/content/docs/components/transaction-log/event-types.mdx'

# Every DenialReason value (except UNSPECIFIED) must appear in the event-types
# "closed enum" table. (R4-9: the table silently lost values across renames.)
while read -r dr; do
  [ "$dr" = "DENIAL_REASON_UNSPECIFIED" ] && continue
  if ! grep -q -- "$dr" "$event_types"; then
    echo "::error::DenialReason '${dr}' is defined in the proto but missing from ${event_types}"
    status=1
  fi
done < <(grep -oE 'DENIAL_REASON_[A-Z_]+' "$proto_ramp" | sort -u)

# The delegation-claim registry (authentication.mdx) is a prose single-source
# for claim/fact names that live inside opaque tokens (no proto field to
# annotate). Guard the registered claim names against silent drift. (R4-7)
auth='website/src/content/docs/protocol/authentication.mdx'
for claim in 'ramp_max_spend_cents' 'ramp_max_accesses' 'ramp_quota_period'; do
  if ! grep -q -- "$claim" "$auth"; then
    echo "::error::registered delegation claim '${claim}' missing from ${auth}"
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "doc-conformance: clean"
fi
exit "$status"
