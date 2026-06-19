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
  # token / vocabulary — both the hyphenated token form and the prose spelling;
  # the canonical optional delegation format is biscuit-v3, and entitlement
  # denials are format-neutral ("entitlement token", not "biscuit").
  'biscuit-v2' 'Biscuit v2'
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
  # Removed CoMP Go path (req.Aisystem.Aisysuse.…). Narrow Go-path patterns only,
  # so legitimate CoMP JSON keys elsewhere don't false-positive. (R5-9)
  'req\.Aisystem' '\.Aisysuse\.'
  # Fields from the deleted AccessRestrictions message — express as Quota now.
  'max_display_words'
  # Underscore function tokens — the registered RAMP vocabulary is dashed
  # (ai-input/ai-train/ai-index). Lowercase underscore forms are wrong; CoMP's
  # uppercase AI_INPUT enum is unaffected (case-sensitive). (CON-05)
  'ai_input' 'ai_train' 'ai_index'
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
# Authored documentation prose only — NOT website/src/data (generated proto views
# like symbols.json, whose live field names e.g. `maxIntermediaryHops` would
# substring-match removal-denylist entries) and NOT website/src/components (code).
roots=(website/src/content docs proto/ramp)

status=0

# Hard-coded paths the positive-fact checks below depend on. Assert up front so a
# rename fails loudly here instead of silently skipping a check — a grep against a
# missing file just yields no matches and would false-pass. (LR-02)
proto_ramp='proto/ramp/v1/ramp.proto'
event_types='website/src/content/docs/components/transaction-log/event-types.mdx'
auth='website/src/content/docs/protocol/authentication.mdx'
for f in "$proto_ramp" "$event_types" "$auth"; do
  [ -f "$f" ] || { echo "::error::check-doc-conformance: required file missing (renamed? update this script): $f"; status=1; }
done

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

# Every DenialReason value (except UNSPECIFIED) must appear in the event-types
# "closed enum" table. (R4-9: the table silently lost values across renames.)
dr_n=0
while read -r dr; do
  dr_n=$((dr_n + 1))
  [ "$dr" = "DENIAL_REASON_UNSPECIFIED" ] && continue
  if ! grep -q -- "$dr" "$event_types"; then
    echo "::error::DenialReason '${dr}' is defined in the proto but missing from ${event_types}"
    status=1
  fi
done < <(grep -oE 'DENIAL_REASON_[A-Z_]+' "$proto_ramp" | sort -u)
# Anti-vacuity floor: if extraction finds nothing, this check would pass for the
# wrong reason. (The Go invariants carry the same `checked == 0` guard.)
if [ "$dr_n" -eq 0 ]; then
  echo "::error::doc-conformance: no DENIAL_REASON_* values found in ${proto_ramp} — extraction drifted; this check would pass vacuously"
  status=1
fi

# Delegation-claim registry guard (R4-7 / R5-8). The registered JWT claims are
# named `ramp_<field>` where <field> is a Delegation proto field. Self-extending:
# derive the registered claim names straight from the auth registry (the only
# place `ramp_` underscored identifiers appear) and assert each maps to a real
# field on the Delegation proto message — so a typo'd or orphaned registry claim
# fails the build, and a newly-registered claim is checked automatically with no
# hardcoded list to drift.
# Scope the field lookup to the Delegation message body only — grepping the whole
# proto would falsely accept e.g. `ramp_offer_id` (offer_id exists on
# TransactionItem, not Delegation).
deleg_block=$(awk '/^message Delegation \{/,/^\}/' "$proto_ramp")
claim_n=0
while read -r claim; do
  [ -z "$claim" ] && continue
  claim_n=$((claim_n + 1))
  field=${claim#ramp_}
  # Defensive: only [a-z_] field names are expected. Reject anything else rather
  # than interpolate it into the grep pattern below, so a future change to the
  # extraction regex can never smuggle a regex metacharacter into the match.
  if ! [[ "$field" =~ ^[a-z_]+$ ]]; then
    echo "::error::registered delegation claim '${claim}' has an unexpected field name '${field}' (only [a-z_] permitted)"
    status=1
    continue
  fi
  if ! grep -qE "[[:space:]]${field}[[:space:]]*=" <<<"$deleg_block"; then
    echo "::error::registered delegation claim '${claim}' has no matching '${field}' field on the Delegation proto message"
    status=1
  fi
done < <(grep -oE 'ramp_[a-z][a-z_]*' "$auth" | sort -u)
if [ "$claim_n" -eq 0 ]; then
  echo "::error::doc-conformance: no ramp_* delegation claims found in ${auth} — extraction drifted; this check would pass vacuously"
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "doc-conformance: clean"
fi
exit "$status"
