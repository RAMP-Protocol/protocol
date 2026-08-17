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
  # Requester.billing_ref dropped: billing keys on the verified
  # caller identity and the account minted at Register, never on a request
  # field. Only the Requester-scoped forms are banned — the bare identifier
  # stays live (RegisterResponse / GetAccountStatusResponse account handle).
  # Covered forms: the dotted token (with an optional markdown-escaped
  # underscore, billing\_ref) and the adjacent possessive/prose form
  # ("the Requester's billing_ref"). JSON examples are gated by the
  # conformance candidate detector (TestDocMarkedExamplesValidate), not this
  # grep — do not widen these into a proximity pattern; it would
  # false-positive on the live account-handle prose (e.g. the
  # ACCOUNT_INACTIVE comment in ramp.proto, which keeps the words "account (the"
  # between the possessive and the identifier so this pattern does not match it).
  '[Rr]equester\.billing\\?_ref' '[Rr]equester\.[Bb]illingRef'
  "[Rr]equester'?s?[[:space:]]+\`?billing\\\\?_ref"
  # the manifest's registration field became a block: registration_schema (a flat
  # Struct) is now account_registration.data_schema, so the old name must not
  # linger in prose, tables or example payloads.
  #
  # Anchored on word boundaries, unlike most patterns here, because the SDK face
  # that implements the SUCCESSOR field's rules is legitimately named for it:
  # CompileRegistrationSchema / compile_registration_schema /
  # registrationSchemaDialect all contain the banned string as a substring while
  # naming the live contract, and they appear in the GENERATED parity matrix, which
  # cannot be edited to appease a grep. A boundary keeps the ban on the identifier
  # (`registration_schema`, `WellKnownManifest.registration_schema`) and off the
  # longer names that merely contain it — `_` and a following capital are both word
  # characters, so neither side of the successor names ever matches.
  '\bregistration_schema\b' '\bregistrationSchema\b'
  # the single billing-reference denial split into ACCOUNT_NOT_REGISTERED ("no
  # account — call Register") and ACCOUNT_INACTIVE ("account exists, awaiting
  # operator activation"); the two are different agent actions, so the old
  # conflated name must not survive anywhere it could still be read as live.
  'BILLING_REF_INACTIVE'
  # request signatures live in HTTP headers (RFC 9421), not message fields
  'caller_signature' 'agent_signature' 'orchestrator_signature' 'broker_signature'
  # the scalar offer_signature pair is gone: the execute-request now reflects the
  # FULL signed Offer back (offer.signature carries the JWS). offer_id stays live.
  'offer_signature' 'offer_signature_algorithm'
  # token / vocabulary — both the hyphenated token form and the prose spelling;
  # the canonical optional delegation format is biscuit-v3 (NEVER v2), and
  # entitlement denials are format-neutral ("entitlement token", not "biscuit").
  # The banned v2 spellings are split string literals so they don't appear
  # verbatim in the repo; the runtime patterns still match both the hyphenated
  # token and the spaced prose form.
  'biscuit-''v2' 'Biscuit ''v2'
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
  # so legitimate CoMP JSON keys elsewhere don't false-positive.
  'req\.Aisystem' '\.Aisysuse\.'
  # Fields from the deleted AccessRestrictions message — express as Quota now.
  'max_display_words'
  # Underscore function tokens — the registered RAMP vocabulary is dashed
  # (ai-input/ai-train/ai-index). Lowercase underscore forms are wrong; CoMP's
  # uppercase AI_INPUT enum is unaffected (case-sensitive). (CON-05)
  'ai_input' 'ai_train' 'ai_index'
  # real-company example names that must stay generic. Split string literal so the
  # banned word does not appear verbatim anywhere in the repo (the runtime pattern
  # is still [Bb]loomberg).
  '[Bb]loom''berg'
  # Identity split (#16): keys moved out of the manifest (WellKnownManifest.
  # public_keys / invalidation_url) into the WBA directory (WBAFile.keys /
  # revocation_url), and the per-key `kid` label was dropped in favour of the
  # RFC 7638 thumbprint (the RFC 9421 keyid). The `"kid"` pattern is anchored to
  # the JSON-key form so it does NOT collide with the live `keyid` identifier or
  # with legitimate "keys carry no kid" prose.
  'public_keys' 'invalidation_url' 'KeyInvalidationList' '"kid"[[:space:]]*:'
)

# Files where naming a removed identifier is legitimate (they record history).
exclude_re='(reference/changelog\.mdx|docs/design-history\.md|proto/CHANGELOG\.md)'

# Search roots. `proto/ramp` is included so the gate also catches stale wire
# identifiers / orphan comments in the source of truth itself (e.g.
# a banner that survived the message it described). Only `proto/ramp` — NOT
# `proto/comp` — because comp.proto mirrors the external CoMP standard, which
# has its own vocabulary (e.g. a legitimate `revshare` field) that the RAMP
# removal denylist must not police.
# Authored documentation prose only — NOT website/src/data (data modules such as
# standards.mjs, not authored prose) and NOT website/src/components (code).
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

# --- 1b. Banned vocabulary: non-canonical role synonyms ---------------------
# The contract's two roles are Requester (the AI/demand side) and Provider (the
# content/supply side). "Buyer"/"Seller" are pre-standardization synonyms; left
# in PROSE they drift the vocabulary the proto and the rest of the docs
# standardize on (the "Buyer's balance" class).
#
# This bans the PROSE word only. The boundary `(^|[^A-Za-z0-9._/-])…([^…]|$)`
# (ERE, so it also works under BSD grep in ci-local) deliberately does NOT match
# identifiers/URLs/tokens where the word is glued to `. _ / -`: the live CoMP
# field `comp.seller`, code like `buyer_lid` / `QueryByBuyer`, `buyer.example.com`,
# the `ramp-ai-buyer` user-agent, or the ordinary word "re·seller". Those are
# protocol facts, not synonym drift. Each entry is "pattern#canonical" (`#`
# delimiter, since the pattern itself contains `|`).
bound_l='(^|[^A-Za-z0-9._/-])'
bound_r='([^A-Za-z0-9._/-]|$)'
vocab=(
  "${bound_l}[Bb]uyers?${bound_r}#Requester"
  "${bound_l}[Ss]ellers?${bound_r}#Provider"
)
for entry in "${vocab[@]}"; do
  p=${entry%%#*}; canon=${entry#*#}
  hits=$(grep -rEn -- "$p" "${roots[@]}" 2>/dev/null | grep -Ev "$exclude_re" || true)
  if [ -n "$hits" ]; then
    echo "::error::non-canonical role vocabulary (prose) — use '${canon}' (Requester/Provider are the standard role terms):"
    echo "$hits"
    status=1
  fi
done

# --- 1c. Enum wire numbers must not appear in prose ------------------------
# Docs cite an enum by its named constant, never its wire integer: nobody sends
# the number, they send the name, and a hand-typed number is the one thing that
# can silently drift from the proto (the M-5 "value 9" vs proto's 7 class). The
# named constant is autolinked / directive-rendered and cannot drift; the number
# adds nothing a reader needs. Ban `SOME_CONSTANT (value N)` outright so the
# generator's guarantees aren't bypassed by a parenthesised integer in a
# sentence. Matches an ALL_CAPS constant (optionally back-ticked) directly
# followed by a "(value N)" annotation.
num_hits=$(grep -rEn -- '[A-Z][A-Z0-9_]{4,}`?[[:space:]]*\(value[[:space:]]*[0-9]+\)' "${roots[@]}" 2>/dev/null | grep -Ev "$exclude_re" || true)
if [ -n "$num_hits" ]; then
  echo "::error::enum wire number hand-typed in prose — cite the named constant only, drop the '(value N)':"
  echo "$num_hits"
  status=1
fi

# --- 2. Positive facts: required identifiers MUST be documented -------------
# A denylist is necessary but not sufficient: it cannot catch a value that was
# silently dropped from a "closed enum" table or a registry that drifted. These
# assertions fail the build when a live wire value is missing from the doc that
# claims to enumerate it.

# (The former "every DenialReason value appears in event-types.mdx" check was
# removed: event-types now renders the enum via `::proto-enum{name=DenialReason}`,
# which emits every value straight from the proto — coverage is structural, and the
# remark-proto guard forbids re-introducing a hand-typed copy. The grep here would
# only have searched the directive source, not the rendered values.)

# Delegation-claim registry guard. The registered JWT claims are
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

# --- 3. Wrong-org references -----------------------------------------------
# The project lives at github.com/RAMP-Protocol. The pre-rename org literal must not
# appear anywhere — code, docs, config, copyright. The literal is built from two
# pieces below so this script does not contain it verbatim, and therefore scans its
# own file too (no self-exclusion blind spot).
old_org='postin''dustria'
org_hits=$(git grep -niF "$old_org" -- . 2>/dev/null || true)
if [ -n "$org_hits" ]; then
  echo "::error::stale '${old_org}' org reference (the project is github.com/RAMP-Protocol):"
  echo "$org_hits"
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "doc-conformance: clean"
fi
exit "$status"
