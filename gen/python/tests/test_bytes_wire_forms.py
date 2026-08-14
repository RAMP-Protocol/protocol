"""Direct behavioral regression for the base64 wire forms of a bytes-rule field.

protoschema renders a bytes field too loose in both rule kinds, so
merge_schema.tighten_bytes_len rewrites them from the bytesgen manifest:

  - bytes.len=32 (the Ed25519 keys, signed_url_hash): protoschema's 43..44
    CHARACTER window also admits a 33-byte value (44 unpadded chars) and a
    31-byte padded value (44 chars with '=='). The rewrite pins the payload to
    exactly 43 chars plus optional exact padding.
  - bytes.min_len=1 (the canonical-bytes fields): protoschema's pattern counts
    padding as content, so "==" (zero payload bytes, which Go protojson refuses
    to decode) passed. The rewrite requires the encoded payload chars of at
    least 1 byte BEFORE the padding tail.

The corpus cannot carry these cases: corpusgen sets values through protoreflect
and protojson always re-encodes bytes into ONE canonical form — the padded,
standard-alphabet encoding — so no unpadded, url-safe-alphabet, or
malformed-base64 STRING can ever appear in a corpus case. The encoding-form
axis is invisible to the corpus, and e.g. dropping the optional-padding tail
from the pattern would keep every corpus gate green while the clients then
reject the unpadded 43-char key Go accepts. This test covers the axis directly,
through the real generated models, exactly as test_numeric_wire_forms.py covers
the numeric wire-string form.

Run:  PYTHONPATH=gen/python python3 -m pytest gen/python/tests/test_bytes_wire_forms.py -q
"""
import pytest
from pydantic import ValidationError

import wire.models as models

# base64 of b"k"*32 — the corpus seed key value.
K32_PADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="
K32_UNPADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"
# base64 of bytes([0xFB, 0xEF] * 16) — 32 bytes chosen so the two alphabets
# actually diverge ('+'/'/' vs '-'/'_'); protojson decodes EITHER.
K32_STD_ALPHABET = "++/77/vv++/77/vv++/77/vv++/77/vv++/77/vv++8="
K32_URL_ALPHABET = "--_77_vv--_77_vv--_77_vv--_77_vv--_77_vv--8="
# 33 bytes, unpadded: 44 chars — INSIDE protoschema's old character window.
B33_UNPADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr"
# 31 bytes, padded: also 44 chars — the other side of the old window.
B31_PADDED = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2traw=="

# Valid corpus baselines (proto-JSON, snake_case), one per message under test.
BASES = {
    "TransactionEvidence": {
        "agent_acceptance_canonical_bytes": "eyJyZXF1ZXN0ZXJfaWQiOiJhZ2VudC1zZWVkIn0=",
        "agent_acceptance_signature": "ab" * 64,
        "agent_acceptance_signature_algorithm": "EdDSA",
        "agent_public_key": K32_PADDED,
        "created_at": "2026-01-02T03:04:05Z",
        "exchange_signing_public_key": K32_PADDED,
        "offer_canonical_bytes": "eyJvZmZlcl9pZCI6Im9mZmVyLXNlZWQifQ==",
        "offer_id": "offer-seed",
        "offer_json": '{"offer_id":"offer-seed"}',
        "offer_sig": "ab" * 64,
        "offer_sig_algorithm": "EdDSA",
        "request_idempotency_key": "idem-tx",
        "tenant_id": "tenant-seed",
        "transaction_id": "tx-seed",
    },
    "TransactionState": {
        "expiry": "2026-01-02T03:04:05Z",
        "idempotency_key": "idem-tx:offer-seed",
        "signed_url_hash": "aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGg=",
    },
}

# The base64 forms every EXACT-length (len=32) field must decide the same way.
EXACT32_FORMS = [
    (K32_PADDED, True),  # padded canonical form (what protojson emits)
    (K32_UNPADDED, True),  # unpadded form (protojson decodes it; the corpus never shows it)
    (K32_STD_ALPHABET, True),  # standard alphabet with real +/
    (K32_URL_ALPHABET, True),  # url-safe alphabet (a JWK "x" value pasted verbatim)
    (B33_UNPADDED, False),  # 33 bytes — inside the old 43..44 char window
    (B31_PADDED, False),  # 31 bytes padded — 44 chars, also inside the old window
    (K32_UNPADDED + "==", False),  # wrong padding length for a 32-byte payload
    ("", False),  # zero bytes
]

# The forms every MINIMUM-length (min_len=1) field must decide the same way.
MIN1_FORMS = [
    ("eyJvZmZlcl9pZCI6Im9mZmVyLXNlZWQifQ==", True),  # padded canonical form
    ("eyJvZmZlcl9pZCI6Im9mZmVyLXNlZWQifQ", True),  # same value, unpadded
    ("AA", True),  # exactly 1 byte, unpadded
    ("AA==", True),  # exactly 1 byte, padded
    ("-_", True),  # url-safe alphabet
    ("==", False),  # pure padding: ZERO payload bytes; Go protojson refuses to decode it
    ("=", False),
    ("A=", False),  # one payload char never decodes
    ("", False),  # zero bytes (min_len 1)
]

CASES = [
    *[("TransactionEvidence", "exchange_signing_public_key", v, ok) for v, ok in EXACT32_FORMS],
    *[("TransactionEvidence", "agent_public_key", v, ok) for v, ok in EXACT32_FORMS],
    *[("TransactionState", "signed_url_hash", v, ok) for v, ok in EXACT32_FORMS],
    *[("TransactionEvidence", "offer_canonical_bytes", v, ok) for v, ok in MIN1_FORMS],
    *[("TransactionEvidence", "agent_acceptance_canonical_bytes", v, ok) for v, ok in MIN1_FORMS],
]


@pytest.mark.parametrize(
    "cls_name,field,value,accepted",
    CASES,
    ids=[f"{m}.{f}={v!r}" for m, f, v, _ in CASES],
)
def test_bytes_rules_decide_every_base64_wire_form(cls_name, field, value, accepted):
    cls = getattr(models, cls_name)
    instance = {**BASES[cls_name], field: value}
    if accepted:
        assert cls.model_validate(instance) is not None
    else:
        with pytest.raises(ValidationError):
            cls.model_validate(instance)
