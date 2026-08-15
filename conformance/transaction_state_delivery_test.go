package conformance

import (
	"testing"

	protovalidate "buf.build/go/protovalidate"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
)

// TestTransactionStateSignedURLFieldsAreOptional pins both halves of the rule that
// lets an evidence row describe a transaction which minted no signed URL.
//
// TransactionState.signed_url_expiry and TransactionState.signed_url_hash both describe ONE
// artifact: the signed retrieval URL. DELIVERY_METHOD_DIRECT returns the resource
// inline or from the Exchange's own endpoint, so a direct transaction has no URL,
// no expiry and nothing to hash — while the row still exists, because the execute
// succeeded. Make either field mandatory and the Exchange has no legal value to
// send for a transaction it genuinely completed: an empty value fails the message's
// own validation, and a fabricated one asserts a delivery that never happened.
//
// The two halves fail in opposite directions, so both are pinned here:
//
//   - Drop the `optional` keyword from signed_url_hash and it becomes a singular
//     scalar with no presence. An unset value is then a PRESENT zero-length value,
//     bytes.len = 32 rejects it, and every direct-delivery row becomes unreadable —
//     while `buf breaking` stays quiet, because the change is wire-compatible.
//   - Weaken bytes.len = 32 (or re-add required = true on signed_url_expiry) and the row stops
//     pinning the digest it joins the edge delivery log on.
func TestTransactionStateSignedURLFieldsAreOptional(t *testing.T) {
	md := (&rampadminv1.TransactionState{}).ProtoReflect().Descriptor()

	hash := md.Fields().ByName("signed_url_hash")
	if hash == nil {
		t.Fatal("TransactionState has no signed_url_hash field")
	}
	if !hash.HasPresence() {
		t.Error("TransactionState.signed_url_hash lost explicit presence — restore the `optional` keyword; " +
			"without it an unset hash is a present zero-length value and bytes.len:32 rejects every " +
			"direct-delivery row")
	}
	if fr := FieldRules(md.Fields().ByName("signed_url_expiry")); fr.GetRequired() {
		t.Error("TransactionState.signed_url_expiry regained required = true — a DELIVERY_METHOD_DIRECT transaction " +
			"mints no signed URL, so it has no expiry to state and the Exchange could not answer " +
			"GetTransactionEvidence for a transaction that succeeded")
	}

	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	// A direct-delivery row: the derived per-item idempotency key and nothing else.
	direct := &rampadminv1.TransactionState{IdempotencyKey: "idem-tx:offer-seed"}
	if err := v.Validate(direct); err != nil {
		t.Errorf("a TransactionState omitting signed_url_expiry and signed_url_hash was rejected: %v\n"+
			"that is the shape of every DELIVERY_METHOD_DIRECT transaction and it must be valid", err)
	}

	// A PRESENT hash is still pinned to a full sha256 digest. Optional buys absence,
	// never a short or long value: 31 and 33 bytes bracket the rule, and a present
	// empty value is the case the `optional` keyword itself creates.
	for _, n := range []int{0, 31, 33} {
		row := &rampadminv1.TransactionState{
			IdempotencyKey: "idem-tx:offer-seed",
			SignedUrlHash:  make([]byte, n),
		}
		if err := v.Validate(row); err == nil {
			t.Errorf("a present %d-byte signed_url_hash was accepted; bytes.len = 32 must still bind "+
				"any value that IS stated", n)
		}
	}

	// The signed-URL case still validates end to end.
	full := &rampadminv1.TransactionState{
		IdempotencyKey: "idem-tx:offer-seed",
		SignedUrlHash:  make([]byte, 32),
	}
	if err := v.Validate(full); err != nil {
		t.Errorf("a TransactionState carrying a 32-byte signed_url_hash was rejected: %v", err)
	}
}
