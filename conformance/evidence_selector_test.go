package conformance

import (
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
)

// TestEvidenceSelectorIsAPair pins the two-field selector on
// GetTransactionEvidenceRequest, because an AGENT-plane statement depends on it.
//
// ramp.v1.TransactionResultItem.transaction_id tells every implementer that RAMP
// places no entropy requirement on a transaction id, and it grounds that on this
// message: the evidence read selects by the (tenant_id, transaction_id) PAIR, so
// an id ALONE is never a bearer capability for the forensic row. Counterparty
// agents legitimately hold transaction ids, so that pairing is the entire reason
// a predictable id is acceptable.
//
// The dependency crosses packages and had nothing holding it. Deleting tenant_id
// or dropping its min_len would leave every gate green: the only other mention is
// inside the GENERATED corpus, which would simply regenerate smaller, and
// committing the smaller corpus makes the tree pass again. That is a visible diff,
// not a failure — and meanwhile the published agent-plane spec would go on telling
// implementers that predictable transaction ids are safe, having lost the
// mechanism that made them safe.
//
// This guard turns that silent weakening into a failing test. It deliberately
// checks BEHAVIOUR (each half is rejected when empty) rather than the rule text:
// what the agent-plane claim needs is that neither half can be omitted, however
// that is expressed.
func TestEvidenceSelectorIsAPair(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	md := (&rampadminv1.GetTransactionEvidenceRequest{}).ProtoReflect().Descriptor()
	for _, name := range []string{"transaction_id", "tenant_id"} {
		if md.Fields().ByName(protoreflect.Name(name)) == nil {
			t.Fatalf("GetTransactionEvidenceRequest lost its %s field — the evidence read no longer "+
				"selects by a pair, so ramp.v1.TransactionResultItem.transaction_id's entropy "+
				"statement is now false and must be rewritten before this field goes", name)
		}
	}

	// The complete pair is the only accepted selector.
	if err := v.Validate(&rampadminv1.GetTransactionEvidenceRequest{
		TransactionId: "01JC0X8N9WQ0000000000000AB",
		TenantId:      "hearst-media",
	}); err != nil {
		t.Errorf("a complete (tenant_id, transaction_id) selector was rejected: %v", err)
	}

	// Each half missing must be refused. The tenant half is the load-bearing one
	// for the agent-plane claim: without it a bare transaction id would read the row.
	halves := []struct {
		name string
		req  *rampadminv1.GetTransactionEvidenceRequest
		why  string
	}{
		{
			"tenant_id",
			&rampadminv1.GetTransactionEvidenceRequest{TransactionId: "01JC0X8N9WQ0000000000000AB"},
			"a transaction id alone would become a bearer capability for the forensic row, which is " +
				"exactly what ramp.v1 promises it is not",
		},
		{
			"transaction_id",
			&rampadminv1.GetTransactionEvidenceRequest{TenantId: "hearst-media"},
			"a tenant alone does not name a row; an unselective read is not what this RPC offers",
		},
	}
	for _, h := range halves {
		if err := v.Validate(h.req); err == nil {
			t.Errorf("a selector omitting %s was accepted — %s", h.name, h.why)
		}
	}
}
