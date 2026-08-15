package conformance

import (
	"testing"

	protovalidate "buf.build/go/protovalidate"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
)

// TestAgentDirectoryURLAdmits pins what TransactionEvidence.agent_directory_url
// actually accepts, because its comment makes specific claims about that and a
// reader makes security decisions on them.
//
// The field is provenance, not authority: it is covered by neither signature and
// is written by the same party as the rest of the row, so its rule cannot make
// following the URL safe. What the rule does is bound the damage when tooling
// follows it anyway — and the comment states the bound precisely, including what
// it does NOT catch. This table is the proof that the stated bound is the real
// one. A row that is silently stricter than its comment breaks legitimate
// evidence; one that is silently looser is a claim the schema does not keep.
func TestAgentDirectoryURLAdmits(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	cases := []struct {
		value    string
		accepted bool
		why      string
	}{
		{"", true,
			"the agent carried no directory anchor; an append-once row states a value for every column"},
		{"https://agent.example/.well-known/http-message-signatures-directory", true,
			"the ordinary WBA identity-directory URL the Exchange pins from"},
		{"https://agent.example:8443/.well-known/x", true,
			"an explicit port, same port grammar as the recipient host"},
		{"https://169.254.169.254/", true,
			"STATED NON-GUARANTEE: the recipient-host grammar admits all-numeric labels, so an " +
				"IPv4 literal passes. Blocking link-local and private address space is the fetching " +
				"tool's job — if this ever flips to rejected, the comment must stop saying it passes"},
		{"http://169.254.169.254/", false,
			"plaintext scheme — https is the only accepted scheme, which is what refuses this one"},
		{"ftp://agent.example/x", false, "non-http scheme"},
		{"file:///etc/passwd", false, "no host, and not an https scheme"},
		{"https://agent.example", false,
			"no path: the value is a directory URL, and a bare origin is not one"},
		{"https://user:pw@agent.example/x", false,
			"embedded userinfo — credentials in a stored, replayed-into-tooling URL"},
		{"https://agent.example/a b", false,
			"raw space: the path is ASCII-printable, so an unencoded space cannot ride through"},
	}

	for _, c := range cases {
		row := &rampadminv1.TransactionEvidence{AgentDirectoryUrl: c.value}
		accepted := true
		if verr, ok := v.Validate(row).(*protovalidate.ValidationError); ok {
			for _, viol := range verr.Violations {
				if els := viol.Proto.GetField().GetElements(); len(els) > 0 &&
					els[0].GetFieldName() == "agent_directory_url" {
					accepted = false
				}
			}
		}
		if accepted != c.accepted {
			t.Errorf("agent_directory_url %q: accepted=%v, want %v — %s", c.value, accepted, c.accepted, c.why)
		}
	}
}
