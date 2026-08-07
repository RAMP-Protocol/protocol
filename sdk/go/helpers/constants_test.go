package helpers_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestWireConstants pins the wire constants and, by importing both helpers
// (L1) and the generated L0 types in one test, proves the scaffold wiring: L1
// lives in the root module and can reach L0 with no replace directive.
func TestWireConstants(t *testing.T) {
	if helpers.ContentTypeProto != "application/proto" {
		t.Errorf("ContentTypeProto = %q", helpers.ContentTypeProto)
	}
	if helpers.ContentTypeJSON != "application/json" {
		t.Errorf("ContentTypeJSON = %q", helpers.ContentTypeJSON)
	}
	if helpers.ConnectProtocolVersion != "1" {
		t.Errorf("ConnectProtocolVersion = %q", helpers.ConnectProtocolVersion)
	}
	if helpers.ProtocolVersion != "1.0" {
		t.Errorf("ProtocolVersion = %q", helpers.ProtocolVersion)
	}

	// L0 reachability: construct a generated message from L1's module.
	if _, ok := any(&rampv1.DiscoveryRequest{}).(interface{ Reset() }); !ok {
		t.Fatal("expected generated DiscoveryRequest to be reachable from sdk/go")
	}
}
