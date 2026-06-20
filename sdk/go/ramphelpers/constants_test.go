package ramphelpers_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

// TestWireConstants pins the wire constants and, by importing both ramphelpers
// (L1) and the generated L0 types in one test, proves the scaffold wiring: L1
// lives in the root module and can reach L0 with no replace directive.
func TestWireConstants(t *testing.T) {
	if ramphelpers.ContentTypeProto != "application/proto" {
		t.Errorf("ContentTypeProto = %q", ramphelpers.ContentTypeProto)
	}
	if ramphelpers.ContentTypeJSON != "application/json" {
		t.Errorf("ContentTypeJSON = %q", ramphelpers.ContentTypeJSON)
	}
	if ramphelpers.ConnectProtocolVersion != "1" {
		t.Errorf("ConnectProtocolVersion = %q", ramphelpers.ConnectProtocolVersion)
	}

	// L0 reachability: construct a generated message from L1's module.
	if _, ok := any(&rampv1.RAMPRequest{}).(interface{ Reset() }); !ok {
		t.Fatal("expected generated RAMPRequest to be reachable from sdk/go")
	}
}
