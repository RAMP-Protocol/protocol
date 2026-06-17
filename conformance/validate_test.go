// Package conformance holds machine checks that the doc-conformance denylist
// gate structurally cannot perform: it actually *evaluates* the protovalidate
// CEL constraints embedded in the proto, and validates the example payloads in
// the docs against the wire contract. A green run here means the constraints
// fire as written and the documented examples would survive ingestion.
package conformance

import (
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestProtovalidateConstraints exercises every CEL/standard constraint added by
// the licensing core against representative valid and invalid instances. Until
// this existed, a syntactically-valid-but-wrong CEL (mis-anchored regex,
// renamed field reference) shipped green because nothing in the toolchain ever
// evaluated the constraints — `buf lint` is style-only and `buf generate` just
// embeds the option bytes. This is the regression guard for that whole class.
func TestProtovalidateConstraints(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	hex64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cases := []struct {
		name      string
		msg       proto.Message
		wantValid bool
	}{
		// License.uri_digest — strong-hash structure only.
		{"uri_digest empty ok", &rampv1.License{UriDigest: proto.String("")}, true},
		{"uri_digest sha256 ok", &rampv1.License{UriDigest: proto.String("sha256:" + hex64)}, true},
		{"uri_digest md5 rejected", &rampv1.License{UriDigest: proto.String("md5:" + hex64)}, false},
		{"uri_digest sha256 wrong length", &rampv1.License{UriDigest: proto.String("sha256:dead")}, false},
		{"uri_digest sha256 non-hex", &rampv1.License{UriDigest: proto.String("sha256:" + "g" + hex64[1:])}, false},

		// Pricing message-level CEL: PER_UNIT⇒unit set; FREE⇒rate 0.
		{"pricing per_unit with unit ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("tokens"), Currency: "USD", Rate: 0.05}, true},
		{"pricing per_unit without unit rejected", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Currency: "USD", Rate: 0.05}, false},
		{"pricing free zero rate ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: 0}, true},
		{"pricing free nonzero rate rejected", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: 1.0}, false},

		// Pricing.unit format: empty / bare-dashed / vendor:namespaced.
		{"pricing unit bare ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("sq-km"), Rate: 1}, true},
		{"pricing unit vendor ok", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("acme:widgets"), Rate: 1}, true},
		{"pricing unit with space rejected", &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("two words"), Rate: 1}, false},

		// AcceptableRestriction.values charset + max_items.
		{"acceptable values ok", &rampv1.AcceptableRestriction{Axis: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: []string{"ai-train", "ai-input"}}, true},
		{"acceptable values space rejected", &rampv1.AcceptableRestriction{Axis: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: []string{"ai train"}}, false},
		{"acceptable values too many rejected", &rampv1.AcceptableRestriction{Axis: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: gen65()}, false},

		// Restriction.permitted/prohibited charset.
		{"restriction permitted ok", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}}, true},
		{"restriction permitted control-char rejected", &rampv1.Restriction{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"bad\ttoken"}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.msg)
			if tc.wantValid && err != nil {
				t.Errorf("expected VALID, got error: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Errorf("expected INVALID, but validation passed")
			}
		})
	}
}

func gen65() []string {
	s := make([]string, 65)
	for i := range s {
		s[i] = "tok"
	}
	return s
}
