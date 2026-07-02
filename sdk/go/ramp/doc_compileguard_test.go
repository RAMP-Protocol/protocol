//go:build compileguard_demo

// This file is DELIBERATELY excluded from the build (build tag
// `compileguard_demo`, never set in CI or `go test`). It documents the
// compile-time guard that the runtime tests in client_verify_test.go cannot
// assert directly — "does not compile" is not a runtime assertion. The snippets
// below are the // want-compile-error examples: each line is annotated with the
// compiler error it MUST produce once package sdk/go/ramp exists. An app cannot
// forge a VerifiedOffer and cannot hand Execute anything but one.
//
// Do NOT remove the build tag: including this file in the normal build would make
// the package fail to compile for the WRONG reason (these are intentional type
// errors), muddying the greenfield red signal ("package sdk/go/ramp does not
// exist yet").

package ramp_test

import (
	"context"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramp"
)

func compileGuardDemo(client *ramp.Client, res ramp.Result) {
	ctx := context.Background()

	// OK: Execute accepts a VerifiedOffer produced by the SDK verify path.
	_, _ = client.Execute(ctx, res.Verified[0])

	// want-compile-error: cannot use res.Rejected[0] (variable of type
	// ramp.RejectedOffer) as ramp.VerifiedOffer value in argument to client.Execute
	_, _ = client.Execute(ctx, res.Rejected[0])

	// want-compile-error: cannot use a raw *rampv1.Offer as ramp.VerifiedOffer
	// value in argument to client.Execute
	raw := &rampv1.Offer{OfferId: "forged"}
	_, _ = client.Execute(ctx, raw)

	// want-compile-error: cannot construct a ramp.VerifiedOffer with a composite
	// literal — its wrapped field is unexported, so only the SDK verify path (or
	// the explicit RejectedOffer.Unsafe escape) can mint one.
	forged := ramp.VerifiedOffer{}
	_, _ = client.Execute(ctx, forged)
}
