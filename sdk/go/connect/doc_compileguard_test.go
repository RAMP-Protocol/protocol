//go:build compileguard_demo

// This file is DELIBERATELY excluded from the build (build tag
// `compileguard_demo`, never set in CI or `go test`). It documents the
// compile-time guard that the runtime tests in client_verify_test.go cannot
// assert directly — "does not compile" is not a runtime assertion. The snippets
// below are the // want-compile-error examples: each line is annotated with the
// compiler error it MUST produce. An app cannot forge a VerifiedOffer and cannot
// hand Execute anything but one.
//
// The guard's subject is Client.Execute — the Client lives in sdk/go/connect after
// the core/connect split, so this demo lives in package connect_test (the
// VerifiedOffer / RejectedOffer / Result types it references are in sdk/go/core).
//
// Do NOT remove the build tag: including this file in the normal build would make
// the package fail to compile for the WRONG reason (these are intentional type
// errors).

package connect_test

import (
	"context"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
)

func compileGuardDemo(client *rampconnect.Client, res core.Result) {
	ctx := context.Background()

	// OK: Execute accepts a VerifiedOffer produced by the SDK verify path.
	_, _ = client.Execute(ctx, res.Verified[0])

	// want-compile-error: cannot use res.Rejected[0] (variable of type
	// core.RejectedOffer) as core.VerifiedOffer value in argument to client.Execute
	_, _ = client.Execute(ctx, res.Rejected[0])

	// want-compile-error: cannot use a raw *rampv1.Offer as core.VerifiedOffer
	// value in argument to client.Execute
	raw := &rampv1.Offer{OfferId: "forged"}
	_, _ = client.Execute(ctx, raw)

	// want-compile-error: cannot populate a core.VerifiedOffer via a composite
	// literal — the wrapped `offer` field is unexported, so an app cannot inject its
	// own *rampv1.Offer. Only the SDK verify path (core.Verifier.Sort) or the
	// explicit RejectedOffer.Unsafe escape can mint one carrying an offer. (An empty
	// core.VerifiedOffer{} literal is legal Go but carries a nil offer, so it is
	// inert — the guard is that you cannot SET the offer from outside core.)
	forged := core.VerifiedOffer{offer: raw}
	_, _ = client.Execute(ctx, forged)
}
