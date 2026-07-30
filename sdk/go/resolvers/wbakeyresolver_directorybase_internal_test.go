package resolvers

// directoryBase normalizes the Signature-Agent value into the origin whose WBA
// directory gets fetched, so it is where "what counts as a key directory" is
// decided. These tests pin the two properties that matter: the bare host:port
// form compose stacks use keeps working, and an opaque URI is refused by name.
//
// The data: scheme is the one the WBA directory draft permits and RAMP declines.
// It inlines an entire key directory into the header, and key resolution here
// rests on fetching the directory from a location the signer had to control — a
// signer that supplies its own directory is asserting its own keys.

import (
	"strings"
	"testing"
)

func TestDirectoryBase_acceptsFetchableForms(t *testing.T) {
	r := &WBAKeyResolver{scheme: "https"}
	for _, tc := range []struct {
		name     string
		ref      string
		wantBase string
		wantHost string
	}{
		{"full origin", "https://agent.example", "https://agent.example", "agent.example"},
		{"bare host", "agent.example", "https://agent.example", "agent.example"},
		{"bare host:port (compose)", "identity:8080", "https://identity:8080", "identity:8080"},
		{"full origin with port", "http://identity:8080", "http://identity:8080", "identity:8080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, host, err := r.directoryBase(tc.ref)
			if err != nil {
				t.Fatalf("directoryBase(%q): unexpected error %v", tc.ref, err)
			}
			if base != tc.wantBase || host != tc.wantHost {
				t.Errorf("directoryBase(%q) = (%q, %q); want (%q, %q)",
					tc.ref, base, host, tc.wantBase, tc.wantHost)
			}
		})
	}
}

// TestDirectoryBase_refusesInlineDirectory pins the refusal AND its diagnosis.
// Before the guard the value was concatenated into "https://data:application/…"
// and died as `invalid port ":application" after host`, which reads as a
// malformed-host bug rather than the policy decision it is. An operator reading
// the log needs to see that the directory was declined, not mis-parsed.
func TestDirectoryBase_refusesInlineDirectory(t *testing.T) {
	r := &WBAKeyResolver{scheme: "https"}
	const inline = `data:application/http-message-signatures-directory;utf8,{"keys":[]}`

	_, _, err := r.directoryBase(inline)
	if err == nil {
		t.Fatal("directoryBase accepted an inline data: directory; a signer must not supply its own keys")
	}
	if !strings.Contains(err.Error(), "inline") || !strings.Contains(err.Error(), "data") {
		t.Errorf("error %q names neither the inline payload nor its scheme; an operator cannot tell this from a malformed host", err)
	}
}

// TestRefuseOpaqueURI_portVsOpaque covers the discrimination the guard rests on.
// "identity:8080" and "data:x" are the same shape to url.Parse — both come back
// as scheme:opaque — so the digits-only test on what follows the colon is the only
// thing separating a compose host from an inline payload. Get it wrong in either
// direction and we either break compose stacks or admit inline directories.
func TestRefuseOpaqueURI_portVsOpaque(t *testing.T) {
	for _, tc := range []struct {
		ref       string
		wantError bool
	}{
		{"identity:8080", false},         // host:port
		{"agent.example", false},         // no colon at all
		{"https://agent.example", false}, // has an authority, guard not consulted
		{"data:application/json,{}", true},
		{"data:", false}, // no opaque part; fails the host check later
		{"mailto:ops@example.com", true},
		{"identity:99999999", true}, // not a 16-bit port, so not a host:port
	} {
		t.Run(tc.ref, func(t *testing.T) {
			err := refuseOpaqueURI(tc.ref)
			if tc.wantError && err == nil {
				t.Errorf("refuseOpaqueURI(%q) = nil; want a refusal", tc.ref)
			}
			if !tc.wantError && err != nil {
				t.Errorf("refuseOpaqueURI(%q) = %v; want nil", tc.ref, err)
			}
		})
	}
}
