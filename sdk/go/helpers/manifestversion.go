package helpers

import (
	"errors"
	"fmt"
	"strings"
)

// ErrManifestVersionRefused signals that a /.well-known/ramp.json document
// carries a WellKnownManifest.ver this reader does not accept: a major version
// it does not implement, a value that is not MAJOR.MINOR, or no version at all.
//
// It is a VERDICT on the document, distinct from a transport or decode failure:
// the manifest was fetched and parsed, and the reader refuses to act on any
// other member of it. A caller that classifies retryability reads this as final.
var ErrManifestVersionRefused = errors.New("helpers: well-known manifest version not accepted")

// CheckWellKnownManifestVersion applies the receive-side rule for
// WellKnownManifest.ver. It accepts a version whose MAJOR equals the major of
// WellKnownManifestVersion, whatever the MINOR — a minor revision of the manifest
// is additive by definition, so a reader ignores members it does not know and
// keeps reading. It refuses an unrecognised major, a value that is not of the form
// MAJOR.MINOR (two runs of ASCII digits joined by one dot), and the empty string,
// which is how an absent field arrives.
//
// Absent is refused rather than tolerated: the field is required by the wire
// shape, and a document with no version is one whose layout the reader cannot
// classify. Why the gate runs before any other member is read, and fails closed,
// is stated once on WellKnownManifest.ver in the proto.
//
// The returned error wraps ErrManifestVersionRefused and names the value found,
// so an operator can tell a version mismatch from a network failure. The echo is
// clipped to maxEchoedVer bytes: the document body is read up to 1 MiB and a
// refusal is never cached, so an unclipped echo would let a hostile origin size
// every error a resolve produces. The function is pure: the same input always
// yields the same verdict, and the three SDK languages pin that verdict to a
// shared corpus.
func CheckWellKnownManifestVersion(ver string) error {
	acceptMajor := majorOf(WellKnownManifestVersion)
	if ver == "" {
		return fmt.Errorf("%w: ver is absent, accept major %s", ErrManifestVersionRefused, acceptMajor)
	}
	major, ok := parseMajor(ver)
	if !ok {
		return fmt.Errorf("%w: ver %q is not MAJOR.MINOR, accept major %s", ErrManifestVersionRefused, echoVer(ver), acceptMajor)
	}
	if major != acceptMajor {
		return fmt.Errorf("%w: ver %q has major %s, accept major %s", ErrManifestVersionRefused, echoVer(ver), major, acceptMajor)
	}
	return nil
}

// maxEchoedVer bounds how much of a refused `ver` the error message repeats. A
// real version is a few bytes; anything longer is only ever going to be shown.
const maxEchoedVer = 64

// echoVer is ver clipped for an error message. Python and TS clip at the same
// length, so an operator reading three SDKs' logs sees the same prefix.
func echoVer(ver string) string {
	if len(ver) <= maxEchoedVer {
		return ver
	}
	return ver[:maxEchoedVer] + "..."
}

// majorOf is parseMajor over a value this package owns, so a malformed constant
// is a programming error rather than a runtime verdict.
func majorOf(ver string) string {
	major, ok := parseMajor(ver)
	if !ok {
		panic("helpers: WellKnownManifestVersion is not MAJOR.MINOR: " + ver)
	}
	return major
}

// parseMajor returns the MAJOR run of a MAJOR.MINOR string. Both runs must be
// non-empty ASCII digits and exactly one dot may separate them; anything else —
// a missing minor, a patch component, a leading "v", surrounding whitespace, a
// non-digit — is not a version this rule recognises.
func parseMajor(ver string) (string, bool) {
	major, minor, found := strings.Cut(ver, ".")
	if !found || !allASCIIDigits(major) || !allASCIIDigits(minor) {
		return "", false
	}
	return major, true
}

func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
