package resolvers

// directoryBase turns the Signature-Agent value into the origin whose WBA
// directory gets fetched, so it is where "what counts as a key directory" is
// decided. Two properties are pinned here:
//
//   - every form a real deployment addresses a directory by keeps working,
//     including the bare host:port compose stacks use and a path after the port;
//   - a directory that cannot be FETCHED is refused, whichever syntax it arrives
//     in — an authority form (data://x) and an opaque one (data:{…}) must reach
//     the same verdict, or a composite resolver reads one of them as "directory
//     down" instead of "not a directory".
//
// The data: scheme is the one the WBA directory draft permits and RAMP declines:
// it inlines the whole key directory, and key resolution rests on fetching it
// from a location the signer had to control.

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
		// A path after the port is a legal bare reference. Only the text before the
		// first "/" can be a port, and reading the whole opaque part as one refused
		// this form outright.
		{"bare host:port with path", "identity:8080/dir", "https://identity:8080", "identity:8080"},
		{"bare host with path", "agent.example/dir", "https://agent.example", "agent.example"},
		// A lone trailing slash was enough to break this form once: the whole
		// opaque part was read as the port, so "8443/" failed the digits test.
		{"bare host:port with a bare trailing slash", "agent.example:8443/", "https://agent.example:8443", "agent.example:8443"},
		{"bare host:port with query", "agent.example:8443?x=1", "https://agent.example:8443", "agent.example:8443"},
		{"bare host:port with fragment", "agent.example:8443#f", "https://agent.example:8443", "agent.example:8443"},
		// IPv6 survives the host re-assembly check: Hostname() drops the brackets
		// that Host carries, so the check has to put them back.
		{"bracketed IPv6 with port", "[::1]:8080", "https://[::1]:8080", "[::1]:8080"},
		{"full origin, bracketed IPv6", "https://[::1]:8080", "https://[::1]:8080", "[::1]:8080"},
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

// TestDirectoryBase_refusesUnfetchable pins the refusals AND their diagnosis. The
// wording is asserted on the policy phrase, not on the scheme name: the reference
// is echoed into the message by %q, so checking for "data" alone would pass on the
// echoed input even if the refusal never fired.
func TestDirectoryBase_refusesUnfetchable(t *testing.T) {
	r := &WBAKeyResolver{scheme: "https"}
	for _, tc := range []struct {
		name        string
		ref         string
		wantPhrase  string
		wantMissing string // must NOT appear: guards against the wrong branch firing
	}{
		{
			name:       "inline data: directory, opaque form",
			ref:        `data:application/http-message-signatures-directory;utf8,{"keys":[]}`,
			wantPhrase: "inline",
		},
		{
			// Same policy, authority syntax. Before the scheme check this passed
			// directoryBase and died later at the HTTP client as a transport error.
			name:       "data: with an authority",
			ref:        "data://agent.example",
			wantPhrase: "not fetchable",
		},
		{"ftp", "ftp://agent.example", "not fetchable", ""},
		{"websocket", "wss://agent.example", "not fetchable", ""},
		{
			// Digits that cannot be a port are a bad port, not an inline payload.
			// Calling this "inline" would be the same misdiagnosis the guard exists
			// to end, pointed the other way.
			name:        "port out of range",
			ref:         "identity:99999999",
			wantPhrase:  "out of range",
			wantMissing: "inline",
		},
		// The shapes below all PARSE. url.Parse carries a dangling colon or plain
		// junk through as a Host rather than failing, and that Host becomes the
		// directory cache key and the Host header of every later fetch — so
		// "non-empty" is not a sufficient test of a host.
		{
			name:       "opaque URI with no payload",
			ref:        "data:",
			wantPhrase: "not a host",
		},
		{
			name:       "opaque URI with only a fragment",
			ref:        "data:#x",
			wantPhrase: "not a host",
		},
		{
			// The sf-dictionary form RAMP does not read. Quotes and equals signs
			// are not host characters, so it cannot be mistaken for one.
			name:       "sf-dictionary form is not a host",
			ref:        `agent2="a.example"`,
			wantPhrase: "not a host",
		},
		{
			// The draft's own §A.4 shape: a dictionary holding a data: value. It
			// does not parse at all, and used to surface url.Parse complaining
			// about a port nobody wrote.
			name:        "dictionary holding a data: value",
			ref:         `agent2="data:application/http-message-signatures-directory;utf8,{}"`,
			wantPhrase:  "is not a directory reference",
			wantMissing: "inline",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := r.directoryBase(tc.ref)
			if err == nil {
				t.Fatalf("directoryBase(%q) accepted an unfetchable directory", tc.ref)
			}
			if !strings.Contains(err.Error(), tc.wantPhrase) {
				t.Errorf("error %q does not contain %q — an operator cannot tell this from a malformed host",
					err, tc.wantPhrase)
			}
			if tc.wantMissing != "" && strings.Contains(err.Error(), tc.wantMissing) {
				t.Errorf("error %q contains %q; the wrong refusal branch fired", err, tc.wantMissing)
			}
		})
	}
}

// TestRequireHostForm_portVsOpaque covers the discrimination the guard rests on.
// "identity:8080" and "data:x" are the same shape to url.Parse — both come back as
// scheme:opaque — so the test on the text before the first "/" is the only thing
// separating a compose host from an inline payload. Too strict breaks compose
// stacks; too loose admits inline directories.
func TestRequireHostForm_portVsOpaque(t *testing.T) {
	for _, tc := range []struct {
		ref       string
		wantError bool
	}{
		{"identity:8080", false},         // host:port
		{"identity:8080/dir", false},     // host:port + path
		{"agent.example", false},         // no colon at all
		{"https://agent.example", false}, // has an authority, guard not consulted
		{"data:application/json,{}", true},
		{"mailto:ops@example.com", true},
		{"identity:99999999", true}, // digits, but not a 16-bit port
		// No opaque part at all. This does NOT fail here — it is prefixed into
		// "https://data:" and stops at the fetch. Recorded so the guard's actual
		// reach is not overstated.
		{"data:", false},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			err := requireHostForm(tc.ref)
			if tc.wantError && err == nil {
				t.Errorf("requireHostForm(%q) = nil; want a refusal", tc.ref)
			}
			if !tc.wantError && err != nil {
				t.Errorf("requireHostForm(%q) = %v; want nil", tc.ref, err)
			}
		})
	}
}

// TestRequireHostForm_errorOmitsRef pins that the guard does not echo the
// reference. Resolve already wraps its error with the value, and having both
// produced a message that named it twice.
func TestRequireHostForm_errorOmitsRef(t *testing.T) {
	const ref = "data:application/json,{}"
	err := requireHostForm(ref)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), ref) {
		t.Errorf("error %q echoes the reference; the caller in Resolve already does", err)
	}
}
