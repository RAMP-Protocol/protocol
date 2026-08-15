// Package core — requestid_test.go pins the one property the request-id
// middleware exists to guarantee: whatever it settles on, the value can be
// persisted as ramp.admin.v1.RequestCorrelation.request_id.
//
// WHY THAT MATTERS MORE THAN IT LOOKS. request_id sits inside a REQUIRED message
// inside a REQUIRED field of GetTransactionEvidenceResponse. A stored value
// outside `^[!-~]+$` does not degrade that response, it invalidates the whole of
// it — so a caller who gets a hostile header persisted permanently breaks the
// forensic row for their own transaction, with one HTTP header and no other
// access. These tests are the guard that keeps that unreachable through this
// middleware; before them the header was propagated verbatim.
package core_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/core"
)

// hostileHeaders are the shapes the wire rule refuses. Each is a real way a
// correlation id goes wrong rather than a random invalid string: control
// characters and terminal escapes matter because a ledger RENDERS this value,
// newlines because a log pipeline splits on them, and the oversize case because
// the rule's ceiling is the reason the field cannot hold an arbitrary blob.
var hostileHeaders = map[string]string{
	"newline":          "abc\ndef",
	"carriage return":  "abc\rdef",
	"nul":              "abc\x00def",
	"terminal escape":  "\x1b[2Jwiped",
	"tab":              "abc\tdef",
	"space":            "two words",
	"non-ascii":        "café",
	"del":              "abc\x7f",
	"over 255 chars":   strings.Repeat("a", 256),
	"empty after trim": " ",
}

// echoRequestID reports what the middleware put in the context, so a test sees
// the value a handler would actually persist rather than only the response
// header.
func echoRequestID(t *testing.T) (http.Handler, *core.RequestID) {
	t.Helper()
	var seen core.RequestID
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := core.RequestIDFromContext(r.Context())
		if !ok {
			t.Error("handler saw no request id in context — RequestIDMiddleware must always place one")
			return
		}
		seen = id
	})
	return h, &seen
}

func TestMiddlewareReplacesNonconformingHeader(t *testing.T) {
	for name, hostile := range hostileHeaders {
		t.Run(name, func(t *testing.T) {
			next, seen := echoRequestID(t)
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set(core.RequestIDHeader, hostile)
			rec := httptest.NewRecorder()

			core.RequestIDMiddleware(nil, next).ServeHTTP(rec, req)

			if seen.Value == hostile {
				t.Fatalf("middleware propagated a nonconforming header %q — the admin plane cannot persist it", hostile)
			}
			if !core.ValidRequestID(seen.Value) {
				t.Fatalf("middleware settled on %q, which is itself nonconforming", seen.Value)
			}
			if !seen.Derived {
				t.Error("a replaced header must be reported as server-derived, or an evidence writer records it as caller-supplied")
			}
			if got := rec.Header().Get(core.RequestIDHeader); got != seen.Value {
				t.Errorf("response header %q disagrees with the id the handler saw %q", got, seen.Value)
			}
		})
	}
}

func TestMiddlewarePropagatesConformingHeader(t *testing.T) {
	// The counterpart that keeps the guard honest: a legitimate caller-supplied
	// id must survive verbatim and must NOT be reported as server-derived. A
	// middleware that replaced everything would pass the test above and be
	// useless.
	for name, id := range map[string]string{
		"hex token":       "0123456789abcdef0123456789abcdef",
		"uuid":            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"braced uuid":     "{3f2504e0-4f89-11d3-9a0c-0305e82c3301}",
		"trace id":        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"single char":     "x",
		"exactly 255":     strings.Repeat("a", 255),
		"punctuation mix": "req:1/2?a=b#c",
	} {
		t.Run(name, func(t *testing.T) {
			next, seen := echoRequestID(t)
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set(core.RequestIDHeader, id)

			core.RequestIDMiddleware(nil, next).ServeHTTP(httptest.NewRecorder(), req)

			if seen.Value != id {
				t.Errorf("conforming header %q was rewritten to %q", id, seen.Value)
			}
			if seen.Derived {
				t.Error("a propagated caller value must not be reported as server-derived — the flag is what marks it attacker-influenceable")
			}
		})
	}
}

func TestMiddlewareMintsWhenHeaderAbsent(t *testing.T) {
	next, seen := echoRequestID(t)
	core.RequestIDMiddleware(nil, next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))

	if !core.ValidRequestID(seen.Value) {
		t.Fatalf("minted id %q does not conform", seen.Value)
	}
	if !seen.Derived {
		t.Error("an absent header must yield a server-derived id")
	}
}

func TestMiddlewareRejectsAHostileCustomMint(t *testing.T) {
	// The trusted side is a real source of bad values: an application injects
	// its own mint through WithRequestIDFunc, usually to reuse a trace id, and a
	// trace id can carry anything. Without this fallback the middleware would
	// refuse a caller's newline and then insert its own.
	for name, bad := range map[string]string{
		"empty":     "",
		"newline":   "trace\nid",
		"oversize":  strings.Repeat("z", 300),
		"non-ascii": "trace-id-ü",
	} {
		t.Run(name, func(t *testing.T) {
			next, seen := echoRequestID(t)
			mint := func() string { return bad }

			core.RequestIDMiddleware(mint, next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))

			if seen.Value == bad {
				t.Fatalf("middleware used a nonconforming minted value %q", bad)
			}
			if !core.ValidRequestID(seen.Value) {
				t.Fatalf("fallback produced %q, which is itself nonconforming", seen.Value)
			}
			if !seen.Derived {
				t.Error("a minted id is server-derived by definition")
			}
		})
	}
}

func TestDefaultRequestIDConforms(t *testing.T) {
	// resolveRequestID's last resort. If this ever stopped conforming, every
	// other guarantee here would fall back to a value the admin plane rejects.
	for i := 0; i < 64; i++ {
		if id := core.DefaultRequestID(); !core.ValidRequestID(id) {
			t.Fatalf("DefaultRequestID produced %q, which the wire rule refuses", id)
		}
	}
}

func TestValidRequestIDBoundaries(t *testing.T) {
	// The rule is `^[!-~]+$`, so the boundary characters are 0x21 and 0x7e, with
	// 0x20 (space) and 0x7f (DEL) immediately outside. Pinning the edges catches
	// an off-by-one in the comparison that no realistic sample string would.
	for _, c := range []struct {
		name  string
		s     string
		valid bool
	}{
		{"0x20 space below range", "\x20", false},
		{"0x21 bang, first in range", "\x21", true},
		{"0x7e tilde, last in range", "\x7e", true},
		{"0x7f del above range", "\x7f", false},
		{"empty", "", false},
		{"255 chars", strings.Repeat("a", 255), true},
		{"256 chars", strings.Repeat("a", 256), false},
	} {
		if got := core.ValidRequestID(c.s); got != c.valid {
			t.Errorf("%s: ValidRequestID(%q) = %v, want %v", c.name, c.s, got, c.valid)
		}
	}
}
