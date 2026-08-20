// Package vectorio holds the byte semantics of a committed conformance corpus.
//
// Every emitter writes a corpus the same way and compares it the same way, and the
// bytes are the contract: a corpus is committed, so an emitter that indented
// differently or dropped the trailing newline would rewrite the whole file and
// report the change as drift. Those semantics lived in one package's test files and
// were re-inlined by the emitter in another, because Go cannot reach a _test.go
// helper across a package boundary.
//
// It deliberately takes no *testing.T and returns errors instead of failing. A
// non-test package that imports testing registers the -test.* flags on every binary
// that links it, so what is shared here is the byte handling; each emitter keeps its
// own t.Fatalf and its own wording.
package vectorio

import (
	"encoding/json"
	"os"
)

// corpusPerm is the mode a committed corpus is written with. It is a checked-in test
// fixture, not a secret.
const corpusPerm = 0o644

// Marshal renders v the way every committed corpus is written: two-space indent and
// exactly one trailing newline.
func Marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Write replaces the corpus at path with v. Used only under RAMP_UPDATE_VECTORS=1.
func Write(path string, v any) error {
	b, err := Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, corpusPerm) //nolint:gosec // committed test vector
}

// Stale reports whether the corpus committed at path differs from what v renders to.
// A corpus that cannot be read is stale rather than an error of its own: either way
// the emitter's answer is "regenerate", and the read error is returned alongside so
// the caller can say which it was.
func Stale(path string, v any) (bool, error) {
	want, err := Marshal(v)
	if err != nil {
		return true, err
	}
	got, err := os.ReadFile(path) //nolint:gosec // a path this package's callers own
	if err != nil {
		return true, err
	}
	return string(got) != string(want), nil
}
