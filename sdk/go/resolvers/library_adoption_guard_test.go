package resolvers_test

// Structural guard (moved from sdk/go/helpers with the fetching resolvers): the
// JWKS decode path must use go-jose's jose.JSONWebKeySet, not a hand-rolled
// OKP/Ed25519 match + raw base64url decode of the JWK `x` member. The well-known
// key face lives in wellknownkeyresolver.go (ed25519KeysFromJWKS) and the shared
// wellKnownDoc.Keys struct in endpointresolver.go, both in this L2 package.

import (
	"os"
	"strings"
	"testing"
)

func readResolverSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestLibraryAdoptionGuard_KeyResolverUsesGoJoseJWKS(t *testing.T) {
	// The JWKS decode must go through go-jose, not a hand-rolled kty match / x decode.
	jwksSrc := readResolverSource(t, "wellknownkeyresolver.go")
	for _, forbidden := range []string{
		`strings.EqualFold(k.Kty, "OKP")`,         // manual kty match
		"base64.RawURLEncoding.DecodeString(k.X)", // manual JWK x decode
	} {
		if strings.Contains(jwksSrc, forbidden) {
			t.Errorf("wellknownkeyresolver.go still contains hand-rolled disease %q; decode via jose.JSONWebKeySet", forbidden)
		}
	}
	if !strings.Contains(jwksSrc, "jose.JSONWebKeySet") {
		t.Error("wellknownkeyresolver.go is missing the vetted-library replacement \"jose.JSONWebKeySet\"; the hand-rolled path was not upgraded")
	}

	// The hand-rolled JWK struct the key face decodes lives in the shared
	// wellKnownDoc.Keys in endpointresolver.go — it must keep only the scalar
	// manifest members (Ver, Endpoint) and promote the go-jose key set.
	epSrc := readResolverSource(t, "endpointresolver.go")
	for _, forbidden := range []string{
		"Kty string `json:\"kty\"`",
		"Crv string `json:\"crv\"`",
		"X   string `json:\"x\"`",
	} {
		if strings.Contains(epSrc, forbidden) {
			t.Errorf("endpointresolver.go still declares the hand-rolled JWK struct field %q; "+
				"the key face must decode via go-jose jose.JSONWebKeySet, keeping only the scalar manifest members", forbidden)
		}
	}
}
