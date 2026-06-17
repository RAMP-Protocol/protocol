package main

// JWT capability-chain variant of the delegation model — the same holder-binding
// guarantee as the Biscuit demo, built from a chain of `cnf` (holder-of-key)
// JWTs instead of a Biscuit. It shows that for RAMP's use cases a stack of
// signed JWTs is functionally equivalent: offline-verifiable, rooted in the
// content owner's key alone, holder-bound at every hop, theft-resistant.
//
// The chain (content owner -> principal -> agent):
//
//   authority JWT   signed by the OWNER, names the PRINCIPAL's key in `cnf.jkt`
//        |          (the owner's public key is the only trust anchor)
//        v
//   delegation JWT  signed by the PRINCIPAL, carries the principal's public key
//        |          in its JOSE header `jwk` (so the verifier can both check it
//        |          against the authority's cnf AND verify this token), and
//        |          names the AGENT's key in `cnf.jkt`. Narrows scope, short TTL.
//        v
//   request         signed by the AGENT (RFC 9421). The verifier checks
//                   thumbprint(request key) == delegation `cnf.jkt`.
//
// Chain-linkage invariant (ADR-016 D4): each token's signer MUST be the key the
// parent named. owner verifies authority; authority.cnf pins principal; the
// delegation's header key must match that pin and verifies the delegation;
// delegation.cnf pins the agent; the request key must match that pin.
//
// Verifier inputs: ONLY the owner's public key. Principal and agent public keys
// arrive inside the chain. No JWKS fetch, no callback — pure offline compute.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// capClaims is the RAMP capability claim set carried by each JWT in the chain.
type capClaims struct {
	Scope string  `json:"scope"`        // space-delimited granted scopes
	Cnf   confKey `json:"cnf"`          // RFC 7800 confirmation — the NEXT holder
	jwt.RegisteredClaims                // iss, exp, iat, ...
}

// confKey is the RFC 7800 `cnf` claim using a JWK SHA-256 thumbprint (`jkt`),
// the same confirmation method DPoP uses.
type confKey struct {
	Jkt string `json:"jkt"`
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key: SHA-256
// over the canonical JWK with members in lexicographic order (crv, kty, x),
// base64url-no-pad. Identical to ADR-013's agent_identity_hash.
func thumbprint(pub ed25519.PublicKey) string {
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + b64url(pub) + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return b64url(sum[:])
}

// jwkHeader is the public key embedded in a child token's JOSE header so the
// verifier can recover the signer's key and check it against the parent's cnf.
func jwkHeader(pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64url(pub)}
}

func pubFromJWKHeader(h any) (ed25519.PublicKey, error) {
	m, ok := h.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no jwk in header")
	}
	x, ok := m["x"].(string)
	if !ok {
		return nil, fmt.Errorf("jwk has no x")
	}
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad jwk x")
	}
	return ed25519.PublicKey(raw), nil
}

// mintAuthority — the OWNER grants scopes to the PRINCIPAL (bound by cnf.jkt).
func mintAuthority(ownerPriv ed25519.PrivateKey, principalPub ed25519.PublicKey, scope string, ttl time.Duration) (string, error) {
	claims := capClaims{
		Scope: scope,
		Cnf:   confKey{Jkt: thumbprint(principalPub)},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "owner",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(ownerPriv)
}

// mintDelegation — the PRINCIPAL delegates to the AGENT (bound by cnf.jkt),
// narrowing scope and shortening TTL. The principal's public key rides in the
// JOSE header so the verifier can link it to the authority's cnf.
func mintDelegation(principalPriv ed25519.PrivateKey, principalPub, agentPub ed25519.PublicKey, scope string, ttl time.Duration) (string, error) {
	claims := capClaims{
		Scope: scope,
		Cnf:   confKey{Jkt: thumbprint(agentPub)},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "principal",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["jwk"] = jwkHeader(principalPub)
	return tok.SignedString(principalPriv)
}

// verifyJWTChain runs the whole offline verification an edge/Exchange performs.
// Inputs: the owner's public key (the only trust anchor), the two tokens, and
// the key that signed the request (from RFC 9421 verification). Returns the
// effective scopes and a denial error.
func verifyJWTChain(ownerPub ed25519.PublicKey, authorityJWT, delegationJWT string, requestKey ed25519.PublicKey) (string, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))

	// 1. Authority — verified with the OWNER's known key (the trust root).
	authClaims := &capClaims{}
	if _, err := parser.ParseWithClaims(authorityJWT, authClaims, func(*jwt.Token) (any, error) {
		return ownerPub, nil
	}); err != nil {
		return "", fmt.Errorf("authority token invalid: %w", err)
	}

	// 2. Delegation — verified with the key in its OWN header, but only after
	//    that key is pinned by the authority's cnf (chain-linkage invariant).
	delClaims := &capClaims{}
	if _, err := parser.ParseWithClaims(delegationJWT, delClaims, func(t *jwt.Token) (any, error) {
		signer, err := pubFromJWKHeader(t.Header["jwk"])
		if err != nil {
			return nil, err
		}
		if thumbprint(signer) != authClaims.Cnf.Jkt {
			return nil, fmt.Errorf("delegation signer is not the key the authority delegated to (chain broken)")
		}
		return signer, nil
	}); err != nil {
		return "", fmt.Errorf("delegation token invalid: %w", err)
	}

	// 3. Attenuation: delegated scopes must be covered by the authority grant.
	if !scopesCovered(authClaims.Scope, delClaims.Scope) {
		return "", fmt.Errorf("delegation widens scope beyond the grant (%q ⊄ %q)", delClaims.Scope, authClaims.Scope)
	}

	// 4. Holder binding: the request key MUST be the agent the delegation named.
	if thumbprint(requestKey) != delClaims.Cnf.Jkt {
		return "", fmt.Errorf("request key != delegation holder (cnf.jkt) — holder binding fails")
	}

	return delClaims.Scope, nil
}

// scopesCovered reports whether every scope in `want` is covered by some scope
// in `have`, using the RAMP M9 segment-wise rule (terminal "*" matches the rest).
func scopesCovered(have, want string) bool {
	granted := strings.Fields(have)
	for _, w := range strings.Fields(want) {
		ok := false
		for _, g := range granted {
			if scopeCovers(g, w) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func scopeCovers(g, r string) bool {
	gs, rs := strings.Split(g, ":"), strings.Split(r, ":")
	for i, seg := range gs {
		if seg == "*" {
			return true // terminal "*" matches all remaining segments
		}
		if i >= len(rs) || seg != rs[i] {
			return false
		}
	}
	return len(gs) == len(rs)
}

// prettyJWT decodes (does not verify) a JWT and prints its header + claims.
func prettyJWT(label, token string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Println(label, "(unparseable)")
		return
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pl, _ := base64.RawURLEncoding.DecodeString(parts[1])
	fmt.Printf("%s (%d bytes)\n", label, len(token))
	fmt.Printf("  header: %s\n", compactJSON(hdr))
	fmt.Printf("  claims: %s\n", compactJSON(pl))
}

func compactJSON(b []byte) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// cmdJWTDemo runs the full JWT capability-chain scenario, mirroring `demo`.
func cmdJWTDemo([]string) error {
	step := func(n int, s string) { fmt.Printf("\n=== %d. %s ===\n", n, s) }

	step(1, "Key pairs (same three roles as the Biscuit demo)")
	ownerPub, ownerPriv := mustKey()         // content owner / distributor (issuer, trust root)
	principalPub, principalPriv := mustKey() // principal (the licensee org)
	agentPub, agentPriv := mustKey()         // agent (the platform/bot that makes requests)
	thiefPub, thiefPriv := mustKey()         // attacker
	fmt.Printf("owner     pub: %s   <- the ONLY key the verifier needs\n", short(ownerPub))
	fmt.Printf("principal pub: %s   (thumbprint pinned by the authority's cnf)\n", short(principalPub))
	fmt.Printf("agent     pub: %s   (thumbprint pinned by the delegation's cnf)\n", short(agentPub))
	fmt.Printf("thief     pub: %s\n", short(thiefPub))

	step(2, "Owner mints the AUTHORITY JWT, bound to the principal's key (cnf.jkt)")
	authorityJWT, err := mintAuthority(ownerPriv, principalPub, "quote:* earnings:*", 24*time.Hour)
	if err != nil {
		return err
	}
	prettyJWT("authority", authorityJWT)

	step(3, "Principal delegates to the AGENT: narrower scope, short TTL, bound to the agent's key")
	delegationJWT, err := mintDelegation(principalPriv, principalPub, agentPub, "earnings:*", 10*time.Minute)
	if err != nil {
		return err
	}
	prettyJWT("delegation", delegationJWT)
	fmt.Println("note: the delegation carries the principal's pubkey in its header `jwk`,")
	fmt.Println("      so the verifier links it to the authority's cnf and verifies it offline.")

	step(4, "Legitimate request: the agent signs the request (RFC 9421) with its OWN key")
	canonicalReq := []byte("POST /ramp/v1/ramp.v1.ExchangeService/Query\ncontent-digest: sha-256=:" +
		base64Digest([]byte(`{"uris":["earnings:NVDA"]}`)) + ":")
	reqSig := ed25519.Sign(agentPriv, canonicalReq)
	authedKey, ok := verifyRFC9421(canonicalReq, reqSig, agentPub)
	fmt.Printf("RFC 9421 signature verifies with agent's key: %v\n", ok)
	scope, aerr := verifyJWTChain(ownerPub, authorityJWT, delegationJWT, authedKey)
	reportJWT(aerr == nil, aerr, fmt.Sprintf("chain links owner->principal->agent and request key == holder; effective scope %q", scope))

	step(5, "Theft attempt A: thief steals BOTH tokens and signs the request with the thief's key")
	thiefSig := ed25519.Sign(thiefPriv, canonicalReq)
	authedA, okA := verifyRFC9421(canonicalReq, thiefSig, thiefPub)
	fmt.Printf("RFC 9421 signature verifies with thief's key: %v\n", okA)
	_, aerrA := verifyJWTChain(ownerPub, authorityJWT, delegationJWT, authedA)
	reportJWT(aerrA == nil, aerrA, "request key (thief) != delegation cnf (agent) -> holder binding fails")

	step(6, "Theft attempt B: thief claims to be the agent but cannot sign as the agent")
	_, okB := verifyRFC9421(canonicalReq, thiefSig, agentPub) // thief's sig vs agent's key
	fmt.Printf("RFC 9421 signature verifies against agent's key: %v  <- rejected before the chain is checked\n", okB)
	reportJWT(false, fmt.Errorf("RFC 9421 verification failed: forged signature"), "no valid request signature, no authenticated key")

	step(7, "Theft attempt C: thief mints its OWN delegation naming itself as the holder")
	fmt.Println("the thief forges a delegation (cnf = thief) and signs the request with the thief's key:")
	forgedDelegation, err := mintDelegation(thiefPriv, thiefPub, thiefPub, "earnings:*", 10*time.Minute)
	if err != nil {
		return err
	}
	_, aerrC := verifyJWTChain(ownerPub, authorityJWT, forgedDelegation, thiefPub)
	reportJWT(aerrC == nil, aerrC, "the forged delegation is signed by the thief's key, not the principal's —\n     its thumbprint != the authority's cnf, so the chain link is rejected")

	step(8, "Over-delegation: principal tries to grant a scope it was never given")
	overJWT, err := mintDelegation(principalPriv, principalPub, agentPub, "quote:* admin:*", 10*time.Minute)
	if err != nil {
		return err
	}
	_, aerrD := verifyJWTChain(ownerPub, authorityJWT, overJWT, agentPub)
	reportJWT(aerrD == nil, aerrD, "delegation cannot widen beyond the authority grant (admin:* was never granted)")

	fmt.Print(`
Summary
-------
Same guarantee as the Biscuit demo, built only from JWTs:
  (1) the chain verifies offline under the OWNER's key alone — principal and
      agent keys arrive inside the chain (header jwk + cnf.jkt);
  (2) access requires an RFC 9421 request signature from the private key whose
      thumbprint is the delegation's cnf.jkt (holder-of-key, RFC 7800/DPoP).
A thief who copies the tokens has (1) but never (2), and cannot forge a
delegation (no principal key) or widen scope. One technology instead of two:
JWT + RFC 9421, both already ubiquitous.
`)
	return nil
}

func reportJWT(allowed bool, err error, why string) {
	if allowed {
		fmt.Printf("  -> ALLOWED ✓  (%s)\n", why)
	} else {
		fmt.Printf("  -> DENIED ✗   (%s)\n", why)
		if err != nil {
			fmt.Printf("     reason: %v\n", err)
		}
	}
}
