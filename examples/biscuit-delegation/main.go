// Command biscuit-delegation is a runnable harness for the RAMP delegation /
// Biscuit holder-binding model. It turns the prose in
// website/.../protocol/authentication.mdx into something you can mint, edit,
// inspect, and attack.
//
// The model, end to end:
//
//   1. The PUBLISHER (principal/issuer) has an Ed25519 keypair. Its PUBLIC key
//      is what an Exchange retrieves (in RAMP, from {domain}/.well-known/ramp.json)
//      to verify any token it issued.
//   2. The AGENT (holder) has its own Ed25519 keypair. This is the key it will
//      sign HTTP requests with (RFC 9421), and the key the token is bound to.
//   3. The publisher MINTS a Biscuit: an authority block carrying the grant
//      (scopes, caps, expiry) plus a `holder(<agent-public-key>)` fact. The
//      block is signed by the publisher's private key.
//   4. The agent may ATTENUATE (append a block that only narrows — adds checks,
//      never rights). No call back to the publisher.
//   5. An Exchange AUTHORIZES: it (a) verifies the Biscuit signature chain with
//      the publisher's PUBLIC key, then (b) takes the key that signed the HTTP
//      request — which it learned by verifying the RFC 9421 signature — and
//      checks `request_key == holder`. That check is the holder binding: a
//      stolen token is useless without the agent's private signing key.
//
// Subcommands:
//
//	keygen <name>        generate an Ed25519 keypair -> <name>.key, <name>.pub
//	mint                 publisher mints a token bound to an agent pubkey
//	inspect              print a token's blocks / datalog / revocation ids
//	attenuate            agent appends a narrowing block
//	authorize            Exchange verifies chain + holder binding, allow/deny
//	demo                 run the whole scenario incl. the theft attempts
//
// Run `go run . demo` first to see it work. Then use the stateful subcommands
// (and the -datalog flags) to poke at the payload yourself.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "mint":
		err = cmdMint(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "attenuate":
		err = cmdAttenuate(os.Args[2:])
	case "authorize":
		err = cmdAuthorize(os.Args[2:])
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "jwt-demo":
		err = cmdJWTDemo(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `biscuit-delegation — RAMP Biscuit holder-binding harness

  go run . demo                              run the full Biscuit scenario + theft attempts
  go run . jwt-demo                          run the same scenario with a JWT (cnf) capability chain
  go run . keygen <name>                     write <name>.key (private) + <name>.pub
  go run . mint -root P.key -holder A.pub -out t.bc [-datalog auth.dl] [-exp DUR]
  go run . inspect -in t.bc
  go run . attenuate -in t.bc -out t2.bc [-datalog block.dl]
  go run . authorize -in t.bc -root P.pub -request-key A.pub [-authorizer pol.dl] [-op read]

Keys are hex files. Tokens are base64 files. The -datalog flags take a Datalog
file so you can edit the payload and re-run.
`)
}

// ---------------------------------------------------------------------------
// Default Datalog payloads. Override any of them with the -datalog flag.
// {holder} and {exp} are parser parameters substituted at mint time.
// ---------------------------------------------------------------------------

const defaultAuthorityDatalog = `// Authority block (block 0) — signed by the PUBLISHER's private key.
// This is the grant. It can only be narrowed by later blocks, never widened.
// what the grant permits:
right("read");
// one fact per granted scope (RAMP segment-wise scopes):
scope("quote:*");
scope("earnings:*");
// a cap (defense-in-depth, not the primary control):
max_spend_cents(50000);
// HOLDER BINDING — the load-bearing fact. The grant is bound to the agent's
// public key. The Exchange will refuse to honor the token unless the key that
// signed the HTTP request (RFC 9421) equals this one.
holder({holder});
// Expiry, enforced by the authorizer's time() fact:
check if time($t), $t <= {exp};`

const defaultAttenuationDatalog = `// Attenuation block — appended and signed by the AGENT. Adds checks only.
// Lowers the spend cap for this (sub-)delegation. The check constrains the
// REQUEST (requested_spend_cents, injected by the Exchange), not the grant —
// that is how you narrow: every later request must satisfy it. Scope narrowing
// works the same way against a requested_resource fact. No round trip to the
// publisher; the publisher's key is not involved here.
check if requested_spend_cents($s), $s <= 10000;`

// The Exchange's verification policy. request_key is injected by the Exchange
// from the verified RFC 9421 signature; time is "now". The first check is the
// HOLDER BINDING. allow if right("read") is the actual authorization decision.
const defaultAuthorizerDatalog = `// HOLDER BINDING — fails closed on mismatch:
check if holder($k), request_key($k);
allow if right("read");`

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

func cmdKeygen(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: keygen <name>")
	}
	name := args[0]
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// Store the 32-byte seed for the private key; the public key is 32 bytes.
	if err := os.WriteFile(name+".key", []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(name+".pub", []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (private, keep secret) and %s.pub\n", name, name)
	fmt.Printf("  public key: %s\n", hex.EncodeToString(pub))
	return nil
}

func loadPriv(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: expected %d-byte seed, got %d", path, ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func loadPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s: expected %d-byte public key, got %d", path, ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// pubHex accepts either a .pub file path or a raw hex string, returning the hex.
func pubHex(s string) (string, error) {
	if _, err := os.Stat(s); err == nil {
		p, err := loadPub(s)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(p), nil
	}
	if _, err := hex.DecodeString(strings.TrimSpace(s)); err != nil {
		return "", fmt.Errorf("%q is neither a file nor hex: %w", s, err)
	}
	return strings.TrimSpace(s), nil
}

// ---------------------------------------------------------------------------
// mint
// ---------------------------------------------------------------------------

func cmdMint(args []string) error {
	fs := newFlagSet("mint")
	root := fs.String("root", "", "publisher private key file (.key)")
	holder := fs.String("holder", "", "agent public key (.pub file or hex) the token binds to")
	datalogFile := fs.String("datalog", "", "authority block Datalog file (default: built-in)")
	out := fs.String("out", "token.bc", "output token file (base64)")
	expDur := fs.Duration("exp", 24*time.Hour, "validity window from now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *root == "" || *holder == "" {
		return fmt.Errorf("mint requires -root and -holder")
	}
	rootPriv, err := loadPriv(*root)
	if err != nil {
		return err
	}
	holderHex, err := pubHex(*holder)
	if err != nil {
		return err
	}
	dl := defaultAuthorityDatalog
	if *datalogFile != "" {
		b, err := os.ReadFile(*datalogFile)
		if err != nil {
			return err
		}
		dl = string(b)
	}

	params := parser.ParametersMap{
		"holder": biscuit.String(holderHex),
		"exp":    biscuit.Date(time.Now().Add(*expDur)),
	}
	parsed, err := parser.FromStringBlockWithParams(stripComments(dl), params)
	if err != nil {
		return fmt.Errorf("parsing authority Datalog: %w", err)
	}

	builder := biscuit.NewBuilder(rootPriv, biscuit.WithRandom(rand.Reader))
	if err := builder.AddBlock(parsed); err != nil {
		return fmt.Errorf("building authority block: %w", err)
	}
	tok, err := builder.Build()
	if err != nil {
		return err
	}
	if err := writeToken(*out, tok); err != nil {
		return err
	}
	fmt.Printf("minted token -> %s  (bound to holder %s…, expires in %s)\n", *out, holderHex[:16], *expDur)
	printCode(tok)
	return nil
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

func cmdInspect(args []string) error {
	fs := newFlagSet("inspect")
	in := fs.String("in", "", "token file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("inspect requires -in")
	}
	tok, err := readToken(*in)
	if err != nil {
		return err
	}
	fmt.Printf("blocks: %d (authority + %d attenuation)\n", tok.BlockCount()+1, tok.BlockCount())
	printCode(tok)
	fmt.Println("revocation ids (one per block):")
	for i, rid := range tok.RevocationIds() {
		fmt.Printf("  block %d: %s\n", i, hex.EncodeToString(rid))
	}
	return nil
}

// ---------------------------------------------------------------------------
// attenuate
// ---------------------------------------------------------------------------

func cmdAttenuate(args []string) error {
	fs := newFlagSet("attenuate")
	in := fs.String("in", "", "input token file")
	out := fs.String("out", "", "output token file")
	datalogFile := fs.String("datalog", "", "attenuation block Datalog file (default: built-in)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" {
		return fmt.Errorf("attenuate requires -in and -out")
	}
	tok, err := readToken(*in)
	if err != nil {
		return err
	}
	dl := defaultAttenuationDatalog
	if *datalogFile != "" {
		b, err := os.ReadFile(*datalogFile)
		if err != nil {
			return err
		}
		dl = string(b)
	}
	parsed, err := parser.FromStringBlock(stripComments(dl))
	if err != nil {
		return fmt.Errorf("parsing attenuation Datalog: %w", err)
	}
	bb := tok.CreateBlock()
	if err := bb.AddBlock(parsed); err != nil {
		return err
	}
	attenuated, err := tok.Append(rand.Reader, bb.Build())
	if err != nil {
		return fmt.Errorf("appending block: %w", err)
	}
	if err := writeToken(*out, attenuated); err != nil {
		return err
	}
	fmt.Printf("attenuated %s -> %s (now %d blocks)\n", *in, *out, attenuated.BlockCount())
	printCode(attenuated)
	return nil
}

// ---------------------------------------------------------------------------
// authorize — the Exchange's verification.
// ---------------------------------------------------------------------------

func cmdAuthorize(args []string) error {
	fs := newFlagSet("authorize")
	in := fs.String("in", "", "token file")
	root := fs.String("root", "", "publisher PUBLIC key (.pub file or hex)")
	requestKey := fs.String("request-key", "", "the key that signed the request, from RFC 9421 verification (.pub or hex)")
	authzFile := fs.String("authorizer", "", "authorizer Datalog file (default: built-in holder-binding policy)")
	op := fs.String("op", "read", "operation the request is attempting (for the allow policy)")
	spend := fs.Int64("spend", 2500, "requested spend in cents (checked against attenuated caps)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *root == "" || *requestKey == "" {
		return fmt.Errorf("authorize requires -in, -root and -request-key")
	}
	rootPub, err := loadPubOrHex(*root)
	if err != nil {
		return err
	}
	reqKeyHex, err := pubHex(*requestKey)
	if err != nil {
		return err
	}
	tok, err := readToken(*in)
	if err != nil {
		return err
	}

	allowed, world, err := authorize(tok, rootPub, reqKeyHex, *op, *spend, *authzFile)
	fmt.Println("---- authorizer world ----")
	fmt.Println(world)
	fmt.Println("--------------------------")
	if allowed {
		fmt.Println("RESULT: ALLOWED ✓  (chain verified AND request key == holder)")
		return nil
	}
	fmt.Printf("RESULT: DENIED ✗  (%v)\n", err)
	return nil
}

// authorize performs the two cryptographic checks an Exchange does:
//  1. verify the Biscuit signature chain against the publisher's PUBLIC key
//     (this happens inside tok.Authorizer);
//  2. enforce the holder binding + grant via Datalog: request_key == holder.
//
// reqKeyHex is the key the Exchange already authenticated via RFC 9421. It
// returns whether access is allowed, a dump of the Datalog world, and the
// denial reason if any.
func authorize(tok *biscuit.Biscuit, rootPub ed25519.PublicKey, reqKeyHex, op string, spendCents int64, authzFile string) (bool, string, error) {
	az, err := tok.Authorizer(rootPub) // (1) signature-chain verification
	if err != nil {
		return false, "", fmt.Errorf("biscuit chain verification failed: %w", err)
	}

	// Facts the Exchange injects from its own verified context.
	reqFact, err := parser.FromStringFactWithParams("request_key({k})", parser.ParametersMap{"k": biscuit.String(reqKeyHex)})
	if err != nil {
		return false, "", err
	}
	az.AddFact(reqFact)
	nowFact, err := parser.FromStringFactWithParams("time({t})", parser.ParametersMap{"t": biscuit.Date(time.Now())})
	if err != nil {
		return false, "", err
	}
	az.AddFact(nowFact)
	if op != "" {
		opFact, err := parser.FromStringFactWithParams("operation({o})", parser.ParametersMap{"o": biscuit.String(op)})
		if err != nil {
			return false, "", err
		}
		az.AddFact(opFact)
	}
	spendFact, err := parser.FromStringFactWithParams("requested_spend_cents({s})", parser.ParametersMap{"s": biscuit.Integer(spendCents)})
	if err != nil {
		return false, "", err
	}
	az.AddFact(spendFact)

	// The Exchange's verification policy (holder binding + allow).
	dl := defaultAuthorizerDatalog
	if authzFile != "" {
		b, err := os.ReadFile(authzFile)
		if err != nil {
			return false, "", err
		}
		dl = string(b)
	}
	parsedAz, err := parser.FromStringAuthorizer(stripComments(dl))
	if err != nil {
		return false, "", fmt.Errorf("parsing authorizer Datalog: %w", err)
	}
	az.AddAuthorizer(parsedAz)

	authErr := az.Authorize() // (2) runs all checks (token + authorizer) and policies
	world := az.PrintWorld()
	return authErr == nil, world, authErr
}

// ---------------------------------------------------------------------------
// demo — the whole story, including theft.
// ---------------------------------------------------------------------------

func cmdDemo(args []string) error {
	step := func(n int, s string) { fmt.Printf("\n=== %d. %s ===\n", n, s) }

	step(1, "Key pairs")
	pubPub, pubPriv := mustKey()        // PUBLISHER (principal/issuer)
	agentPub, agentPriv := mustKey()    // AGENT (holder)
	thiefPub, thiefPriv := mustKey()    // ATTACKER who steals the token bytes
	fmt.Printf("publisher pub: %s\n", short(pubPub))
	fmt.Printf("agent     pub: %s   <- the token will be bound to this\n", short(agentPub))
	fmt.Printf("thief     pub: %s\n", short(thiefPub))

	step(2, "Publisher mints the Biscuit, bound to the agent's public key")
	params := parser.ParametersMap{
		"holder": biscuit.String(hex.EncodeToString(agentPub)),
		"exp":    biscuit.Date(time.Now().Add(24 * time.Hour)),
	}
	parsed, err := parser.FromStringBlockWithParams(stripComments(defaultAuthorityDatalog), params)
	if err != nil {
		return err
	}
	builder := biscuit.NewBuilder(pubPriv, biscuit.WithRandom(rand.Reader))
	if err := builder.AddBlock(parsed); err != nil {
		return err
	}
	tok, err := builder.Build()
	if err != nil {
		return err
	}
	printCode(tok)
	serialized, _ := tok.Serialize()
	fmt.Printf("serialized token: %d bytes (this is the opaque `token` in Delegation; `token_format` says biscuit-v3)\n", len(serialized))

	step(3, "Agent attenuates (narrows to earnings, lowers the cap) — no call to the publisher")
	parsedBlock, err := parser.FromStringBlock(stripComments(defaultAttenuationDatalog))
	if err != nil {
		return err
	}
	bb := tok.CreateBlock()
	if err := bb.AddBlock(parsedBlock); err != nil {
		return err
	}
	tok, err = tok.Append(rand.Reader, bb.Build())
	if err != nil {
		return err
	}
	fmt.Printf("token now has %d blocks\n", tok.BlockCount())

	// The Exchange retrieves only the publisher's PUBLIC key to verify the token.
	rootPub := pubPub

	step(4, "Legitimate request: agent signs the HTTP request (RFC 9421) with its OWN private key")
	canonicalReq := []byte("POST /ramp/v1/ramp.v1.ExchangeService/Query\ncontent-digest: sha-256=:" +
		base64Digest([]byte(`{"uris":["quote:AAPL"]}`)) + ":")
	reqSig := ed25519.Sign(agentPriv, canonicalReq)
	authedKey, ok := verifyRFC9421(canonicalReq, reqSig, agentPub)
	fmt.Printf("RFC 9421 signature verifies with agent's key: %v\n", ok)
	allowed, _, aerr := authorize(tok, rootPub, hex.EncodeToString(authedKey), "read", 2500, "")
	report(allowed, aerr, "agent holds the matching private key, so request_key == holder")

	step(5, "Theft attempt A: thief steals the token bytes and signs with the THIEF's key")
	fmt.Println("the thief can produce a valid RFC 9421 signature — but with their own key:")
	thiefSig := ed25519.Sign(thiefPriv, canonicalReq)
	authedKeyA, okA := verifyRFC9421(canonicalReq, thiefSig, thiefPub)
	fmt.Printf("RFC 9421 signature verifies with thief's key: %v\n", okA)
	allowedA, _, aerrA := authorize(tok, rootPub, hex.EncodeToString(authedKeyA), "read", 2500, "")
	report(allowedA, aerrA, "request_key (thief) != holder (agent) -> holder-binding check fails closed")

	step(6, "Theft attempt B: thief claims to BE the agent but cannot sign as the agent")
	fmt.Println("the thief presents the agent's key id but signs with the thief's private key:")
	_, okB := verifyRFC9421(canonicalReq, thiefSig, agentPub) // verify thief's sig against agent's key
	fmt.Printf("RFC 9421 signature verifies against agent's key: %v  <- rejected before Biscuit is even consulted\n", okB)
	report(false, fmt.Errorf("RFC 9421 verification failed: forged signature"), "no valid request signature, no authenticated key")

	step(7, "Theft attempt C: thief appends holder(thief) to RE-BIND the stolen token")
	fmt.Println("the thief can append a block (Biscuit lets anyone attenuate) adding their own holder fact,")
	fmt.Println("then signs the request with the thief's key so request_key == the appended holder:")
	rebindBlock, err := parser.FromStringBlockWithParams("holder({k});",
		parser.ParametersMap{"k": biscuit.String(hex.EncodeToString(thiefPub))})
	if err != nil {
		return err
	}
	bb2 := tok.CreateBlock()
	if err := bb2.AddBlock(rebindBlock); err != nil {
		return err
	}
	rebound, err := tok.Append(rand.Reader, bb2.Build())
	if err != nil {
		return err
	}
	allowedC, _, aerrC := authorize(rebound, rootPub, hex.EncodeToString(thiefPub), "read", 2500, "")
	report(allowedC, aerrC, "holder() in an ATTENUATION block is not trusted by the authorizer check — only the\n     authority block's holder() (signed by the publisher) is. Re-binding cannot widen.")

	fmt.Print(`
Summary
-------
The token bytes are not a bearer credential. Authorization requires BOTH:
  (1) a Biscuit chain that verifies under the publisher's public key, and
  (2) an RFC 9421 request signature from the private key whose public key is the
      token's holder() fact.
A thief who copies the token has (1) but never (2). What the Exchange must
RETRIEVE: only the publisher's public key (to check the chain). What it must
COMPUTE: the request signer's key, from verifying the RFC 9421 signature. The
binding is request_key == holder.
`)
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// verifyRFC9421 stands in for the HTTP Message Signature verification an
// Exchange performs. In production the public key is resolved from the
// requester's {domain}/.well-known/ramp.json by keyid; here it is passed in.
// It returns the authenticated public key and whether the signature is valid.
func verifyRFC9421(canonicalRequest, sig []byte, claimedKey ed25519.PublicKey) (ed25519.PublicKey, bool) {
	if ed25519.Verify(claimedKey, canonicalRequest, sig) {
		return claimedKey, true
	}
	return nil, false
}

func base64Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8]) // short stand-in, content is irrelevant to the demo
}

func report(allowed bool, err error, why string) {
	if allowed {
		fmt.Printf("  -> ALLOWED ✓  (%s)\n", why)
	} else {
		fmt.Printf("  -> DENIED ✗   (%s)\n", why)
		if err != nil {
			fmt.Printf("     reason: %v\n", err)
		}
	}
}

func mustKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func short(p ed25519.PublicKey) string {
	h := hex.EncodeToString(p)
	return h[:16] + "…"
}

func loadPubOrHex(s string) (ed25519.PublicKey, error) {
	h, err := pubHex(s)
	if err != nil {
		return nil, err
	}
	raw, _ := hex.DecodeString(h)
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte public key, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// printCode prints the token's Datalog. tok.Code() only returns the appended
// (attenuation) blocks — the authority block lives separately and is only
// rendered via tok.String() — so we use String() to show the whole token.
func printCode(tok *biscuit.Biscuit) {
	fmt.Println("---- token (authority + " + fmt.Sprint(tok.BlockCount()) + " attenuation block(s)) ----")
	fmt.Println(strings.TrimSpace(tok.String()))
	fmt.Println("------------------------------------------------")
}
