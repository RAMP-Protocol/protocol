# biscuit-delegation — RAMP Biscuit holder-binding harness

A runnable model of RAMP's delegation token: mint a real Biscuit, attenuate it,
inspect its Datalog, and watch a stolen token fail. It makes concrete the
holder-binding guarantee from [`authentication.mdx`](../../website/src/content/docs/protocol/authentication.mdx)
— *"a leaked token is not bearer-usable."*

Library: [`github.com/biscuit-auth/biscuit-go/v2`](https://github.com/biscuit-auth/biscuit-go)
v2.2.0, which emits and verifies the **Biscuit v3** wire format (`version: 3`),
matching RAMP's default `token_format: "biscuit-v3"`. It's an isolated Go module
— not part of the protocol module and not built by CI.

It also includes a **JWT capability-chain** variant (`go run . jwt-demo`) that
delivers the *same* holder-binding guarantee with no Biscuit at all — to compare
the two and answer "do we actually need Biscuit?" See [JWT variant](#jwt-variant-go-run--jwt-demo).

## The model

| Role | Key | Used for |
|---|---|---|
| **Publisher** (principal/issuer) | Ed25519 | signs the authority block; its **public** key is what an Exchange retrieves (RAMP: `{domain}/.well-known/ramp.json`) to verify the token |
| **Agent** (holder) | Ed25519 | signs the HTTP request (RFC 9421); its **public** key is the token's `holder()` fact |
| **Exchange** (verifier) | — | verifies the Biscuit chain with the publisher's public key, then checks `request_key == holder` |

Two independent cryptographic facts must both hold for access:

1. **Chain validity** — the Biscuit verifies under the publisher's public key.
2. **Holder binding** — the key that signed the request (learned by verifying the
   RFC 9421 signature) equals the token's `holder()` fact.

A thief who copies the token bytes gets (1) but never (2): they don't hold the
agent's private signing key, so they cannot produce the request signature the
binding demands. The binding is enforced in Datalog as
`check if holder($k), request_key($k)` — fail-closed.

## Quick start

```sh
go run . demo      # full scenario: mint → attenuate → legitimate request → two theft attempts
```

Expected: the legitimate request is **ALLOWED**; both theft attempts are
**DENIED** (one because `request_key != holder`, one because the forged request
signature fails RFC 9421 before Biscuit is even consulted).

## Step through it yourself

```sh
go run . keygen publisher                 # -> publisher.key (private), publisher.pub
go run . keygen agent                     # -> agent.key, agent.pub
go run . keygen thief

# Publisher mints a token bound to the agent's public key:
go run . mint -root publisher.key -holder agent.pub -out token.bc

go run . inspect -in token.bc             # see the v3 token, the holder() fact, scopes, cap, expiry

# Agent narrows it (lower spend cap), no call to the publisher:
go run . attenuate -in token.bc -out token2.bc

# Exchange authorizes. request-key is the key the Exchange authenticated via RFC 9421:
go run . authorize -in token2.bc -root publisher.pub -request-key agent.pub   # ALLOWED
go run . authorize -in token2.bc -root publisher.pub -request-key thief.pub   # DENIED (binding)
go run . authorize -in token2.bc -root publisher.pub -request-key agent.pub -spend 20000  # DENIED (cap)
```

## Edit the payload

Every `-datalog` flag takes a Datalog file, so you can change the grant and
re-run. Comments (`//`, on their own line or trailing) are stripped before
parsing. Mint substitutes two parameters: `{holder}` (the `-holder` key) and
`{exp}` (now + `-exp`).

```sh
cat > authority.dl <<'EOF'
right("read");
scope("earnings:NVDA");          // a tighter grant
max_spend_cents(1000);
holder({holder});
check if time($t), $t <= {exp};
EOF
go run . mint -root publisher.key -holder agent.pub -datalog authority.dl -out custom.bc
go run . inspect -in custom.bc
```

You can likewise pass `-datalog` to `attenuate` and `-authorizer` to `authorize`
to change the narrowing block and the Exchange's verification policy.

## What maps to what in RAMP

- The serialized token bytes = `Delegation.token`; `token_format` = `"biscuit-v3"`.
- `holder()` fact = the mandatory subject/holder binding in the delegation-claims
  profile.
- `scope()` facts = `Delegation.scopes` (segment-wise matching lives in the spec).
- `max_spend_cents` / expiry = the defense-in-depth caps, secondary to the binding.
- `authorize`'s `request_key` = the output of the Exchange's RFC 9421 verification
  (here simulated with an Ed25519 sign/verify over a canonical request string).

## JWT variant (`go run . jwt-demo`)

The same delegation model, built from a chain of **`cnf` (holder-of-key) JWTs**
instead of a Biscuit — to show that for RAMP's use cases the two are equivalent
and Biscuit is optional. Library: [`golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt)
(EdDSA), the standard, ubiquitous Go JWT library.

The chain mirrors the Biscuit one (content owner → principal → agent):

```
authority JWT   signed by the OWNER; cnf.jkt = thumbprint(principal key)
   │            (the owner's public key is the only trust anchor)
   ▼
delegation JWT  signed by the PRINCIPAL; carries the principal key in its JOSE
   │            header `jwk` (so the verifier links it to the authority's cnf
   │            and verifies it); cnf.jkt = thumbprint(agent key); narrowed scope
   ▼
request         signed by the AGENT (RFC 9421); verifier checks
                thumbprint(request key) == delegation cnf.jkt
```

`jwt-demo` runs five outcomes: a legitimate request (**ALLOWED**) and four
failures (**DENIED**) — thief signs with own key (holder binding), forged request
signature (RFC 9421), thief forges a delegation (chain linkage — can't sign as the
principal), and over-delegation (scope can't widen). It prints the real JWT
header + claims so you can see `cnf.jkt` and the header `jwk`.

**Equivalence.** Every property the Biscuit demo shows holds here: offline
verification rooted in the owner's key alone (principal/agent keys arrive *inside*
the chain via header `jwk` + `cnf.jkt`), holder binding at each hop, short-TTL
delegation, scope narrowing, theft-resistance.

**What Biscuit would add (and RAMP doesn't use):** in-token Datalog (arbitrary
checks — RAMP needs only a fixed set: scope coverage, exp, cnf, optional
op/resource) and in-place "anyone-can-attenuate" for *deep* chains (RAMP's are
shallow: owner → principal → agent). The trade is **one technology instead of
two** — JWT + RFC 9421 are both already ubiquitous; Biscuit is the only genuinely
new dependency. Keeping `token_format` agnostic lets a deployment opt into Biscuit
for deep offline attenuation; JWT is the leaner default.

Chain-linkage invariant (the security keystone): each token's signer MUST be the
key the parent named — owner verifies the authority; `authority.cnf` pins the
principal; the delegation's header key must match that pin and verifies the
delegation; `delegation.cnf` pins the agent; the request key must match that pin.
Implemented in `verifyJWTChain` (`jwt.go`).
