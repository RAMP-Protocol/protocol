package connectserver

import (
	"log/slog"
	"net/http"
	"time"

	connectrpc "connectrpc.com/connect"

	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// replayTTL is the default window a nonce is remembered when the app does not set
// one. It matches the RAMP RFC 9421 replay-window target (5 minutes); the app
// overrides it via WithReplayTTL, and owns the store itself.
const replayTTL = 5 * time.Minute

// DefaultMaxRequestBytes caps what a handler will read from one request. Connect
// treats an unset cap as "any size" and decompresses every request, so without one
// a caller can spend the server's memory and CPU at a ratio it chooses: a gzip
// body inflates roughly a thousandfold, and the wire rules do NOT bound that work
// — protovalidate walks every element it is handed and collects every violation
// before any cardinality rule is reported, so an over-cap list is fully traversed
// on its way to being refused. This is the bound that models that cost, which is
// why it lives here and not on the fields.
//
// 4 MiB is chosen against both ends, measured. A FULL-CARDINALITY push — 256
// entries each carrying the full 32 terms, every field at a realistic length — is
// 0.31 MiB and validates in ~150ms, so a real catalog batch fits with better than
// tenfold headroom. The worst ADVERSARIAL shape that still fits under this cap
// costs ~1.6s of validation. That is the number this constant buys: not a small
// cost, but a BOUNDED one, where an uncapped handler has no worst case at all —
// the same shape at 22 MiB costs ~8s, and nothing stops it growing.
//
// Note what that figure is and is not. It sizes a representative batch, NOT a
// ceiling on a conformant one: the caps in the contract bound how MANY entries,
// terms and attestations a push may carry, never how many bytes. Obligation.detail,
// the License strings and every ResourceAttestation member are length-free, so a
// conformant push can be arbitrarily large and this cap can refuse one. That is the
// intended trade — the bound models the cost of CHECKING a submission, and a
// deployment that must accept larger documents raises it.
//
// Lower it if the deployment does not accept a 256-entry batch; raising it raises
// the worst case roughly linearly. Override per server with WithMaxRequestBytes.
const DefaultMaxRequestBytes = 4 << 20 // 4 MiB

// serverConfig is the resolved set of injected holders the server verify face runs
// over: the request-signing KeyResolver, the ReplayStore, the hop budget, the
// request-id source, and any application interceptors. All are injected — the SDK
// owns no keys, no replay state, and no policy constants (ADR-020 §3).
type serverConfig struct {
	resolver        helpers.KeyResolver
	replay          core.ReplayStore
	replayTTL       time.Duration
	maxSignatures   int
	maxSignatureAge time.Duration
	allowNoReplay   bool
	validation      rampconnect.Validation
	requestID       core.RequestIDFunc
	extra           []connectrpc.Interceptor
	handlerOpts     []connectrpc.HandlerOption
	verifyGate      func(*http.Request) bool
	onReject        func(*http.Request, error)
	maxRequestBytes int64
}

// ServerOption configures the server verify face.
type ServerOption func(*serverConfig)

// WithKeyResolver injects the request-signing KeyResolver the verify face resolves
// each signature's key through — the same interface the client resolves offer keys
// through (connect.WithKeyResolver). Custody and network policy stay with the app.
func WithKeyResolver(r helpers.KeyResolver) ServerOption {
	return func(c *serverConfig) { c.resolver = r }
}

// WithReplayStore injects the nonce-dedup store the verify face calls as part of
// fail-closed verification. The SDK orchestrates the check; the app owns the store
// and its persistence. Omitting it disables the replay check (verify-only).
func WithReplayStore(s core.ReplayStore) ServerOption {
	return func(c *serverConfig) { c.replay = s }
}

// WithReplayTTL overrides the nonce-retention window passed to the store's
// SeenOrAdd (default 5 minutes).
func WithReplayTTL(ttl time.Duration) ServerOption {
	return func(c *serverConfig) { c.replayTTL = ttl }
}

// WithMaxSignatureAge clamps the accepted signature lifetime (expires − created).
// It bounds the replay window even when no ReplayStore is wired: without it a
// signer can set a far-future expires and replay the same bytes until then. 0
// (default) is unbounded; a terminal Exchange sets it to its replay-window target
// (minutes). A longer-lived signature is rejected as a verify-gate failure.
func WithMaxSignatureAge(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.maxSignatureAge = d }
}

// WithoutReplayStore is the explicit acknowledgement that this server face runs
// with no replay protection (e.g. a stateless edge that relies only on the
// MaxSignatureAge window). It silences the construction-time warning that a
// server handler otherwise emits when no ReplayStore is injected, so an
// ACCIDENTAL omission stays loud while a DELIBERATE one is quiet.
func WithoutReplayStore() ServerOption {
	return func(c *serverConfig) { c.allowNoReplay = true }
}

// WithMaxSignatures injects the hop budget — the maximum number of signatures a
// multisig (relay) request may carry (= max_intermediary_hops + 1). It is an
// INJECTED value, never an SDK constant: the hop LIMIT is app policy, only the
// reject-reason→connect.Code mapping is SDK mechanics. 0 means unbounded.
func WithMaxSignatures(n int) ServerOption {
	return func(c *serverConfig) { c.maxSignatures = n }
}

// WithMaxRequestBytes overrides the per-request read cap (default
// DefaultMaxRequestBytes). It bounds TWO distinct quantities, because a caller can
// exhaust the server through either: the decompressed Connect message, refused as
// CodeResourceExhausted, and the raw HTTP body the verify face buffers before it
// can check a signature, refused as a 413. An unsigned caller reaches only the
// second, which is why the body bound cannot wait for authentication.
//
// A non-positive value restores the default rather than disabling the cap: a
// server that reads without a bound is the state this option exists to prevent,
// and no accident should be able to select it.
func WithMaxRequestBytes(n int64) ServerOption {
	return func(c *serverConfig) { c.maxRequestBytes = n }
}

// WithValidation sets protovalidate strictness for the server face. The default is
// ValidationOff; a server opts into bidirectional wire-shape enforcement (requests
// + responses + error details) with WithValidation(connect.ValidationStrict). The
// Validation enum is shared with the client (sdk/go/connect) so both faces select
// strictness with one type.
func WithValidation(v rampconnect.Validation) ServerOption {
	return func(c *serverConfig) { c.validation = v }
}

// WithRequestIDFunc overrides the server request-id source stamped outermost on
// every response (including the reject path).
func WithRequestIDFunc(fn core.RequestIDFunc) ServerOption {
	return func(c *serverConfig) { c.requestID = fn }
}

// WithInterceptors appends application interceptors (tracing, metrics) to the
// generated handler's interceptor stack, inside the SDK validate / error-detail
// interceptors.
func WithInterceptors(is ...connectrpc.Interceptor) ServerOption {
	return func(c *serverConfig) { c.extra = append(c.extra, is...) }
}

// WithHandlerOptions appends raw connect handler options (e.g. a custom codec
// via connectrpc.WithCodec) to the generated handler. Interceptors belong in
// WithInterceptors; this is the escape hatch for the remaining handler-level
// knobs the SDK does not model.
func WithHandlerOptions(opts ...connectrpc.HandlerOption) ServerOption {
	return func(c *serverConfig) { c.handlerOpts = append(c.handlerOpts, opts...) }
}

// WithVerifyGate overrides which requests the seam verifies. The DEFAULT gates
// every /ramp. procedure unconditionally (fail-closed). A service whose
// handlers own the typed Unauthenticated fault for UNSIGNED requests narrows
// the gate to signature-presenting requests only:
//
//	WithVerifyGate(func(r *http.Request) bool {
//		return r.Header.Get("Signature-Input") != ""
//	})
//
// A request the gate declines is NOT rejected — it flows to the origin handler
// unverified (helpers.FromContext returns nil there), so the handler decides.
// The gate composes with the /ramp. procedure check; it cannot widen the seam
// to non-procedure paths.
func WithVerifyGate(gate func(*http.Request) bool) ServerOption {
	return func(c *serverConfig) { c.verifyGate = gate }
}

// WithOnReject injects an observer the verify gate calls when it REJECTS a
// request, before the rejection response is written. It receives the request
// and the rejection error so a consumer can audit-log the outcome, classifying
// it via errors.Is against the exported sentinels (ErrTooManyHops → hop budget,
// ErrReplayed → replay, helpers.ErrBrokenSignatureChain → broken chain, else →
// signature). The observer is for observation only — it MUST NOT write to the
// response (the gate owns the fail-closed response) and runs on the reject path
// exclusively (a verified request never calls it). Omitting it keeps rejections
// silent (the pre-existing behavior).
func WithOnReject(fn func(*http.Request, error)) ServerOption {
	return func(c *serverConfig) { c.onReject = fn }
}

func resolveServerConfig(opts []ServerOption) serverConfig {
	cfg := serverConfig{replayTTL: replayTTL}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.replayTTL <= 0 {
		cfg.replayTTL = replayTTL
	}
	if cfg.maxRequestBytes <= 0 {
		cfg.maxRequestBytes = DefaultMaxRequestBytes
	}
	// A server face with no replay store silently accepts a replayed signature
	// within its window. That is a legitimate stateless-edge choice, but a
	// FORGOTTEN WithReplayStore is a security hole, so make an unacknowledged
	// omission loud (opt out deliberately with WithoutReplayStore).
	if cfg.replay == nil && !cfg.allowNoReplay {
		slog.Warn("connectserver: no ReplayStore injected — replay protection is OFF; " +
			"inject WithReplayStore, or acknowledge with WithoutReplayStore to silence this")
	}
	return cfg
}
