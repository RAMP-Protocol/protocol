package connectserver

import (
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

// serverConfig is the resolved set of injected holders the server verify face runs
// over: the request-signing KeyResolver, the ReplayStore, the hop budget, the
// request-id source, and any application interceptors. All are injected — the SDK
// owns no keys, no replay state, and no policy constants (ADR-020 §3).
type serverConfig struct {
	resolver      helpers.KeyResolver
	replay        core.ReplayStore
	replayTTL     time.Duration
	maxSignatures int
	validation    rampconnect.Validation
	requestID     core.RequestIDFunc
	extra         []connectrpc.Interceptor
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

// WithMaxSignatures injects the hop budget — the maximum number of signatures a
// multisig (relay) request may carry (= max_intermediary_hops + 1). It is an
// INJECTED value, never an SDK constant: the hop LIMIT is app policy, only the
// reject-reason→connect.Code mapping is SDK mechanics. 0 means unbounded.
func WithMaxSignatures(n int) ServerOption {
	return func(c *serverConfig) { c.maxSignatures = n }
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

func resolveServerConfig(opts []ServerOption) serverConfig {
	cfg := serverConfig{replayTTL: replayTTL}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.replayTTL <= 0 {
		cfg.replayTTL = replayTTL
	}
	return cfg
}
