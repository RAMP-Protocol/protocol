// RAMP v1.0 — Resource Access Metering Protocol
//
// Extends IAB Tech Lab CoMP v1.0 with pricing, marketplace orchestration,
// resource identity, transactions, and post-usage reporting.
//
// v1.0 additions (from v0.2):
//   - Metering generalization: unit-agnostic pricing (unit_cost, estimated_quantity, unit)
//     replaces text-specific eCPT/estimated_tokens. Supports tokens, seconds, pages,
//     records, bytes, calls, and domain-specific units.
//   - Usage generalization: consumed_quantity + consumed_unit replace token_count
//   - New pricing models: PER_PAGE, PER_MINUTE, PER_RECORD
//   - Streaming delivery: DELIVERY_METHOD_STREAMING for real-time connections (WebSocket, SSE)
//   - CoMP decoupled: comp.v1.Package/Function moved to ramp-comp-v1 extension profile.
//     Core protocol no longer imports comp.proto. IAB metadata is optional via ext.
//   - Pricing.revshare + license_duration_months: revenue share pricing model
//   - PRICING_MODEL_REVENUE_SHARE: new pricing model enum value
//   - AccessRestrictions.max_display_words: word display limit from CoMP License.maxword
//   - CitationFormat enum + AttributionDetail message: structured attribution in Usage
//   - Usage.attribution: detailed citation reporting
//   - OfferGroup.absence_reason: per-URI diagnostic when no offers available
//   - ResourceResponse.rate_limit: rate limit signaling on discovery
//   - OfferAbsenceReason enum (7 reasons)
//   - RateLimitInfo message (limit, remaining, reset_at, window)
//   - DisputeTransaction RPC: resource dispute signaling
//   - DomainVerification messages: ACME-style provider onboarding
//   - ResourceAttestation: signed claim envelope for resource integrity verification
//   - DisputeStatus enum: full dispute lifecycle (FILED → FINAL)
//   - ResolutionType enum: dispute resolution outcomes (CREDIT, REDELIVERY, etc.)
//   - Offer.attestations: replaces ContentQuality with cryptographic attestations
//   - ResourceEntry.attestations: attestations at catalog level
//   - UsageReportResponse.report_id: enables dispute chain (report → dispute)
//   - DisputeRequest.report_id: agent must file usage report before disputing
//   - DisputeResponse.status/resolution: dispute lifecycle tracking
//   - ProviderManifest.catalog_contributors: authorized third-party catalog pushers
//   - WellKnownManifest: machine-readable self-description for every role (/.well-known/ramp.json). ExchangeManifest deprecated v1.1.0.
//   - ResourceMutability enum: signals whether resource content is static, dynamic, or live
//     Drives hash verification behavior: STATIC = verify hash, DYNAMIC = expect hash drift,
//     LIVE = no content exists at offer time (streaming). Validated across 18 use cases.
//   - Offer.data_as_of: timestamp indicating when the offered data was current.
//     Cross-cutting need: credit reports, drug databases, stock quotes, satellite imagery.
//   - RequestConstraints.max_data_age: agent-side freshness requirement. Marketplace
//     SHOULD exclude offers whose data_as_of is older than this threshold.
//   - ExchangeManifest.supported_profiles: declares conformance to domain extension
//     profiles (e.g., "ramp-pharma-v1", "ramp-medimg-v1"). Enables Broker filtering.
//   - ResourceQuery.supported_profiles: caller declares which profiles it understands.
//     Exchange MAY optimize metadata computation based on declared profiles.
//   - RAMPRequest.supported_profiles: agent declares profiles to Broker.
//     Broker uses this for routing and profile forwarding.
//   - ext_critical: critical extension signaling (COSE crit pattern, RFC 9052).
//     Every message with an ext field also carries ext_critical — a list of
//     ext keys that MUST be understood by the consumer. If a consumer encounters
//     a key in ext_critical that it does not recognize, it MUST reject the message.
//     Regular ext keys (not in ext_critical) follow the robustness principle:
//     unknown keys are safely ignored. This pattern is well-established across
//     FHIR (modifierExtension), SOAP (mustUnderstand), CoAP (odd/even options),
//     and COSE (crit). RAMP adopts the COSE enumeration approach because it
//     avoids the namespace migration problem (MIME X- prefix, RFC 6648) and
//     supports contextual criticality (same extension can be critical in some
//     messages but not others).
//   - retrieval_endpoint: canonical signed-URL field on TransactionResponse,
//     TransactionResultItem, and RAMPResponse. Replaces ext["signed_url"]
//     usage; removes stranded CoMP Package comments.
//
// v1.1.0 additions (from v1.0.2):
//   - WellKnownManifest: unified manifest served at /.well-known/ramp.json
//     by every RAMP role (agent, broker, exchange, publisher). Replaces
//     ProviderManifest and ExchangeManifest, both now Deprecated.
//   - JsonWebKey: inline RFC 7517 JWK objects with not_before / not_after
//     time bounds, replacing the keys_uri / jwks_uri pointer pattern.
//   - KeyInvalidationList: snapshot-semantic kid revocation list served
//     at WellKnownManifest.invalidation_url for emergency revocation.
//   - Role enum (AGENT, EXCHANGE, BROKER, PUBLISHER). Verifiers fold
//     into the role their operating domain holds.
//   - ProviderManifest.marketplaces renamed to exchanges (wire tag 4
//     preserved). Same rename propagates into WellKnownManifest.
//   - Per-role well-known filenames (ramp-agent.json, ramp-exchange.json,
//     ramp-verifier.json) and the legacy /marketplace/v1/keys path are
//     eliminated from the spec. ExchangeManifest.keys_uri and .jwks_uri
//     are marked Deprecated.
//
// The ExchangeService is the core protocol. Both AI agents and
// Brokers are valid clients — the Exchange doesn't distinguish.

// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: ramp/v1/ramp.proto

package rampv1connect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	v1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// ExchangeServiceName is the fully-qualified name of the ExchangeService service.
	ExchangeServiceName = "ramp.v1.ExchangeService"
	// CatalogServiceName is the fully-qualified name of the CatalogService service.
	CatalogServiceName = "ramp.v1.CatalogService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// ExchangeServiceDiscoverResourcesProcedure is the fully-qualified name of the ExchangeService's
	// DiscoverResources RPC.
	ExchangeServiceDiscoverResourcesProcedure = "/ramp.v1.ExchangeService/DiscoverResources"
	// ExchangeServiceExecuteTransactionProcedure is the fully-qualified name of the ExchangeService's
	// ExecuteTransaction RPC.
	ExchangeServiceExecuteTransactionProcedure = "/ramp.v1.ExchangeService/ExecuteTransaction"
	// ExchangeServiceReportUsageProcedure is the fully-qualified name of the ExchangeService's
	// ReportUsage RPC.
	ExchangeServiceReportUsageProcedure = "/ramp.v1.ExchangeService/ReportUsage"
	// ExchangeServiceDisputeTransactionProcedure is the fully-qualified name of the ExchangeService's
	// DisputeTransaction RPC.
	ExchangeServiceDisputeTransactionProcedure = "/ramp.v1.ExchangeService/DisputeTransaction"
	// ExchangeServiceRequestDomainVerificationProcedure is the fully-qualified name of the
	// ExchangeService's RequestDomainVerification RPC.
	ExchangeServiceRequestDomainVerificationProcedure = "/ramp.v1.ExchangeService/RequestDomainVerification"
	// ExchangeServiceConfirmDomainVerificationProcedure is the fully-qualified name of the
	// ExchangeService's ConfirmDomainVerification RPC.
	ExchangeServiceConfirmDomainVerificationProcedure = "/ramp.v1.ExchangeService/ConfirmDomainVerification"
	// CatalogServicePushResourcesProcedure is the fully-qualified name of the CatalogService's
	// PushResources RPC.
	CatalogServicePushResourcesProcedure = "/ramp.v1.CatalogService/PushResources"
	// CatalogServiceRemoveResourcesProcedure is the fully-qualified name of the CatalogService's
	// RemoveResources RPC.
	CatalogServiceRemoveResourcesProcedure = "/ramp.v1.CatalogService/RemoveResources"
	// CatalogServiceRefreshCatalogProcedure is the fully-qualified name of the CatalogService's
	// RefreshCatalog RPC.
	CatalogServiceRefreshCatalogProcedure = "/ramp.v1.CatalogService/RefreshCatalog"
)

// ExchangeServiceClient is a client for the ramp.v1.ExchangeService service.
type ExchangeServiceClient interface {
	// Discover available resource offers matching the query.
	// Steps 2-3 in the RAMP flow.
	DiscoverResources(context.Context, *connect.Request[v1.ResourceQuery]) (*connect.Response[v1.ResourceResponse], error)
	// Commit to an offer and receive delivery information.
	// Steps 4-5 in the RAMP flow.
	ExecuteTransaction(context.Context, *connect.Request[v1.TransactionRequest]) (*connect.Response[v1.TransactionResponse], error)
	// Submit a post-usage report for a completed transaction.
	// Step 7 in the RAMP flow.
	ReportUsage(context.Context, *connect.Request[v1.UsageReport]) (*connect.Response[v1.UsageReportResponse], error)
	// v0.3: Signal a resource dispute for a completed transaction.
	// Filed by the agent when delivered resource does not match what was
	// promised (hash mismatch, resource unavailable, wrong resource).
	// The Exchange records the dispute and initiates resolution.
	// Resolution mechanics (refund, credit, re-delivery) are implementation-
	// specific — this RPC standardizes the dispute signal, not the outcome.
	DisputeTransaction(context.Context, *connect.Request[v1.DisputeRequest]) (*connect.Response[v1.DisputeResponse], error)
	// v0.3: Request a domain verification challenge for provider onboarding.
	// Used by ramp-cli to prove domain control before pushing signing keys.
	// Follows the ACME HTTP-01 pattern (Let's Encrypt).
	RequestDomainVerification(context.Context, *connect.Request[v1.DomainVerificationRequest]) (*connect.Response[v1.DomainVerificationChallenge], error)
	// v0.3: Confirm domain verification and register a signing key.
	// Called after the challenge token is placed at the provider's domain.
	ConfirmDomainVerification(context.Context, *connect.Request[v1.DomainVerificationConfirmation]) (*connect.Response[v1.DomainVerificationResult], error)
}

// NewExchangeServiceClient constructs a client for the ramp.v1.ExchangeService service. By default,
// it uses the Connect protocol with the binary Protobuf Codec, asks for gzipped responses, and
// sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC()
// or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewExchangeServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) ExchangeServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	exchangeServiceMethods := v1.File_ramp_v1_ramp_proto.Services().ByName("ExchangeService").Methods()
	return &exchangeServiceClient{
		discoverResources: connect.NewClient[v1.ResourceQuery, v1.ResourceResponse](
			httpClient,
			baseURL+ExchangeServiceDiscoverResourcesProcedure,
			connect.WithSchema(exchangeServiceMethods.ByName("DiscoverResources")),
			connect.WithClientOptions(opts...),
		),
		executeTransaction: connect.NewClient[v1.TransactionRequest, v1.TransactionResponse](
			httpClient,
			baseURL+ExchangeServiceExecuteTransactionProcedure,
			connect.WithSchema(exchangeServiceMethods.ByName("ExecuteTransaction")),
			connect.WithClientOptions(opts...),
		),
		reportUsage: connect.NewClient[v1.UsageReport, v1.UsageReportResponse](
			httpClient,
			baseURL+ExchangeServiceReportUsageProcedure,
			connect.WithSchema(exchangeServiceMethods.ByName("ReportUsage")),
			connect.WithClientOptions(opts...),
		),
		disputeTransaction: connect.NewClient[v1.DisputeRequest, v1.DisputeResponse](
			httpClient,
			baseURL+ExchangeServiceDisputeTransactionProcedure,
			connect.WithSchema(exchangeServiceMethods.ByName("DisputeTransaction")),
			connect.WithClientOptions(opts...),
		),
		requestDomainVerification: connect.NewClient[v1.DomainVerificationRequest, v1.DomainVerificationChallenge](
			httpClient,
			baseURL+ExchangeServiceRequestDomainVerificationProcedure,
			connect.WithSchema(exchangeServiceMethods.ByName("RequestDomainVerification")),
			connect.WithClientOptions(opts...),
		),
		confirmDomainVerification: connect.NewClient[v1.DomainVerificationConfirmation, v1.DomainVerificationResult](
			httpClient,
			baseURL+ExchangeServiceConfirmDomainVerificationProcedure,
			connect.WithSchema(exchangeServiceMethods.ByName("ConfirmDomainVerification")),
			connect.WithClientOptions(opts...),
		),
	}
}

// exchangeServiceClient implements ExchangeServiceClient.
type exchangeServiceClient struct {
	discoverResources         *connect.Client[v1.ResourceQuery, v1.ResourceResponse]
	executeTransaction        *connect.Client[v1.TransactionRequest, v1.TransactionResponse]
	reportUsage               *connect.Client[v1.UsageReport, v1.UsageReportResponse]
	disputeTransaction        *connect.Client[v1.DisputeRequest, v1.DisputeResponse]
	requestDomainVerification *connect.Client[v1.DomainVerificationRequest, v1.DomainVerificationChallenge]
	confirmDomainVerification *connect.Client[v1.DomainVerificationConfirmation, v1.DomainVerificationResult]
}

// DiscoverResources calls ramp.v1.ExchangeService.DiscoverResources.
func (c *exchangeServiceClient) DiscoverResources(ctx context.Context, req *connect.Request[v1.ResourceQuery]) (*connect.Response[v1.ResourceResponse], error) {
	return c.discoverResources.CallUnary(ctx, req)
}

// ExecuteTransaction calls ramp.v1.ExchangeService.ExecuteTransaction.
func (c *exchangeServiceClient) ExecuteTransaction(ctx context.Context, req *connect.Request[v1.TransactionRequest]) (*connect.Response[v1.TransactionResponse], error) {
	return c.executeTransaction.CallUnary(ctx, req)
}

// ReportUsage calls ramp.v1.ExchangeService.ReportUsage.
func (c *exchangeServiceClient) ReportUsage(ctx context.Context, req *connect.Request[v1.UsageReport]) (*connect.Response[v1.UsageReportResponse], error) {
	return c.reportUsage.CallUnary(ctx, req)
}

// DisputeTransaction calls ramp.v1.ExchangeService.DisputeTransaction.
func (c *exchangeServiceClient) DisputeTransaction(ctx context.Context, req *connect.Request[v1.DisputeRequest]) (*connect.Response[v1.DisputeResponse], error) {
	return c.disputeTransaction.CallUnary(ctx, req)
}

// RequestDomainVerification calls ramp.v1.ExchangeService.RequestDomainVerification.
func (c *exchangeServiceClient) RequestDomainVerification(ctx context.Context, req *connect.Request[v1.DomainVerificationRequest]) (*connect.Response[v1.DomainVerificationChallenge], error) {
	return c.requestDomainVerification.CallUnary(ctx, req)
}

// ConfirmDomainVerification calls ramp.v1.ExchangeService.ConfirmDomainVerification.
func (c *exchangeServiceClient) ConfirmDomainVerification(ctx context.Context, req *connect.Request[v1.DomainVerificationConfirmation]) (*connect.Response[v1.DomainVerificationResult], error) {
	return c.confirmDomainVerification.CallUnary(ctx, req)
}

// ExchangeServiceHandler is an implementation of the ramp.v1.ExchangeService service.
type ExchangeServiceHandler interface {
	// Discover available resource offers matching the query.
	// Steps 2-3 in the RAMP flow.
	DiscoverResources(context.Context, *connect.Request[v1.ResourceQuery]) (*connect.Response[v1.ResourceResponse], error)
	// Commit to an offer and receive delivery information.
	// Steps 4-5 in the RAMP flow.
	ExecuteTransaction(context.Context, *connect.Request[v1.TransactionRequest]) (*connect.Response[v1.TransactionResponse], error)
	// Submit a post-usage report for a completed transaction.
	// Step 7 in the RAMP flow.
	ReportUsage(context.Context, *connect.Request[v1.UsageReport]) (*connect.Response[v1.UsageReportResponse], error)
	// v0.3: Signal a resource dispute for a completed transaction.
	// Filed by the agent when delivered resource does not match what was
	// promised (hash mismatch, resource unavailable, wrong resource).
	// The Exchange records the dispute and initiates resolution.
	// Resolution mechanics (refund, credit, re-delivery) are implementation-
	// specific — this RPC standardizes the dispute signal, not the outcome.
	DisputeTransaction(context.Context, *connect.Request[v1.DisputeRequest]) (*connect.Response[v1.DisputeResponse], error)
	// v0.3: Request a domain verification challenge for provider onboarding.
	// Used by ramp-cli to prove domain control before pushing signing keys.
	// Follows the ACME HTTP-01 pattern (Let's Encrypt).
	RequestDomainVerification(context.Context, *connect.Request[v1.DomainVerificationRequest]) (*connect.Response[v1.DomainVerificationChallenge], error)
	// v0.3: Confirm domain verification and register a signing key.
	// Called after the challenge token is placed at the provider's domain.
	ConfirmDomainVerification(context.Context, *connect.Request[v1.DomainVerificationConfirmation]) (*connect.Response[v1.DomainVerificationResult], error)
}

// NewExchangeServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewExchangeServiceHandler(svc ExchangeServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	exchangeServiceMethods := v1.File_ramp_v1_ramp_proto.Services().ByName("ExchangeService").Methods()
	exchangeServiceDiscoverResourcesHandler := connect.NewUnaryHandler(
		ExchangeServiceDiscoverResourcesProcedure,
		svc.DiscoverResources,
		connect.WithSchema(exchangeServiceMethods.ByName("DiscoverResources")),
		connect.WithHandlerOptions(opts...),
	)
	exchangeServiceExecuteTransactionHandler := connect.NewUnaryHandler(
		ExchangeServiceExecuteTransactionProcedure,
		svc.ExecuteTransaction,
		connect.WithSchema(exchangeServiceMethods.ByName("ExecuteTransaction")),
		connect.WithHandlerOptions(opts...),
	)
	exchangeServiceReportUsageHandler := connect.NewUnaryHandler(
		ExchangeServiceReportUsageProcedure,
		svc.ReportUsage,
		connect.WithSchema(exchangeServiceMethods.ByName("ReportUsage")),
		connect.WithHandlerOptions(opts...),
	)
	exchangeServiceDisputeTransactionHandler := connect.NewUnaryHandler(
		ExchangeServiceDisputeTransactionProcedure,
		svc.DisputeTransaction,
		connect.WithSchema(exchangeServiceMethods.ByName("DisputeTransaction")),
		connect.WithHandlerOptions(opts...),
	)
	exchangeServiceRequestDomainVerificationHandler := connect.NewUnaryHandler(
		ExchangeServiceRequestDomainVerificationProcedure,
		svc.RequestDomainVerification,
		connect.WithSchema(exchangeServiceMethods.ByName("RequestDomainVerification")),
		connect.WithHandlerOptions(opts...),
	)
	exchangeServiceConfirmDomainVerificationHandler := connect.NewUnaryHandler(
		ExchangeServiceConfirmDomainVerificationProcedure,
		svc.ConfirmDomainVerification,
		connect.WithSchema(exchangeServiceMethods.ByName("ConfirmDomainVerification")),
		connect.WithHandlerOptions(opts...),
	)
	return "/ramp.v1.ExchangeService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case ExchangeServiceDiscoverResourcesProcedure:
			exchangeServiceDiscoverResourcesHandler.ServeHTTP(w, r)
		case ExchangeServiceExecuteTransactionProcedure:
			exchangeServiceExecuteTransactionHandler.ServeHTTP(w, r)
		case ExchangeServiceReportUsageProcedure:
			exchangeServiceReportUsageHandler.ServeHTTP(w, r)
		case ExchangeServiceDisputeTransactionProcedure:
			exchangeServiceDisputeTransactionHandler.ServeHTTP(w, r)
		case ExchangeServiceRequestDomainVerificationProcedure:
			exchangeServiceRequestDomainVerificationHandler.ServeHTTP(w, r)
		case ExchangeServiceConfirmDomainVerificationProcedure:
			exchangeServiceConfirmDomainVerificationHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedExchangeServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedExchangeServiceHandler struct{}

func (UnimplementedExchangeServiceHandler) DiscoverResources(context.Context, *connect.Request[v1.ResourceQuery]) (*connect.Response[v1.ResourceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.ExchangeService.DiscoverResources is not implemented"))
}

func (UnimplementedExchangeServiceHandler) ExecuteTransaction(context.Context, *connect.Request[v1.TransactionRequest]) (*connect.Response[v1.TransactionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.ExchangeService.ExecuteTransaction is not implemented"))
}

func (UnimplementedExchangeServiceHandler) ReportUsage(context.Context, *connect.Request[v1.UsageReport]) (*connect.Response[v1.UsageReportResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.ExchangeService.ReportUsage is not implemented"))
}

func (UnimplementedExchangeServiceHandler) DisputeTransaction(context.Context, *connect.Request[v1.DisputeRequest]) (*connect.Response[v1.DisputeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.ExchangeService.DisputeTransaction is not implemented"))
}

func (UnimplementedExchangeServiceHandler) RequestDomainVerification(context.Context, *connect.Request[v1.DomainVerificationRequest]) (*connect.Response[v1.DomainVerificationChallenge], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.ExchangeService.RequestDomainVerification is not implemented"))
}

func (UnimplementedExchangeServiceHandler) ConfirmDomainVerification(context.Context, *connect.Request[v1.DomainVerificationConfirmation]) (*connect.Response[v1.DomainVerificationResult], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.ExchangeService.ConfirmDomainVerification is not implemented"))
}

// CatalogServiceClient is a client for the ramp.v1.CatalogService service.
type CatalogServiceClient interface {
	// Push or update resource entries in the Exchange catalog.
	PushResources(context.Context, *connect.Request[v1.PushResourcesRequest]) (*connect.Response[v1.PushResourcesResponse], error)
	// Remove resource entries.
	RemoveResources(context.Context, *connect.Request[v1.RemoveResourcesRequest]) (*connect.Response[v1.RemoveResourcesResponse], error)
	// Trigger a full catalog refresh from configured sources.
	RefreshCatalog(context.Context, *connect.Request[v1.RefreshCatalogRequest]) (*connect.Response[v1.RefreshCatalogResponse], error)
}

// NewCatalogServiceClient constructs a client for the ramp.v1.CatalogService service. By default,
// it uses the Connect protocol with the binary Protobuf Codec, asks for gzipped responses, and
// sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC()
// or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewCatalogServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) CatalogServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	catalogServiceMethods := v1.File_ramp_v1_ramp_proto.Services().ByName("CatalogService").Methods()
	return &catalogServiceClient{
		pushResources: connect.NewClient[v1.PushResourcesRequest, v1.PushResourcesResponse](
			httpClient,
			baseURL+CatalogServicePushResourcesProcedure,
			connect.WithSchema(catalogServiceMethods.ByName("PushResources")),
			connect.WithClientOptions(opts...),
		),
		removeResources: connect.NewClient[v1.RemoveResourcesRequest, v1.RemoveResourcesResponse](
			httpClient,
			baseURL+CatalogServiceRemoveResourcesProcedure,
			connect.WithSchema(catalogServiceMethods.ByName("RemoveResources")),
			connect.WithClientOptions(opts...),
		),
		refreshCatalog: connect.NewClient[v1.RefreshCatalogRequest, v1.RefreshCatalogResponse](
			httpClient,
			baseURL+CatalogServiceRefreshCatalogProcedure,
			connect.WithSchema(catalogServiceMethods.ByName("RefreshCatalog")),
			connect.WithClientOptions(opts...),
		),
	}
}

// catalogServiceClient implements CatalogServiceClient.
type catalogServiceClient struct {
	pushResources   *connect.Client[v1.PushResourcesRequest, v1.PushResourcesResponse]
	removeResources *connect.Client[v1.RemoveResourcesRequest, v1.RemoveResourcesResponse]
	refreshCatalog  *connect.Client[v1.RefreshCatalogRequest, v1.RefreshCatalogResponse]
}

// PushResources calls ramp.v1.CatalogService.PushResources.
func (c *catalogServiceClient) PushResources(ctx context.Context, req *connect.Request[v1.PushResourcesRequest]) (*connect.Response[v1.PushResourcesResponse], error) {
	return c.pushResources.CallUnary(ctx, req)
}

// RemoveResources calls ramp.v1.CatalogService.RemoveResources.
func (c *catalogServiceClient) RemoveResources(ctx context.Context, req *connect.Request[v1.RemoveResourcesRequest]) (*connect.Response[v1.RemoveResourcesResponse], error) {
	return c.removeResources.CallUnary(ctx, req)
}

// RefreshCatalog calls ramp.v1.CatalogService.RefreshCatalog.
func (c *catalogServiceClient) RefreshCatalog(ctx context.Context, req *connect.Request[v1.RefreshCatalogRequest]) (*connect.Response[v1.RefreshCatalogResponse], error) {
	return c.refreshCatalog.CallUnary(ctx, req)
}

// CatalogServiceHandler is an implementation of the ramp.v1.CatalogService service.
type CatalogServiceHandler interface {
	// Push or update resource entries in the Exchange catalog.
	PushResources(context.Context, *connect.Request[v1.PushResourcesRequest]) (*connect.Response[v1.PushResourcesResponse], error)
	// Remove resource entries.
	RemoveResources(context.Context, *connect.Request[v1.RemoveResourcesRequest]) (*connect.Response[v1.RemoveResourcesResponse], error)
	// Trigger a full catalog refresh from configured sources.
	RefreshCatalog(context.Context, *connect.Request[v1.RefreshCatalogRequest]) (*connect.Response[v1.RefreshCatalogResponse], error)
}

// NewCatalogServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewCatalogServiceHandler(svc CatalogServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	catalogServiceMethods := v1.File_ramp_v1_ramp_proto.Services().ByName("CatalogService").Methods()
	catalogServicePushResourcesHandler := connect.NewUnaryHandler(
		CatalogServicePushResourcesProcedure,
		svc.PushResources,
		connect.WithSchema(catalogServiceMethods.ByName("PushResources")),
		connect.WithHandlerOptions(opts...),
	)
	catalogServiceRemoveResourcesHandler := connect.NewUnaryHandler(
		CatalogServiceRemoveResourcesProcedure,
		svc.RemoveResources,
		connect.WithSchema(catalogServiceMethods.ByName("RemoveResources")),
		connect.WithHandlerOptions(opts...),
	)
	catalogServiceRefreshCatalogHandler := connect.NewUnaryHandler(
		CatalogServiceRefreshCatalogProcedure,
		svc.RefreshCatalog,
		connect.WithSchema(catalogServiceMethods.ByName("RefreshCatalog")),
		connect.WithHandlerOptions(opts...),
	)
	return "/ramp.v1.CatalogService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case CatalogServicePushResourcesProcedure:
			catalogServicePushResourcesHandler.ServeHTTP(w, r)
		case CatalogServiceRemoveResourcesProcedure:
			catalogServiceRemoveResourcesHandler.ServeHTTP(w, r)
		case CatalogServiceRefreshCatalogProcedure:
			catalogServiceRefreshCatalogHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedCatalogServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedCatalogServiceHandler struct{}

func (UnimplementedCatalogServiceHandler) PushResources(context.Context, *connect.Request[v1.PushResourcesRequest]) (*connect.Response[v1.PushResourcesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.CatalogService.PushResources is not implemented"))
}

func (UnimplementedCatalogServiceHandler) RemoveResources(context.Context, *connect.Request[v1.RemoveResourcesRequest]) (*connect.Response[v1.RemoveResourcesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.CatalogService.RemoveResources is not implemented"))
}

func (UnimplementedCatalogServiceHandler) RefreshCatalog(context.Context, *connect.Request[v1.RefreshCatalogRequest]) (*connect.Response[v1.RefreshCatalogResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ramp.v1.CatalogService.RefreshCatalog is not implemented"))
}
