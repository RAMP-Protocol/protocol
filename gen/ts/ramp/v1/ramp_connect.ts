// RAMP v1.0 — Resource Access Metering Protocol
//
// Extends IAB Tech Lab CoMP v1.0 with pricing, exchange orchestration,
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
//   - RequestConstraints.max_data_age: agent-side freshness requirement. Exchange
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

// @generated by protoc-gen-connect-es v1.6.1 with parameter "target=ts"
// @generated from file ramp/v1/ramp.proto (package ramp.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { DisputeRequest, DisputeResponse, DomainVerificationChallenge, DomainVerificationConfirmation, DomainVerificationRequest, DomainVerificationResult, PushResourcesRequest, PushResourcesResponse, RefreshCatalogRequest, RefreshCatalogResponse, RemoveResourcesRequest, RemoveResourcesResponse, ResourceQuery, ResourceResponse, TransactionRequest, TransactionResponse, UsageReport, UsageReportResponse } from "./ramp_pb.js";
import { MethodKind } from "@bufbuild/protobuf";

/**
 * @generated from service ramp.v1.ExchangeService
 */
export const ExchangeService = {
  typeName: "ramp.v1.ExchangeService",
  methods: {
    /**
     * Discover available resource offers matching the query.
     * Steps 2-3 in the RAMP flow.
     *
     * @generated from rpc ramp.v1.ExchangeService.DiscoverResources
     */
    discoverResources: {
      name: "DiscoverResources",
      I: ResourceQuery,
      O: ResourceResponse,
      kind: MethodKind.Unary,
    },
    /**
     * Commit to an offer and receive delivery information.
     * Steps 4-5 in the RAMP flow.
     *
     * @generated from rpc ramp.v1.ExchangeService.ExecuteTransaction
     */
    executeTransaction: {
      name: "ExecuteTransaction",
      I: TransactionRequest,
      O: TransactionResponse,
      kind: MethodKind.Unary,
    },
    /**
     * Submit a post-usage report for a completed transaction.
     * Step 7 in the RAMP flow.
     *
     * @generated from rpc ramp.v1.ExchangeService.ReportUsage
     */
    reportUsage: {
      name: "ReportUsage",
      I: UsageReport,
      O: UsageReportResponse,
      kind: MethodKind.Unary,
    },
    /**
     * v0.3: Signal a resource dispute for a completed transaction.
     * Filed by the agent when delivered resource does not match what was
     * promised (hash mismatch, resource unavailable, wrong resource).
     * The Exchange records the dispute and initiates resolution.
     * Resolution mechanics (refund, credit, re-delivery) are implementation-
     * specific — this RPC standardizes the dispute signal, not the outcome.
     *
     * @generated from rpc ramp.v1.ExchangeService.DisputeTransaction
     */
    disputeTransaction: {
      name: "DisputeTransaction",
      I: DisputeRequest,
      O: DisputeResponse,
      kind: MethodKind.Unary,
    },
    /**
     * v0.3: Request a domain verification challenge for provider onboarding.
     * Used by ramp-cli to prove domain control before pushing signing keys.
     * Follows the ACME HTTP-01 pattern (Let's Encrypt).
     *
     * @generated from rpc ramp.v1.ExchangeService.RequestDomainVerification
     */
    requestDomainVerification: {
      name: "RequestDomainVerification",
      I: DomainVerificationRequest,
      O: DomainVerificationChallenge,
      kind: MethodKind.Unary,
    },
    /**
     * v0.3: Confirm domain verification and register a signing key.
     * Called after the challenge token is placed at the provider's domain.
     *
     * @generated from rpc ramp.v1.ExchangeService.ConfirmDomainVerification
     */
    confirmDomainVerification: {
      name: "ConfirmDomainVerification",
      I: DomainVerificationConfirmation,
      O: DomainVerificationResult,
      kind: MethodKind.Unary,
    },
  }
} as const;

/**
 * CatalogService — Optional RPC for providers/CMS/third-party intelligence
 * providers to push resource metadata to a Exchange.
 *
 * @generated from service ramp.v1.CatalogService
 */
export const CatalogService = {
  typeName: "ramp.v1.CatalogService",
  methods: {
    /**
     * Push or update resource entries in the Exchange catalog.
     *
     * @generated from rpc ramp.v1.CatalogService.PushResources
     */
    pushResources: {
      name: "PushResources",
      I: PushResourcesRequest,
      O: PushResourcesResponse,
      kind: MethodKind.Unary,
    },
    /**
     * Remove resource entries.
     *
     * @generated from rpc ramp.v1.CatalogService.RemoveResources
     */
    removeResources: {
      name: "RemoveResources",
      I: RemoveResourcesRequest,
      O: RemoveResourcesResponse,
      kind: MethodKind.Unary,
    },
    /**
     * Trigger a full catalog refresh from configured sources.
     *
     * @generated from rpc ramp.v1.CatalogService.RefreshCatalog
     */
    refreshCatalog: {
      name: "RefreshCatalog",
      I: RefreshCatalogRequest,
      O: RefreshCatalogResponse,
      kind: MethodKind.Unary,
    },
  }
} as const;

