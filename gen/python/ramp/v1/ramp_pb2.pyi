import datetime

from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import duration_pb2 as _duration_pb2
from buf.validate import validate_pb2 as _validate_pb2
from ramp.v1 import vocab_pb2 as _vocab_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DiscoveryMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DISCOVERY_METHOD_UNSPECIFIED: _ClassVar[DiscoveryMethod]
    DISCOVERY_METHOD_EXCHANGE: _ClassVar[DiscoveryMethod]
    DISCOVERY_METHOD_SEARCH: _ClassVar[DiscoveryMethod]
    DISCOVERY_METHOD_RECOMMENDATION: _ClassVar[DiscoveryMethod]
    DISCOVERY_METHOD_SYNDICATION: _ClassVar[DiscoveryMethod]

class OfferAbsenceReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OFFER_ABSENCE_REASON_UNSPECIFIED: _ClassVar[OfferAbsenceReason]
    OFFER_ABSENCE_REASON_NOT_IN_CATALOG: _ClassVar[OfferAbsenceReason]
    OFFER_ABSENCE_REASON_CONTENT_BLOCKED: _ClassVar[OfferAbsenceReason]
    OFFER_ABSENCE_REASON_RESTRICTION_FILTERED: _ClassVar[OfferAbsenceReason]
    OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE: _ClassVar[OfferAbsenceReason]
    OFFER_ABSENCE_REASON_NOT_AUTHORIZED: _ClassVar[OfferAbsenceReason]
    OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT: _ClassVar[OfferAbsenceReason]
    OFFER_ABSENCE_REASON_UNKNOWN_CRITICAL_EXTENSION: _ClassVar[OfferAbsenceReason]

class TermSemantics(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TERM_SEMANTICS_UNSPECIFIED: _ClassVar[TermSemantics]
    TERM_SEMANTICS_ENUMERATED: _ClassVar[TermSemantics]
    TERM_SEMANTICS_REFERENCE_ONLY: _ClassVar[TermSemantics]

class RestrictionKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESTRICTION_KIND_UNSPECIFIED: _ClassVar[RestrictionKind]
    RESTRICTION_KIND_FUNCTION: _ClassVar[RestrictionKind]
    RESTRICTION_KIND_GEOGRAPHY: _ClassVar[RestrictionKind]
    RESTRICTION_KIND_USER_TYPE: _ClassVar[RestrictionKind]
    RESTRICTION_KIND_OTHER: _ClassVar[RestrictionKind]

class QuotaWindow(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    QUOTA_WINDOW_UNSPECIFIED: _ClassVar[QuotaWindow]
    QUOTA_WINDOW_HOURLY: _ClassVar[QuotaWindow]
    QUOTA_WINDOW_DAILY: _ClassVar[QuotaWindow]
    QUOTA_WINDOW_MONTHLY: _ClassVar[QuotaWindow]
    QUOTA_WINDOW_TOTAL: _ClassVar[QuotaWindow]

class ObligationKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OBLIGATION_KIND_UNSPECIFIED: _ClassVar[ObligationKind]
    OBLIGATION_KIND_ATTRIBUTION: _ClassVar[ObligationKind]
    OBLIGATION_KIND_CONTRIBUTION: _ClassVar[ObligationKind]
    OBLIGATION_KIND_SHARE_ALIKE: _ClassVar[ObligationKind]
    OBLIGATION_KIND_NETWORK_COPYLEFT: _ClassVar[ObligationKind]
    OBLIGATION_KIND_NOTICE: _ClassVar[ObligationKind]
    OBLIGATION_KIND_OTHER: _ClassVar[ObligationKind]

class ObligationTrigger(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OBLIGATION_TRIGGER_UNSPECIFIED: _ClassVar[ObligationTrigger]
    OBLIGATION_TRIGGER_ON_USE: _ClassVar[ObligationTrigger]
    OBLIGATION_TRIGGER_ON_DISTRIBUTION: _ClassVar[ObligationTrigger]
    OBLIGATION_TRIGGER_ON_NETWORK_SERVICE: _ClassVar[ObligationTrigger]
    OBLIGATION_TRIGGER_ON_DERIVATIVE: _ClassVar[ObligationTrigger]

class PricingModel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PRICING_MODEL_UNSPECIFIED: _ClassVar[PricingModel]
    PRICING_MODEL_FREE: _ClassVar[PricingModel]
    PRICING_MODEL_PER_UNIT: _ClassVar[PricingModel]
    PRICING_MODEL_FLAT: _ClassVar[PricingModel]

class PricingMetering(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PRICING_METERING_ONLINE: _ClassVar[PricingMetering]
    PRICING_METERING_NONE: _ClassVar[PricingMetering]
    PRICING_METERING_OFFLINE_SELF_REPORTED: _ClassVar[PricingMetering]

class DeliveryMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DELIVERY_METHOD_UNSPECIFIED: _ClassVar[DeliveryMethod]
    DELIVERY_METHOD_DIRECT: _ClassVar[DeliveryMethod]
    DELIVERY_METHOD_INSTRUCTIONS: _ClassVar[DeliveryMethod]
    DELIVERY_METHOD_STREAMING: _ClassVar[DeliveryMethod]

class RequesterType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REQUESTER_TYPE_UNSPECIFIED: _ClassVar[RequesterType]
    REQUESTER_TYPE_AGENT: _ClassVar[RequesterType]
    REQUESTER_TYPE_HUMAN_TOOL: _ClassVar[RequesterType]
    REQUESTER_TYPE_SERVICE: _ClassVar[RequesterType]
    REQUESTER_TYPE_DELEGATED: _ClassVar[RequesterType]
    REQUESTER_TYPE_RESEARCH: _ClassVar[RequesterType]

class C2PAStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    C2PA_STATUS_UNSPECIFIED: _ClassVar[C2PAStatus]
    C2PA_STATUS_TRUSTED: _ClassVar[C2PAStatus]
    C2PA_STATUS_VALID: _ClassVar[C2PAStatus]
    C2PA_STATUS_INVALID: _ClassVar[C2PAStatus]
    C2PA_STATUS_ABSENT: _ClassVar[C2PAStatus]

class ResourceMutability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESOURCE_MUTABILITY_UNSPECIFIED: _ClassVar[ResourceMutability]
    RESOURCE_MUTABILITY_STATIC: _ClassVar[ResourceMutability]
    RESOURCE_MUTABILITY_DYNAMIC: _ClassVar[ResourceMutability]
    RESOURCE_MUTABILITY_LIVE: _ClassVar[ResourceMutability]

class DenialReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DENIAL_REASON_UNSPECIFIED: _ClassVar[DenialReason]
    DENIAL_REASON_BILLING_REF_INACTIVE: _ClassVar[DenialReason]
    DENIAL_REASON_INSUFFICIENT_BALANCE: _ClassVar[DenialReason]
    DENIAL_REASON_RATE_LIMITED: _ClassVar[DenialReason]
    DENIAL_REASON_CONTENT_UNAVAILABLE: _ClassVar[DenialReason]
    DENIAL_REASON_RESTRICTION_NOT_SATISFIED: _ClassVar[DenialReason]
    DENIAL_REASON_REPORTING_OVERDUE: _ClassVar[DenialReason]
    DENIAL_REASON_OFFER_EXPIRED: _ClassVar[DenialReason]
    DENIAL_REASON_SIGNATURE_INVALID: _ClassVar[DenialReason]
    DENIAL_REASON_QUOTA_EXCEEDED: _ClassVar[DenialReason]
    DENIAL_REASON_DELEGATION_INVALID: _ClassVar[DenialReason]
    DENIAL_REASON_SCOPE_INSUFFICIENT: _ClassVar[DenialReason]
    DENIAL_REASON_ENTITLEMENT_MISSING: _ClassVar[DenialReason]
    DENIAL_REASON_ENTITLEMENT_MALFORMED: _ClassVar[DenialReason]
    DENIAL_REASON_ENTITLEMENT_EXPIRED: _ClassVar[DenialReason]
    DENIAL_REASON_ENTITLEMENT_WRONG_BUYER: _ClassVar[DenialReason]
    DENIAL_REASON_SUBSCRIPTION_LAPSED: _ClassVar[DenialReason]
    DENIAL_REASON_ENTITLEMENT_NOT_GRANTED: _ClassVar[DenialReason]
    DENIAL_REASON_ENTITLEMENT_STALE_ATTENUATION: _ClassVar[DenialReason]

class IngestionSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INGESTION_SOURCE_UNSPECIFIED: _ClassVar[IngestionSource]
    INGESTION_SOURCE_RAMP_SITEMAP: _ClassVar[IngestionSource]
    INGESTION_SOURCE_RSL: _ClassVar[IngestionSource]
    INGESTION_SOURCE_SITEMAP: _ClassVar[IngestionSource]
    INGESTION_SOURCE_HTML_CRAWL: _ClassVar[IngestionSource]
    INGESTION_SOURCE_CMS_API: _ClassVar[IngestionSource]
    INGESTION_SOURCE_MANUAL: _ClassVar[IngestionSource]
    INGESTION_SOURCE_CATALOG_API: _ClassVar[IngestionSource]

class CitationFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CITATION_FORMAT_LINK: _ClassVar[CitationFormat]
    CITATION_FORMAT_FOOTNOTE: _ClassVar[CitationFormat]
    CITATION_FORMAT_INLINE: _ClassVar[CitationFormat]

class Role(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ROLE_UNSPECIFIED: _ClassVar[Role]
    ROLE_AGENT: _ClassVar[Role]
    ROLE_EXCHANGE: _ClassVar[Role]
    ROLE_BROKER: _ClassVar[Role]
    ROLE_PUBLISHER: _ClassVar[Role]

class ProviderRelationship(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROVIDER_RELATIONSHIP_UNSPECIFIED: _ClassVar[ProviderRelationship]
    PROVIDER_RELATIONSHIP_DIRECT: _ClassVar[ProviderRelationship]
    PROVIDER_RELATIONSHIP_RESELLER: _ClassVar[ProviderRelationship]

class AuthMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUTH_METHOD_UNSPECIFIED: _ClassVar[AuthMethod]
    AUTH_METHOD_GNAP: _ClassVar[AuthMethod]
    AUTH_METHOD_OAUTH_DPOP: _ClassVar[AuthMethod]
    AUTH_METHOD_OAUTH_BEARER: _ClassVar[AuthMethod]
    AUTH_METHOD_OAUTH_MTLS: _ClassVar[AuthMethod]

class DisputeReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DISPUTE_REASON_UNSPECIFIED: _ClassVar[DisputeReason]
    DISPUTE_REASON_CONTENT_MISMATCH: _ClassVar[DisputeReason]
    DISPUTE_REASON_DELIVERY_FAILED: _ClassVar[DisputeReason]
    DISPUTE_REASON_WRONG_CONTENT: _ClassVar[DisputeReason]
    DISPUTE_REASON_EXPIRED_BEFORE_FETCH: _ClassVar[DisputeReason]
    DISPUTE_REASON_INCOMPLETE_CONTENT: _ClassVar[DisputeReason]

class DisputeStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DISPUTE_STATUS_UNSPECIFIED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_FILED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_AUTO_RESOLVED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_EVIDENCE_NEEDED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_UNDER_REVIEW: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_ESCALATED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_RESOLVED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_APPEALED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_SETTLED: _ClassVar[DisputeStatus]
    DISPUTE_STATUS_FINAL: _ClassVar[DisputeStatus]

class ResolutionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESOLUTION_TYPE_UNSPECIFIED: _ClassVar[ResolutionType]
    RESOLUTION_TYPE_CREDIT: _ClassVar[ResolutionType]
    RESOLUTION_TYPE_REDELIVERY: _ClassVar[ResolutionType]
    RESOLUTION_TYPE_REJECTED: _ClassVar[ResolutionType]
    RESOLUTION_TYPE_INVESTIGATION: _ClassVar[ResolutionType]

class CatalogRejectionReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CATALOG_REJECTION_REASON_UNSPECIFIED: _ClassVar[CatalogRejectionReason]
    CATALOG_REJECTION_REASON_NOT_CATALOG_CONTRIBUTOR: _ClassVar[CatalogRejectionReason]
    CATALOG_REJECTION_REASON_TENANT_MISMATCH: _ClassVar[CatalogRejectionReason]
    CATALOG_REJECTION_REASON_DOMAIN_NOT_VERIFIED: _ClassVar[CatalogRejectionReason]
    CATALOG_REJECTION_REASON_SIGNATURE_INVALID: _ClassVar[CatalogRejectionReason]
    CATALOG_REJECTION_REASON_MALFORMED_ENTRY: _ClassVar[CatalogRejectionReason]
    CATALOG_REJECTION_REASON_UNKNOWN_VOCAB_TOKEN: _ClassVar[CatalogRejectionReason]
    CATALOG_REJECTION_REASON_QUOTA_EXCEEDED: _ClassVar[CatalogRejectionReason]

class RegistrationFailureReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REGISTRATION_FAILURE_REASON_UNSPECIFIED: _ClassVar[RegistrationFailureReason]
    REGISTRATION_FAILURE_REASON_DOMAIN_NOT_VERIFIED: _ClassVar[RegistrationFailureReason]
    REGISTRATION_FAILURE_REASON_INVALID_KEY: _ClassVar[RegistrationFailureReason]
    REGISTRATION_FAILURE_REASON_SIGNATURE_INVALID: _ClassVar[RegistrationFailureReason]
    REGISTRATION_FAILURE_REASON_ALREADY_REGISTERED: _ClassVar[RegistrationFailureReason]
    REGISTRATION_FAILURE_REASON_QUOTA_EXCEEDED: _ClassVar[RegistrationFailureReason]

class DisputeFailureReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DISPUTE_FAILURE_REASON_UNSPECIFIED: _ClassVar[DisputeFailureReason]
    DISPUTE_FAILURE_REASON_TRANSACTION_NOT_FOUND: _ClassVar[DisputeFailureReason]
    DISPUTE_FAILURE_REASON_REPORT_NOT_FILED: _ClassVar[DisputeFailureReason]
    DISPUTE_FAILURE_REASON_WINDOW_EXPIRED: _ClassVar[DisputeFailureReason]
    DISPUTE_FAILURE_REASON_DUPLICATE: _ClassVar[DisputeFailureReason]
    DISPUTE_FAILURE_REASON_INELIGIBLE: _ClassVar[DisputeFailureReason]

class DomainVerificationFailureReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DOMAIN_VERIFICATION_FAILURE_REASON_UNSPECIFIED: _ClassVar[DomainVerificationFailureReason]
    DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_NOT_FOUND: _ClassVar[DomainVerificationFailureReason]
    DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_MISMATCH: _ClassVar[DomainVerificationFailureReason]
    DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_EXPIRED: _ClassVar[DomainVerificationFailureReason]
    DOMAIN_VERIFICATION_FAILURE_REASON_FETCH_FAILED: _ClassVar[DomainVerificationFailureReason]
    DOMAIN_VERIFICATION_FAILURE_REASON_EXCHANGE_NOT_AUTHORIZED: _ClassVar[DomainVerificationFailureReason]
    DOMAIN_VERIFICATION_FAILURE_REASON_KEY_REGISTRATION_FAILED: _ClassVar[DomainVerificationFailureReason]

class RetrievalAuthFailureReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RETRIEVAL_AUTH_FAILURE_REASON_UNSPECIFIED: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_AGENT_KEY_MISSING: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_MISSING: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_CREATED_MISSING: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRY_MISSING: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED: _ClassVar[RetrievalAuthFailureReason]
    RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_INVALID: _ClassVar[RetrievalAuthFailureReason]

class UsageReportRejectionReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    USAGE_REPORT_REJECTION_REASON_UNSPECIFIED: _ClassVar[UsageReportRejectionReason]
    USAGE_REPORT_REJECTION_REASON_TRANSACTION_NOT_FOUND: _ClassVar[UsageReportRejectionReason]
    USAGE_REPORT_REJECTION_REASON_DUPLICATE: _ClassVar[UsageReportRejectionReason]
    USAGE_REPORT_REJECTION_REASON_WINDOW_EXPIRED: _ClassVar[UsageReportRejectionReason]
    USAGE_REPORT_REJECTION_REASON_MISSING_REQUIRED_FIELDS: _ClassVar[UsageReportRejectionReason]
    USAGE_REPORT_REJECTION_REASON_MALFORMED: _ClassVar[UsageReportRejectionReason]
DISCOVERY_METHOD_UNSPECIFIED: DiscoveryMethod
DISCOVERY_METHOD_EXCHANGE: DiscoveryMethod
DISCOVERY_METHOD_SEARCH: DiscoveryMethod
DISCOVERY_METHOD_RECOMMENDATION: DiscoveryMethod
DISCOVERY_METHOD_SYNDICATION: DiscoveryMethod
OFFER_ABSENCE_REASON_UNSPECIFIED: OfferAbsenceReason
OFFER_ABSENCE_REASON_NOT_IN_CATALOG: OfferAbsenceReason
OFFER_ABSENCE_REASON_CONTENT_BLOCKED: OfferAbsenceReason
OFFER_ABSENCE_REASON_RESTRICTION_FILTERED: OfferAbsenceReason
OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE: OfferAbsenceReason
OFFER_ABSENCE_REASON_NOT_AUTHORIZED: OfferAbsenceReason
OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT: OfferAbsenceReason
OFFER_ABSENCE_REASON_UNKNOWN_CRITICAL_EXTENSION: OfferAbsenceReason
TERM_SEMANTICS_UNSPECIFIED: TermSemantics
TERM_SEMANTICS_ENUMERATED: TermSemantics
TERM_SEMANTICS_REFERENCE_ONLY: TermSemantics
RESTRICTION_KIND_UNSPECIFIED: RestrictionKind
RESTRICTION_KIND_FUNCTION: RestrictionKind
RESTRICTION_KIND_GEOGRAPHY: RestrictionKind
RESTRICTION_KIND_USER_TYPE: RestrictionKind
RESTRICTION_KIND_OTHER: RestrictionKind
QUOTA_WINDOW_UNSPECIFIED: QuotaWindow
QUOTA_WINDOW_HOURLY: QuotaWindow
QUOTA_WINDOW_DAILY: QuotaWindow
QUOTA_WINDOW_MONTHLY: QuotaWindow
QUOTA_WINDOW_TOTAL: QuotaWindow
OBLIGATION_KIND_UNSPECIFIED: ObligationKind
OBLIGATION_KIND_ATTRIBUTION: ObligationKind
OBLIGATION_KIND_CONTRIBUTION: ObligationKind
OBLIGATION_KIND_SHARE_ALIKE: ObligationKind
OBLIGATION_KIND_NETWORK_COPYLEFT: ObligationKind
OBLIGATION_KIND_NOTICE: ObligationKind
OBLIGATION_KIND_OTHER: ObligationKind
OBLIGATION_TRIGGER_UNSPECIFIED: ObligationTrigger
OBLIGATION_TRIGGER_ON_USE: ObligationTrigger
OBLIGATION_TRIGGER_ON_DISTRIBUTION: ObligationTrigger
OBLIGATION_TRIGGER_ON_NETWORK_SERVICE: ObligationTrigger
OBLIGATION_TRIGGER_ON_DERIVATIVE: ObligationTrigger
PRICING_MODEL_UNSPECIFIED: PricingModel
PRICING_MODEL_FREE: PricingModel
PRICING_MODEL_PER_UNIT: PricingModel
PRICING_MODEL_FLAT: PricingModel
PRICING_METERING_ONLINE: PricingMetering
PRICING_METERING_NONE: PricingMetering
PRICING_METERING_OFFLINE_SELF_REPORTED: PricingMetering
DELIVERY_METHOD_UNSPECIFIED: DeliveryMethod
DELIVERY_METHOD_DIRECT: DeliveryMethod
DELIVERY_METHOD_INSTRUCTIONS: DeliveryMethod
DELIVERY_METHOD_STREAMING: DeliveryMethod
REQUESTER_TYPE_UNSPECIFIED: RequesterType
REQUESTER_TYPE_AGENT: RequesterType
REQUESTER_TYPE_HUMAN_TOOL: RequesterType
REQUESTER_TYPE_SERVICE: RequesterType
REQUESTER_TYPE_DELEGATED: RequesterType
REQUESTER_TYPE_RESEARCH: RequesterType
C2PA_STATUS_UNSPECIFIED: C2PAStatus
C2PA_STATUS_TRUSTED: C2PAStatus
C2PA_STATUS_VALID: C2PAStatus
C2PA_STATUS_INVALID: C2PAStatus
C2PA_STATUS_ABSENT: C2PAStatus
RESOURCE_MUTABILITY_UNSPECIFIED: ResourceMutability
RESOURCE_MUTABILITY_STATIC: ResourceMutability
RESOURCE_MUTABILITY_DYNAMIC: ResourceMutability
RESOURCE_MUTABILITY_LIVE: ResourceMutability
DENIAL_REASON_UNSPECIFIED: DenialReason
DENIAL_REASON_BILLING_REF_INACTIVE: DenialReason
DENIAL_REASON_INSUFFICIENT_BALANCE: DenialReason
DENIAL_REASON_RATE_LIMITED: DenialReason
DENIAL_REASON_CONTENT_UNAVAILABLE: DenialReason
DENIAL_REASON_RESTRICTION_NOT_SATISFIED: DenialReason
DENIAL_REASON_REPORTING_OVERDUE: DenialReason
DENIAL_REASON_OFFER_EXPIRED: DenialReason
DENIAL_REASON_SIGNATURE_INVALID: DenialReason
DENIAL_REASON_QUOTA_EXCEEDED: DenialReason
DENIAL_REASON_DELEGATION_INVALID: DenialReason
DENIAL_REASON_SCOPE_INSUFFICIENT: DenialReason
DENIAL_REASON_ENTITLEMENT_MISSING: DenialReason
DENIAL_REASON_ENTITLEMENT_MALFORMED: DenialReason
DENIAL_REASON_ENTITLEMENT_EXPIRED: DenialReason
DENIAL_REASON_ENTITLEMENT_WRONG_BUYER: DenialReason
DENIAL_REASON_SUBSCRIPTION_LAPSED: DenialReason
DENIAL_REASON_ENTITLEMENT_NOT_GRANTED: DenialReason
DENIAL_REASON_ENTITLEMENT_STALE_ATTENUATION: DenialReason
INGESTION_SOURCE_UNSPECIFIED: IngestionSource
INGESTION_SOURCE_RAMP_SITEMAP: IngestionSource
INGESTION_SOURCE_RSL: IngestionSource
INGESTION_SOURCE_SITEMAP: IngestionSource
INGESTION_SOURCE_HTML_CRAWL: IngestionSource
INGESTION_SOURCE_CMS_API: IngestionSource
INGESTION_SOURCE_MANUAL: IngestionSource
INGESTION_SOURCE_CATALOG_API: IngestionSource
CITATION_FORMAT_LINK: CitationFormat
CITATION_FORMAT_FOOTNOTE: CitationFormat
CITATION_FORMAT_INLINE: CitationFormat
ROLE_UNSPECIFIED: Role
ROLE_AGENT: Role
ROLE_EXCHANGE: Role
ROLE_BROKER: Role
ROLE_PUBLISHER: Role
PROVIDER_RELATIONSHIP_UNSPECIFIED: ProviderRelationship
PROVIDER_RELATIONSHIP_DIRECT: ProviderRelationship
PROVIDER_RELATIONSHIP_RESELLER: ProviderRelationship
AUTH_METHOD_UNSPECIFIED: AuthMethod
AUTH_METHOD_GNAP: AuthMethod
AUTH_METHOD_OAUTH_DPOP: AuthMethod
AUTH_METHOD_OAUTH_BEARER: AuthMethod
AUTH_METHOD_OAUTH_MTLS: AuthMethod
DISPUTE_REASON_UNSPECIFIED: DisputeReason
DISPUTE_REASON_CONTENT_MISMATCH: DisputeReason
DISPUTE_REASON_DELIVERY_FAILED: DisputeReason
DISPUTE_REASON_WRONG_CONTENT: DisputeReason
DISPUTE_REASON_EXPIRED_BEFORE_FETCH: DisputeReason
DISPUTE_REASON_INCOMPLETE_CONTENT: DisputeReason
DISPUTE_STATUS_UNSPECIFIED: DisputeStatus
DISPUTE_STATUS_FILED: DisputeStatus
DISPUTE_STATUS_AUTO_RESOLVED: DisputeStatus
DISPUTE_STATUS_EVIDENCE_NEEDED: DisputeStatus
DISPUTE_STATUS_UNDER_REVIEW: DisputeStatus
DISPUTE_STATUS_ESCALATED: DisputeStatus
DISPUTE_STATUS_RESOLVED: DisputeStatus
DISPUTE_STATUS_APPEALED: DisputeStatus
DISPUTE_STATUS_SETTLED: DisputeStatus
DISPUTE_STATUS_FINAL: DisputeStatus
RESOLUTION_TYPE_UNSPECIFIED: ResolutionType
RESOLUTION_TYPE_CREDIT: ResolutionType
RESOLUTION_TYPE_REDELIVERY: ResolutionType
RESOLUTION_TYPE_REJECTED: ResolutionType
RESOLUTION_TYPE_INVESTIGATION: ResolutionType
CATALOG_REJECTION_REASON_UNSPECIFIED: CatalogRejectionReason
CATALOG_REJECTION_REASON_NOT_CATALOG_CONTRIBUTOR: CatalogRejectionReason
CATALOG_REJECTION_REASON_TENANT_MISMATCH: CatalogRejectionReason
CATALOG_REJECTION_REASON_DOMAIN_NOT_VERIFIED: CatalogRejectionReason
CATALOG_REJECTION_REASON_SIGNATURE_INVALID: CatalogRejectionReason
CATALOG_REJECTION_REASON_MALFORMED_ENTRY: CatalogRejectionReason
CATALOG_REJECTION_REASON_UNKNOWN_VOCAB_TOKEN: CatalogRejectionReason
CATALOG_REJECTION_REASON_QUOTA_EXCEEDED: CatalogRejectionReason
REGISTRATION_FAILURE_REASON_UNSPECIFIED: RegistrationFailureReason
REGISTRATION_FAILURE_REASON_DOMAIN_NOT_VERIFIED: RegistrationFailureReason
REGISTRATION_FAILURE_REASON_INVALID_KEY: RegistrationFailureReason
REGISTRATION_FAILURE_REASON_SIGNATURE_INVALID: RegistrationFailureReason
REGISTRATION_FAILURE_REASON_ALREADY_REGISTERED: RegistrationFailureReason
REGISTRATION_FAILURE_REASON_QUOTA_EXCEEDED: RegistrationFailureReason
DISPUTE_FAILURE_REASON_UNSPECIFIED: DisputeFailureReason
DISPUTE_FAILURE_REASON_TRANSACTION_NOT_FOUND: DisputeFailureReason
DISPUTE_FAILURE_REASON_REPORT_NOT_FILED: DisputeFailureReason
DISPUTE_FAILURE_REASON_WINDOW_EXPIRED: DisputeFailureReason
DISPUTE_FAILURE_REASON_DUPLICATE: DisputeFailureReason
DISPUTE_FAILURE_REASON_INELIGIBLE: DisputeFailureReason
DOMAIN_VERIFICATION_FAILURE_REASON_UNSPECIFIED: DomainVerificationFailureReason
DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_NOT_FOUND: DomainVerificationFailureReason
DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_MISMATCH: DomainVerificationFailureReason
DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_EXPIRED: DomainVerificationFailureReason
DOMAIN_VERIFICATION_FAILURE_REASON_FETCH_FAILED: DomainVerificationFailureReason
DOMAIN_VERIFICATION_FAILURE_REASON_EXCHANGE_NOT_AUTHORIZED: DomainVerificationFailureReason
DOMAIN_VERIFICATION_FAILURE_REASON_KEY_REGISTRATION_FAILED: DomainVerificationFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_UNSPECIFIED: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_AGENT_KEY_MISSING: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_MISSING: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_PROOF_CREATED_MISSING: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRY_MISSING: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED: RetrievalAuthFailureReason
RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_INVALID: RetrievalAuthFailureReason
USAGE_REPORT_REJECTION_REASON_UNSPECIFIED: UsageReportRejectionReason
USAGE_REPORT_REJECTION_REASON_TRANSACTION_NOT_FOUND: UsageReportRejectionReason
USAGE_REPORT_REJECTION_REASON_DUPLICATE: UsageReportRejectionReason
USAGE_REPORT_REJECTION_REASON_WINDOW_EXPIRED: UsageReportRejectionReason
USAGE_REPORT_REJECTION_REASON_MISSING_REQUIRED_FIELDS: UsageReportRejectionReason
USAGE_REPORT_REJECTION_REASON_MALFORMED: UsageReportRejectionReason

class AcceptableRestriction(_message.Message):
    __slots__ = ("axis", "values")
    AXIS_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    axis: RestrictionKind
    values: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, axis: _Optional[_Union[RestrictionKind, str]] = ..., values: _Optional[_Iterable[str]] = ...) -> None: ...

class ResourceQuery(_message.Message):
    __slots__ = ("ver", "id", "requester", "uris", "acceptable_restrictions", "deadline", "supported_profiles", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    REQUESTER_FIELD_NUMBER: _ClassVar[int]
    URIS_FIELD_NUMBER: _ClassVar[int]
    ACCEPTABLE_RESTRICTIONS_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_PROFILES_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    id: str
    requester: Requester
    uris: _containers.RepeatedScalarFieldContainer[str]
    acceptable_restrictions: _containers.RepeatedCompositeFieldContainer[AcceptableRestriction]
    deadline: _duration_pb2.Duration
    supported_profiles: _containers.RepeatedScalarFieldContainer[str]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., id: _Optional[str] = ..., requester: _Optional[_Union[Requester, _Mapping]] = ..., uris: _Optional[_Iterable[str]] = ..., acceptable_restrictions: _Optional[_Iterable[_Union[AcceptableRestriction, _Mapping]]] = ..., deadline: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., supported_profiles: _Optional[_Iterable[str]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class ResourceResponse(_message.Message):
    __slots__ = ("ver", "exchange", "offers", "offer_groups", "rate_limit", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    EXCHANGE_FIELD_NUMBER: _ClassVar[int]
    OFFERS_FIELD_NUMBER: _ClassVar[int]
    OFFER_GROUPS_FIELD_NUMBER: _ClassVar[int]
    RATE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    exchange: str
    offers: _containers.RepeatedCompositeFieldContainer[Offer]
    offer_groups: _containers.RepeatedCompositeFieldContainer[OfferGroup]
    rate_limit: RateLimitInfo
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., exchange: _Optional[str] = ..., offers: _Optional[_Iterable[_Union[Offer, _Mapping]]] = ..., offer_groups: _Optional[_Iterable[_Union[OfferGroup, _Mapping]]] = ..., rate_limit: _Optional[_Union[RateLimitInfo, _Mapping]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class OfferGroup(_message.Message):
    __slots__ = ("uri", "offers", "discovery_method", "absence_reason", "restriction_filters")
    URI_FIELD_NUMBER: _ClassVar[int]
    OFFERS_FIELD_NUMBER: _ClassVar[int]
    DISCOVERY_METHOD_FIELD_NUMBER: _ClassVar[int]
    ABSENCE_REASON_FIELD_NUMBER: _ClassVar[int]
    RESTRICTION_FILTERS_FIELD_NUMBER: _ClassVar[int]
    uri: str
    offers: _containers.RepeatedCompositeFieldContainer[Offer]
    discovery_method: DiscoveryMethod
    absence_reason: OfferAbsenceReason
    restriction_filters: _containers.RepeatedScalarFieldContainer[RestrictionKind]
    def __init__(self, uri: _Optional[str] = ..., offers: _Optional[_Iterable[_Union[Offer, _Mapping]]] = ..., discovery_method: _Optional[_Union[DiscoveryMethod, str]] = ..., absence_reason: _Optional[_Union[OfferAbsenceReason, str]] = ..., restriction_filters: _Optional[_Iterable[_Union[RestrictionKind, str]]] = ...) -> None: ...

class RateLimitInfo(_message.Message):
    __slots__ = ("limit", "remaining", "reset_at", "window")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    REMAINING_FIELD_NUMBER: _ClassVar[int]
    RESET_AT_FIELD_NUMBER: _ClassVar[int]
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    limit: int
    remaining: int
    reset_at: _timestamp_pb2.Timestamp
    window: _duration_pb2.Duration
    def __init__(self, limit: _Optional[int] = ..., remaining: _Optional[int] = ..., reset_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., window: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class SubscriptionQuotaInfo(_message.Message):
    __slots__ = ("subscription_id", "quota_limit", "quota_used", "quota_remaining", "resets_at", "unit")
    SUBSCRIPTION_ID_FIELD_NUMBER: _ClassVar[int]
    QUOTA_LIMIT_FIELD_NUMBER: _ClassVar[int]
    QUOTA_USED_FIELD_NUMBER: _ClassVar[int]
    QUOTA_REMAINING_FIELD_NUMBER: _ClassVar[int]
    RESETS_AT_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    subscription_id: str
    quota_limit: int
    quota_used: int
    quota_remaining: int
    resets_at: _timestamp_pb2.Timestamp
    unit: str
    def __init__(self, subscription_id: _Optional[str] = ..., quota_limit: _Optional[int] = ..., quota_used: _Optional[int] = ..., quota_remaining: _Optional[int] = ..., resets_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., unit: _Optional[str] = ...) -> None: ...

class Offer(_message.Message):
    __slots__ = ("offer_id", "title", "pricing", "delivery_method", "reporting", "expires_at", "identity", "signature", "signature_algorithm", "subscription_id", "iab_categories", "attestations", "data_as_of", "subscription_quota", "previews", "terms", "ext", "ext_critical")
    OFFER_ID_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    PRICING_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_METHOD_FIELD_NUMBER: _ClassVar[int]
    REPORTING_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTION_ID_FIELD_NUMBER: _ClassVar[int]
    IAB_CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    ATTESTATIONS_FIELD_NUMBER: _ClassVar[int]
    DATA_AS_OF_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTION_QUOTA_FIELD_NUMBER: _ClassVar[int]
    PREVIEWS_FIELD_NUMBER: _ClassVar[int]
    TERMS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    offer_id: str
    title: str
    pricing: Pricing
    delivery_method: DeliveryMethod
    reporting: ReportingObligation
    expires_at: _timestamp_pb2.Timestamp
    identity: ResourceIdentity
    signature: str
    signature_algorithm: str
    subscription_id: str
    iab_categories: _containers.RepeatedScalarFieldContainer[str]
    attestations: _containers.RepeatedCompositeFieldContainer[ResourceAttestation]
    data_as_of: _timestamp_pb2.Timestamp
    subscription_quota: _containers.RepeatedCompositeFieldContainer[SubscriptionQuotaInfo]
    previews: _containers.RepeatedCompositeFieldContainer[Preview]
    terms: _containers.RepeatedCompositeFieldContainer[LicenseTerm]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, offer_id: _Optional[str] = ..., title: _Optional[str] = ..., pricing: _Optional[_Union[Pricing, _Mapping]] = ..., delivery_method: _Optional[_Union[DeliveryMethod, str]] = ..., reporting: _Optional[_Union[ReportingObligation, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., identity: _Optional[_Union[ResourceIdentity, _Mapping]] = ..., signature: _Optional[str] = ..., signature_algorithm: _Optional[str] = ..., subscription_id: _Optional[str] = ..., iab_categories: _Optional[_Iterable[str]] = ..., attestations: _Optional[_Iterable[_Union[ResourceAttestation, _Mapping]]] = ..., data_as_of: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., subscription_quota: _Optional[_Iterable[_Union[SubscriptionQuotaInfo, _Mapping]]] = ..., previews: _Optional[_Iterable[_Union[Preview, _Mapping]]] = ..., terms: _Optional[_Iterable[_Union[LicenseTerm, _Mapping]]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class ResourceIdentity(_message.Message):
    __slots__ = ("canonical_url", "doi", "iptc_guid", "isni", "content_hash", "hash_method", "resource_mutability", "c2pa_manifest", "c2pa_status", "soft_binding", "soft_binding_method", "ext", "ext_critical")
    CANONICAL_URL_FIELD_NUMBER: _ClassVar[int]
    DOI_FIELD_NUMBER: _ClassVar[int]
    IPTC_GUID_FIELD_NUMBER: _ClassVar[int]
    ISNI_FIELD_NUMBER: _ClassVar[int]
    CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    HASH_METHOD_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_MUTABILITY_FIELD_NUMBER: _ClassVar[int]
    C2PA_MANIFEST_FIELD_NUMBER: _ClassVar[int]
    C2PA_STATUS_FIELD_NUMBER: _ClassVar[int]
    SOFT_BINDING_FIELD_NUMBER: _ClassVar[int]
    SOFT_BINDING_METHOD_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    canonical_url: str
    doi: str
    iptc_guid: str
    isni: str
    content_hash: str
    hash_method: str
    resource_mutability: ResourceMutability
    c2pa_manifest: str
    c2pa_status: C2PAStatus
    soft_binding: str
    soft_binding_method: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, canonical_url: _Optional[str] = ..., doi: _Optional[str] = ..., iptc_guid: _Optional[str] = ..., isni: _Optional[str] = ..., content_hash: _Optional[str] = ..., hash_method: _Optional[str] = ..., resource_mutability: _Optional[_Union[ResourceMutability, str]] = ..., c2pa_manifest: _Optional[str] = ..., c2pa_status: _Optional[_Union[C2PAStatus, str]] = ..., soft_binding: _Optional[str] = ..., soft_binding_method: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class ResourceAttestation(_message.Message):
    __slots__ = ("verifier", "kid", "attested_at", "uri", "claims", "signature")
    VERIFIER_FIELD_NUMBER: _ClassVar[int]
    KID_FIELD_NUMBER: _ClassVar[int]
    ATTESTED_AT_FIELD_NUMBER: _ClassVar[int]
    URI_FIELD_NUMBER: _ClassVar[int]
    CLAIMS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    verifier: str
    kid: str
    attested_at: _timestamp_pb2.Timestamp
    uri: str
    claims: _struct_pb2.Struct
    signature: str
    def __init__(self, verifier: _Optional[str] = ..., kid: _Optional[str] = ..., attested_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., uri: _Optional[str] = ..., claims: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., signature: _Optional[str] = ...) -> None: ...

class License(_message.Message):
    __slots__ = ("uri", "id", "name", "immutable", "uri_digest")
    URI_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    IMMUTABLE_FIELD_NUMBER: _ClassVar[int]
    URI_DIGEST_FIELD_NUMBER: _ClassVar[int]
    uri: str
    id: str
    name: str
    immutable: bool
    uri_digest: str
    def __init__(self, uri: _Optional[str] = ..., id: _Optional[str] = ..., name: _Optional[str] = ..., immutable: _Optional[bool] = ..., uri_digest: _Optional[str] = ...) -> None: ...

class Restriction(_message.Message):
    __slots__ = ("kind", "permitted", "prohibited", "advisory")
    KIND_FIELD_NUMBER: _ClassVar[int]
    PERMITTED_FIELD_NUMBER: _ClassVar[int]
    PROHIBITED_FIELD_NUMBER: _ClassVar[int]
    ADVISORY_FIELD_NUMBER: _ClassVar[int]
    kind: RestrictionKind
    permitted: _containers.RepeatedScalarFieldContainer[str]
    prohibited: _containers.RepeatedScalarFieldContainer[str]
    advisory: bool
    def __init__(self, kind: _Optional[_Union[RestrictionKind, str]] = ..., permitted: _Optional[_Iterable[str]] = ..., prohibited: _Optional[_Iterable[str]] = ..., advisory: _Optional[bool] = ...) -> None: ...

class Quota(_message.Message):
    __slots__ = ("metric", "limit", "window")
    METRIC_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    metric: str
    limit: int
    window: QuotaWindow
    def __init__(self, metric: _Optional[str] = ..., limit: _Optional[int] = ..., window: _Optional[_Union[QuotaWindow, str]] = ...) -> None: ...

class Obligation(_message.Message):
    __slots__ = ("kind", "trigger", "scope_license", "detail")
    KIND_FIELD_NUMBER: _ClassVar[int]
    TRIGGER_FIELD_NUMBER: _ClassVar[int]
    SCOPE_LICENSE_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    kind: ObligationKind
    trigger: ObligationTrigger
    scope_license: License
    detail: str
    def __init__(self, kind: _Optional[_Union[ObligationKind, str]] = ..., trigger: _Optional[_Union[ObligationTrigger, str]] = ..., scope_license: _Optional[_Union[License, _Mapping]] = ..., detail: _Optional[str] = ...) -> None: ...

class LicenseTerm(_message.Message):
    __slots__ = ("license", "semantics", "restrictions", "quotas", "obligations", "pricing", "scopes", "part_label")
    LICENSE_FIELD_NUMBER: _ClassVar[int]
    SEMANTICS_FIELD_NUMBER: _ClassVar[int]
    RESTRICTIONS_FIELD_NUMBER: _ClassVar[int]
    QUOTAS_FIELD_NUMBER: _ClassVar[int]
    OBLIGATIONS_FIELD_NUMBER: _ClassVar[int]
    PRICING_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    PART_LABEL_FIELD_NUMBER: _ClassVar[int]
    license: License
    semantics: TermSemantics
    restrictions: _containers.RepeatedCompositeFieldContainer[Restriction]
    quotas: _containers.RepeatedCompositeFieldContainer[Quota]
    obligations: _containers.RepeatedCompositeFieldContainer[Obligation]
    pricing: Pricing
    scopes: _containers.RepeatedScalarFieldContainer[str]
    part_label: str
    def __init__(self, license: _Optional[_Union[License, _Mapping]] = ..., semantics: _Optional[_Union[TermSemantics, str]] = ..., restrictions: _Optional[_Iterable[_Union[Restriction, _Mapping]]] = ..., quotas: _Optional[_Iterable[_Union[Quota, _Mapping]]] = ..., obligations: _Optional[_Iterable[_Union[Obligation, _Mapping]]] = ..., pricing: _Optional[_Union[Pricing, _Mapping]] = ..., scopes: _Optional[_Iterable[str]] = ..., part_label: _Optional[str] = ...) -> None: ...

class Preview(_message.Message):
    __slots__ = ("url", "media_type", "width", "height", "duration", "size")
    URL_FIELD_NUMBER: _ClassVar[int]
    MEDIA_TYPE_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    url: str
    media_type: str
    width: int
    height: int
    duration: int
    size: str
    def __init__(self, url: _Optional[str] = ..., media_type: _Optional[str] = ..., width: _Optional[int] = ..., height: _Optional[int] = ..., duration: _Optional[int] = ..., size: _Optional[str] = ...) -> None: ...

class Pricing(_message.Message):
    __slots__ = ("model", "rate", "currency", "unit_cost", "estimated_quantity", "license_duration_months", "unit", "metering")
    MODEL_FIELD_NUMBER: _ClassVar[int]
    RATE_FIELD_NUMBER: _ClassVar[int]
    CURRENCY_FIELD_NUMBER: _ClassVar[int]
    UNIT_COST_FIELD_NUMBER: _ClassVar[int]
    ESTIMATED_QUANTITY_FIELD_NUMBER: _ClassVar[int]
    LICENSE_DURATION_MONTHS_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    METERING_FIELD_NUMBER: _ClassVar[int]
    model: PricingModel
    rate: float
    currency: str
    unit_cost: float
    estimated_quantity: int
    license_duration_months: int
    unit: str
    metering: PricingMetering
    def __init__(self, model: _Optional[_Union[PricingModel, str]] = ..., rate: _Optional[float] = ..., currency: _Optional[str] = ..., unit_cost: _Optional[float] = ..., estimated_quantity: _Optional[int] = ..., license_duration_months: _Optional[int] = ..., unit: _Optional[str] = ..., metering: _Optional[_Union[PricingMetering, str]] = ...) -> None: ...

class Requester(_message.Message):
    __slots__ = ("id", "domain", "type", "name", "billing_ref", "scopes", "delegation", "ext", "ext_critical")
    ID_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    BILLING_REF_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    DELEGATION_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    id: str
    domain: str
    type: RequesterType
    name: str
    billing_ref: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    delegation: Delegation
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, id: _Optional[str] = ..., domain: _Optional[str] = ..., type: _Optional[_Union[RequesterType, str]] = ..., name: _Optional[str] = ..., billing_ref: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ..., delegation: _Optional[_Union[Delegation, _Mapping]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class Delegation(_message.Message):
    __slots__ = ("principal_domain", "principal_id", "scopes", "expires_at", "max_spend_cents", "max_accesses", "quota_period", "token", "token_format", "revocation_uri", "issuer", "ext", "ext_critical")
    PRINCIPAL_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    MAX_SPEND_CENTS_FIELD_NUMBER: _ClassVar[int]
    MAX_ACCESSES_FIELD_NUMBER: _ClassVar[int]
    QUOTA_PERIOD_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FORMAT_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_URI_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    principal_domain: str
    principal_id: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    expires_at: _timestamp_pb2.Timestamp
    max_spend_cents: int
    max_accesses: int
    quota_period: _duration_pb2.Duration
    token: bytes
    token_format: str
    revocation_uri: str
    issuer: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, principal_domain: _Optional[str] = ..., principal_id: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., max_spend_cents: _Optional[int] = ..., max_accesses: _Optional[int] = ..., quota_period: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., token: _Optional[bytes] = ..., token_format: _Optional[str] = ..., revocation_uri: _Optional[str] = ..., issuer: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class TransactionRequest(_message.Message):
    __slots__ = ("ver", "idempotency_key", "offer_id", "requester", "offer_signature", "items", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    OFFER_ID_FIELD_NUMBER: _ClassVar[int]
    REQUESTER_FIELD_NUMBER: _ClassVar[int]
    OFFER_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    idempotency_key: str
    offer_id: str
    requester: Requester
    offer_signature: str
    items: _containers.RepeatedCompositeFieldContainer[TransactionItem]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., offer_id: _Optional[str] = ..., requester: _Optional[_Union[Requester, _Mapping]] = ..., offer_signature: _Optional[str] = ..., items: _Optional[_Iterable[_Union[TransactionItem, _Mapping]]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class TransactionItem(_message.Message):
    __slots__ = ("offer_id", "offer_signature")
    OFFER_ID_FIELD_NUMBER: _ClassVar[int]
    OFFER_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    offer_id: str
    offer_signature: str
    def __init__(self, offer_id: _Optional[str] = ..., offer_signature: _Optional[str] = ...) -> None: ...

class TransactionResponse(_message.Message):
    __slots__ = ("ver", "transaction_id", "billing_id", "resource_title", "cost", "delivery_method", "reporting_obligation", "expires_at", "agent_identity_hash", "retrieval_endpoint", "subscription_id", "subscription_unit_value", "items", "total_cost", "subscription_quota", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_ID_FIELD_NUMBER: _ClassVar[int]
    BILLING_ID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TITLE_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_METHOD_FIELD_NUMBER: _ClassVar[int]
    REPORTING_OBLIGATION_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    AGENT_IDENTITY_HASH_FIELD_NUMBER: _ClassVar[int]
    RETRIEVAL_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTION_ID_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTION_UNIT_VALUE_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_COST_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTION_QUOTA_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    transaction_id: str
    billing_id: str
    resource_title: str
    cost: Cost
    delivery_method: DeliveryMethod
    reporting_obligation: ReportingObligation
    expires_at: _timestamp_pb2.Timestamp
    agent_identity_hash: str
    retrieval_endpoint: str
    subscription_id: str
    subscription_unit_value: Cost
    items: _containers.RepeatedCompositeFieldContainer[TransactionResultItem]
    total_cost: Cost
    subscription_quota: _containers.RepeatedCompositeFieldContainer[SubscriptionQuotaInfo]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., transaction_id: _Optional[str] = ..., billing_id: _Optional[str] = ..., resource_title: _Optional[str] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ..., delivery_method: _Optional[_Union[DeliveryMethod, str]] = ..., reporting_obligation: _Optional[_Union[ReportingObligation, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., agent_identity_hash: _Optional[str] = ..., retrieval_endpoint: _Optional[str] = ..., subscription_id: _Optional[str] = ..., subscription_unit_value: _Optional[_Union[Cost, _Mapping]] = ..., items: _Optional[_Iterable[_Union[TransactionResultItem, _Mapping]]] = ..., total_cost: _Optional[_Union[Cost, _Mapping]] = ..., subscription_quota: _Optional[_Iterable[_Union[SubscriptionQuotaInfo, _Mapping]]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class TransactionResultItem(_message.Message):
    __slots__ = ("offer_id", "transaction_id", "billing_id", "resource_title", "cost", "subscription_id", "subscription_unit_value", "denial_reason", "restriction_mismatches", "expires_at", "retrieval_endpoint", "delivery_method", "reporting_obligation")
    OFFER_ID_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_ID_FIELD_NUMBER: _ClassVar[int]
    BILLING_ID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TITLE_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTION_ID_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTION_UNIT_VALUE_FIELD_NUMBER: _ClassVar[int]
    DENIAL_REASON_FIELD_NUMBER: _ClassVar[int]
    RESTRICTION_MISMATCHES_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    RETRIEVAL_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_METHOD_FIELD_NUMBER: _ClassVar[int]
    REPORTING_OBLIGATION_FIELD_NUMBER: _ClassVar[int]
    offer_id: str
    transaction_id: str
    billing_id: str
    resource_title: str
    cost: Cost
    subscription_id: str
    subscription_unit_value: Cost
    denial_reason: DenialReason
    restriction_mismatches: _containers.RepeatedScalarFieldContainer[RestrictionKind]
    expires_at: _timestamp_pb2.Timestamp
    retrieval_endpoint: str
    delivery_method: DeliveryMethod
    reporting_obligation: ReportingObligation
    def __init__(self, offer_id: _Optional[str] = ..., transaction_id: _Optional[str] = ..., billing_id: _Optional[str] = ..., resource_title: _Optional[str] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ..., subscription_id: _Optional[str] = ..., subscription_unit_value: _Optional[_Union[Cost, _Mapping]] = ..., denial_reason: _Optional[_Union[DenialReason, str]] = ..., restriction_mismatches: _Optional[_Iterable[_Union[RestrictionKind, str]]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., retrieval_endpoint: _Optional[str] = ..., delivery_method: _Optional[_Union[DeliveryMethod, str]] = ..., reporting_obligation: _Optional[_Union[ReportingObligation, _Mapping]] = ...) -> None: ...

class Cost(_message.Message):
    __slots__ = ("amount", "currency", "unit_cost")
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    CURRENCY_FIELD_NUMBER: _ClassVar[int]
    UNIT_COST_FIELD_NUMBER: _ClassVar[int]
    amount: float
    currency: str
    unit_cost: float
    def __init__(self, amount: _Optional[float] = ..., currency: _Optional[str] = ..., unit_cost: _Optional[float] = ...) -> None: ...

class PushResourcesRequest(_message.Message):
    __slots__ = ("ver", "tenant_id", "entries", "caller_id", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    CALLER_ID_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    tenant_id: str
    entries: _containers.RepeatedCompositeFieldContainer[ResourceEntry]
    caller_id: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., tenant_id: _Optional[str] = ..., entries: _Optional[_Iterable[_Union[ResourceEntry, _Mapping]]] = ..., caller_id: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class ResourceEntry(_message.Message):
    __slots__ = ("domain", "path", "content_id", "title", "word_count", "estimated_quantity", "content_hash", "hash_method", "source", "provenance_source", "provenance_timestamp", "attestations", "terms", "ext", "ext_critical")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    CONTENT_ID_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    WORD_COUNT_FIELD_NUMBER: _ClassVar[int]
    ESTIMATED_QUANTITY_FIELD_NUMBER: _ClassVar[int]
    CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    HASH_METHOD_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ATTESTATIONS_FIELD_NUMBER: _ClassVar[int]
    TERMS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    domain: str
    path: str
    content_id: str
    title: str
    word_count: int
    estimated_quantity: int
    content_hash: str
    hash_method: str
    source: IngestionSource
    provenance_source: str
    provenance_timestamp: _timestamp_pb2.Timestamp
    attestations: _containers.RepeatedCompositeFieldContainer[ResourceAttestation]
    terms: _containers.RepeatedCompositeFieldContainer[LicenseTerm]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, domain: _Optional[str] = ..., path: _Optional[str] = ..., content_id: _Optional[str] = ..., title: _Optional[str] = ..., word_count: _Optional[int] = ..., estimated_quantity: _Optional[int] = ..., content_hash: _Optional[str] = ..., hash_method: _Optional[str] = ..., source: _Optional[_Union[IngestionSource, str]] = ..., provenance_source: _Optional[str] = ..., provenance_timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., attestations: _Optional[_Iterable[_Union[ResourceAttestation, _Mapping]]] = ..., terms: _Optional[_Iterable[_Union[LicenseTerm, _Mapping]]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class PushResourcesResponse(_message.Message):
    __slots__ = ("ver", "accepted", "rejected", "warnings", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    REJECTED_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    accepted: int
    rejected: int
    warnings: _containers.RepeatedScalarFieldContainer[str]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., accepted: _Optional[int] = ..., rejected: _Optional[int] = ..., warnings: _Optional[_Iterable[str]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class RemoveResourcesRequest(_message.Message):
    __slots__ = ("ver", "tenant_id", "paths")
    VER_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    PATHS_FIELD_NUMBER: _ClassVar[int]
    ver: str
    tenant_id: str
    paths: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., tenant_id: _Optional[str] = ..., paths: _Optional[_Iterable[str]] = ...) -> None: ...

class RemoveResourcesResponse(_message.Message):
    __slots__ = ("ver", "removed")
    VER_FIELD_NUMBER: _ClassVar[int]
    REMOVED_FIELD_NUMBER: _ClassVar[int]
    ver: str
    removed: int
    def __init__(self, ver: _Optional[str] = ..., removed: _Optional[int] = ...) -> None: ...

class RefreshCatalogRequest(_message.Message):
    __slots__ = ("ver", "tenant_id")
    VER_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    ver: str
    tenant_id: str
    def __init__(self, ver: _Optional[str] = ..., tenant_id: _Optional[str] = ...) -> None: ...

class RefreshCatalogResponse(_message.Message):
    __slots__ = ("ver", "started")
    VER_FIELD_NUMBER: _ClassVar[int]
    STARTED_FIELD_NUMBER: _ClassVar[int]
    ver: str
    started: bool
    def __init__(self, ver: _Optional[str] = ..., started: _Optional[bool] = ...) -> None: ...

class ReportingObligation(_message.Message):
    __slots__ = ("required", "window", "endpoint", "required_fields", "ext", "ext_critical")
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELDS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    required: bool
    window: _duration_pb2.Duration
    endpoint: str
    required_fields: _containers.RepeatedScalarFieldContainer[str]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, required: _Optional[bool] = ..., window: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., endpoint: _Optional[str] = ..., required_fields: _Optional[_Iterable[str]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class UsageReport(_message.Message):
    __slots__ = ("ver", "idempotency_key", "transaction_id", "billing_id", "usage", "timestamp", "exchange", "assets", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_ID_FIELD_NUMBER: _ClassVar[int]
    BILLING_ID_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    EXCHANGE_FIELD_NUMBER: _ClassVar[int]
    ASSETS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    idempotency_key: str
    transaction_id: str
    billing_id: str
    usage: Usage
    timestamp: _timestamp_pb2.Timestamp
    exchange: str
    assets: _containers.RepeatedCompositeFieldContainer[UsageAsset]
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., transaction_id: _Optional[str] = ..., billing_id: _Optional[str] = ..., usage: _Optional[_Union[Usage, _Mapping]] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., exchange: _Optional[str] = ..., assets: _Optional[_Iterable[_Union[UsageAsset, _Mapping]]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class AttributionDetail(_message.Message):
    __slots__ = ("displayed_url", "format", "visible_to_user")
    DISPLAYED_URL_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    VISIBLE_TO_USER_FIELD_NUMBER: _ClassVar[int]
    displayed_url: str
    format: CitationFormat
    visible_to_user: bool
    def __init__(self, displayed_url: _Optional[str] = ..., format: _Optional[_Union[CitationFormat, str]] = ..., visible_to_user: _Optional[bool] = ...) -> None: ...

class Usage(_message.Message):
    __slots__ = ("function", "subfn", "consumed_quantity", "displayed_to_user", "citation_included", "attribution", "consumed_unit")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    SUBFN_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_QUANTITY_FIELD_NUMBER: _ClassVar[int]
    DISPLAYED_TO_USER_FIELD_NUMBER: _ClassVar[int]
    CITATION_INCLUDED_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTION_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_UNIT_FIELD_NUMBER: _ClassVar[int]
    function: _containers.RepeatedScalarFieldContainer[str]
    subfn: _containers.RepeatedScalarFieldContainer[str]
    consumed_quantity: int
    displayed_to_user: bool
    citation_included: bool
    attribution: _containers.RepeatedCompositeFieldContainer[AttributionDetail]
    consumed_unit: str
    def __init__(self, function: _Optional[_Iterable[str]] = ..., subfn: _Optional[_Iterable[str]] = ..., consumed_quantity: _Optional[int] = ..., displayed_to_user: _Optional[bool] = ..., citation_included: _Optional[bool] = ..., attribution: _Optional[_Iterable[_Union[AttributionDetail, _Mapping]]] = ..., consumed_unit: _Optional[str] = ...) -> None: ...

class UsageAsset(_message.Message):
    __slots__ = ("uri", "title", "package_id")
    URI_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_ID_FIELD_NUMBER: _ClassVar[int]
    uri: str
    title: str
    package_id: str
    def __init__(self, uri: _Optional[str] = ..., title: _Optional[str] = ..., package_id: _Optional[str] = ...) -> None: ...

class UsageReportResponse(_message.Message):
    __slots__ = ("ver", "report_id", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    REPORT_ID_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    report_id: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., report_id: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class RAMPRequest(_message.Message):
    __slots__ = ("ver", "id", "requester", "uris", "acceptable_restrictions", "constraints", "supported_profiles", "query", "search_filters", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    REQUESTER_FIELD_NUMBER: _ClassVar[int]
    URIS_FIELD_NUMBER: _ClassVar[int]
    ACCEPTABLE_RESTRICTIONS_FIELD_NUMBER: _ClassVar[int]
    CONSTRAINTS_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_PROFILES_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    SEARCH_FILTERS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    id: str
    requester: Requester
    uris: _containers.RepeatedScalarFieldContainer[str]
    acceptable_restrictions: _containers.RepeatedCompositeFieldContainer[AcceptableRestriction]
    constraints: RequestConstraints
    supported_profiles: _containers.RepeatedScalarFieldContainer[str]
    query: str
    search_filters: _struct_pb2.Struct
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., id: _Optional[str] = ..., requester: _Optional[_Union[Requester, _Mapping]] = ..., uris: _Optional[_Iterable[str]] = ..., acceptable_restrictions: _Optional[_Iterable[_Union[AcceptableRestriction, _Mapping]]] = ..., constraints: _Optional[_Union[RequestConstraints, _Mapping]] = ..., supported_profiles: _Optional[_Iterable[str]] = ..., query: _Optional[str] = ..., search_filters: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class RequestConstraints(_message.Message):
    __slots__ = ("exchanges", "max_price", "max_unit_cost", "delivery_preference", "reporting_capable", "preferred_exchanges", "budget_scope", "period_budget", "budget_period", "max_data_age", "max_hops")
    EXCHANGES_FIELD_NUMBER: _ClassVar[int]
    MAX_PRICE_FIELD_NUMBER: _ClassVar[int]
    MAX_UNIT_COST_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_PREFERENCE_FIELD_NUMBER: _ClassVar[int]
    REPORTING_CAPABLE_FIELD_NUMBER: _ClassVar[int]
    PREFERRED_EXCHANGES_FIELD_NUMBER: _ClassVar[int]
    BUDGET_SCOPE_FIELD_NUMBER: _ClassVar[int]
    PERIOD_BUDGET_FIELD_NUMBER: _ClassVar[int]
    BUDGET_PERIOD_FIELD_NUMBER: _ClassVar[int]
    MAX_DATA_AGE_FIELD_NUMBER: _ClassVar[int]
    MAX_HOPS_FIELD_NUMBER: _ClassVar[int]
    exchanges: _containers.RepeatedScalarFieldContainer[str]
    max_price: Cost
    max_unit_cost: float
    delivery_preference: _containers.RepeatedScalarFieldContainer[DeliveryMethod]
    reporting_capable: bool
    preferred_exchanges: _containers.RepeatedScalarFieldContainer[str]
    budget_scope: str
    period_budget: Cost
    budget_period: _duration_pb2.Duration
    max_data_age: _duration_pb2.Duration
    max_hops: int
    def __init__(self, exchanges: _Optional[_Iterable[str]] = ..., max_price: _Optional[_Union[Cost, _Mapping]] = ..., max_unit_cost: _Optional[float] = ..., delivery_preference: _Optional[_Iterable[_Union[DeliveryMethod, str]]] = ..., reporting_capable: _Optional[bool] = ..., preferred_exchanges: _Optional[_Iterable[str]] = ..., budget_scope: _Optional[str] = ..., period_budget: _Optional[_Union[Cost, _Mapping]] = ..., budget_period: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., max_data_age: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., max_hops: _Optional[int] = ...) -> None: ...

class JsonWebKey(_message.Message):
    __slots__ = ("kid", "kty", "crv", "use", "alg", "x", "not_before", "not_after")
    KID_FIELD_NUMBER: _ClassVar[int]
    KTY_FIELD_NUMBER: _ClassVar[int]
    CRV_FIELD_NUMBER: _ClassVar[int]
    USE_FIELD_NUMBER: _ClassVar[int]
    ALG_FIELD_NUMBER: _ClassVar[int]
    X_FIELD_NUMBER: _ClassVar[int]
    NOT_BEFORE_FIELD_NUMBER: _ClassVar[int]
    NOT_AFTER_FIELD_NUMBER: _ClassVar[int]
    kid: str
    kty: str
    crv: str
    use: str
    alg: str
    x: str
    not_before: str
    not_after: str
    def __init__(self, kid: _Optional[str] = ..., kty: _Optional[str] = ..., crv: _Optional[str] = ..., use: _Optional[str] = ..., alg: _Optional[str] = ..., x: _Optional[str] = ..., not_before: _Optional[str] = ..., not_after: _Optional[str] = ...) -> None: ...

class WellKnownManifest(_message.Message):
    __slots__ = ("ver", "role", "domain", "contact", "public_keys", "invalidation_url", "exchanges", "catalog_contributors", "name", "operator", "operator_domain", "endpoint", "health_endpoint", "catalog_endpoint", "protocol_versions_supported", "pricing_models_supported", "delivery_methods_supported", "hash_methods_supported", "accepted_verifiers", "terms_uri", "privacy_uri", "supported_profiles", "supported_auth_methods", "oidc_issuer", "gnap_grant_endpoint", "base_currency", "max_intermediary_hops", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    CONTACT_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEYS_FIELD_NUMBER: _ClassVar[int]
    INVALIDATION_URL_FIELD_NUMBER: _ClassVar[int]
    EXCHANGES_FIELD_NUMBER: _ClassVar[int]
    CATALOG_CONTRIBUTORS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    HEALTH_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    CATALOG_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_VERSIONS_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    PRICING_MODELS_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_METHODS_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    HASH_METHODS_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_VERIFIERS_FIELD_NUMBER: _ClassVar[int]
    TERMS_URI_FIELD_NUMBER: _ClassVar[int]
    PRIVACY_URI_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_PROFILES_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_AUTH_METHODS_FIELD_NUMBER: _ClassVar[int]
    OIDC_ISSUER_FIELD_NUMBER: _ClassVar[int]
    GNAP_GRANT_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    BASE_CURRENCY_FIELD_NUMBER: _ClassVar[int]
    MAX_INTERMEDIARY_HOPS_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    role: Role
    domain: str
    contact: str
    public_keys: _containers.RepeatedCompositeFieldContainer[JsonWebKey]
    invalidation_url: str
    exchanges: _containers.RepeatedCompositeFieldContainer[AuthorizedExchange]
    catalog_contributors: _containers.RepeatedCompositeFieldContainer[CatalogContributor]
    name: str
    operator: str
    operator_domain: str
    endpoint: str
    health_endpoint: str
    catalog_endpoint: str
    protocol_versions_supported: _containers.RepeatedScalarFieldContainer[str]
    pricing_models_supported: _containers.RepeatedScalarFieldContainer[PricingModel]
    delivery_methods_supported: _containers.RepeatedScalarFieldContainer[DeliveryMethod]
    hash_methods_supported: _containers.RepeatedScalarFieldContainer[str]
    accepted_verifiers: _containers.RepeatedScalarFieldContainer[str]
    terms_uri: str
    privacy_uri: str
    supported_profiles: _containers.RepeatedScalarFieldContainer[str]
    supported_auth_methods: _containers.RepeatedScalarFieldContainer[AuthMethod]
    oidc_issuer: str
    gnap_grant_endpoint: str
    base_currency: str
    max_intermediary_hops: int
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., role: _Optional[_Union[Role, str]] = ..., domain: _Optional[str] = ..., contact: _Optional[str] = ..., public_keys: _Optional[_Iterable[_Union[JsonWebKey, _Mapping]]] = ..., invalidation_url: _Optional[str] = ..., exchanges: _Optional[_Iterable[_Union[AuthorizedExchange, _Mapping]]] = ..., catalog_contributors: _Optional[_Iterable[_Union[CatalogContributor, _Mapping]]] = ..., name: _Optional[str] = ..., operator: _Optional[str] = ..., operator_domain: _Optional[str] = ..., endpoint: _Optional[str] = ..., health_endpoint: _Optional[str] = ..., catalog_endpoint: _Optional[str] = ..., protocol_versions_supported: _Optional[_Iterable[str]] = ..., pricing_models_supported: _Optional[_Iterable[_Union[PricingModel, str]]] = ..., delivery_methods_supported: _Optional[_Iterable[_Union[DeliveryMethod, str]]] = ..., hash_methods_supported: _Optional[_Iterable[str]] = ..., accepted_verifiers: _Optional[_Iterable[str]] = ..., terms_uri: _Optional[str] = ..., privacy_uri: _Optional[str] = ..., supported_profiles: _Optional[_Iterable[str]] = ..., supported_auth_methods: _Optional[_Iterable[_Union[AuthMethod, str]]] = ..., oidc_issuer: _Optional[str] = ..., gnap_grant_endpoint: _Optional[str] = ..., base_currency: _Optional[str] = ..., max_intermediary_hops: _Optional[int] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class KeyInvalidationList(_message.Message):
    __slots__ = ("as_of", "revoked")
    AS_OF_FIELD_NUMBER: _ClassVar[int]
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    as_of: _timestamp_pb2.Timestamp
    revoked: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, as_of: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., revoked: _Optional[_Iterable[str]] = ...) -> None: ...

class CatalogContributor(_message.Message):
    __slots__ = ("domain", "relationship")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    RELATIONSHIP_FIELD_NUMBER: _ClassVar[int]
    domain: str
    relationship: str
    def __init__(self, domain: _Optional[str] = ..., relationship: _Optional[str] = ...) -> None: ...

class AuthorizedExchange(_message.Message):
    __slots__ = ("domain", "endpoint", "relationship", "ext", "ext_critical")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    RELATIONSHIP_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    domain: str
    endpoint: str
    relationship: ProviderRelationship
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, domain: _Optional[str] = ..., endpoint: _Optional[str] = ..., relationship: _Optional[_Union[ProviderRelationship, str]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class RAMPResponse(_message.Message):
    __slots__ = ("ver", "transaction_id", "billing_id", "exchange", "resource_title", "cost", "delivery_method", "reporting_obligation", "expires_at", "retrieval_endpoint", "agent_identity_hash", "broker_fee", "absence_reason", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_ID_FIELD_NUMBER: _ClassVar[int]
    BILLING_ID_FIELD_NUMBER: _ClassVar[int]
    EXCHANGE_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TITLE_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_METHOD_FIELD_NUMBER: _ClassVar[int]
    REPORTING_OBLIGATION_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    RETRIEVAL_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    AGENT_IDENTITY_HASH_FIELD_NUMBER: _ClassVar[int]
    BROKER_FEE_FIELD_NUMBER: _ClassVar[int]
    ABSENCE_REASON_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    transaction_id: str
    billing_id: str
    exchange: str
    resource_title: str
    cost: Cost
    delivery_method: DeliveryMethod
    reporting_obligation: ReportingObligation
    expires_at: _timestamp_pb2.Timestamp
    retrieval_endpoint: str
    agent_identity_hash: str
    broker_fee: Cost
    absence_reason: OfferAbsenceReason
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., transaction_id: _Optional[str] = ..., billing_id: _Optional[str] = ..., exchange: _Optional[str] = ..., resource_title: _Optional[str] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ..., delivery_method: _Optional[_Union[DeliveryMethod, str]] = ..., reporting_obligation: _Optional[_Union[ReportingObligation, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., retrieval_endpoint: _Optional[str] = ..., agent_identity_hash: _Optional[str] = ..., broker_fee: _Optional[_Union[Cost, _Mapping]] = ..., absence_reason: _Optional[_Union[OfferAbsenceReason, str]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class DisputeRequest(_message.Message):
    __slots__ = ("ver", "idempotency_key", "transaction_id", "billing_id", "reason", "description", "received_content_hash", "received_hash_method", "report_id", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_ID_FIELD_NUMBER: _ClassVar[int]
    BILLING_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    RECEIVED_CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    RECEIVED_HASH_METHOD_FIELD_NUMBER: _ClassVar[int]
    REPORT_ID_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    idempotency_key: str
    transaction_id: str
    billing_id: str
    reason: DisputeReason
    description: str
    received_content_hash: str
    received_hash_method: str
    report_id: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., transaction_id: _Optional[str] = ..., billing_id: _Optional[str] = ..., reason: _Optional[_Union[DisputeReason, str]] = ..., description: _Optional[str] = ..., received_content_hash: _Optional[str] = ..., received_hash_method: _Optional[str] = ..., report_id: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class DisputeResponse(_message.Message):
    __slots__ = ("ver", "dispute_id", "estimated_resolution", "status", "resolution", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    DISPUTE_ID_FIELD_NUMBER: _ClassVar[int]
    ESTIMATED_RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    dispute_id: str
    estimated_resolution: _duration_pb2.Duration
    status: DisputeStatus
    resolution: ResolutionType
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., dispute_id: _Optional[str] = ..., estimated_resolution: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., status: _Optional[_Union[DisputeStatus, str]] = ..., resolution: _Optional[_Union[ResolutionType, str]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class DomainVerificationRequest(_message.Message):
    __slots__ = ("ver", "domain", "caller_id", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    CALLER_ID_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    domain: str
    caller_id: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., domain: _Optional[str] = ..., caller_id: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class DomainVerificationChallenge(_message.Message):
    __slots__ = ("ver", "token", "expires_at", "verification_url", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_URL_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    token: str
    expires_at: _timestamp_pb2.Timestamp
    verification_url: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., token: _Optional[str] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., verification_url: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class DomainVerificationConfirmation(_message.Message):
    __slots__ = ("ver", "domain", "token", "signing_key", "cdn_type", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    CDN_TYPE_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    domain: str
    token: str
    signing_key: str
    cdn_type: str
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., domain: _Optional[str] = ..., token: _Optional[str] = ..., signing_key: _Optional[str] = ..., cdn_type: _Optional[str] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class DomainVerificationResult(_message.Message):
    __slots__ = ("ver", "key_id", "valid_until", "ext", "ext_critical")
    VER_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    EXT_FIELD_NUMBER: _ClassVar[int]
    EXT_CRITICAL_FIELD_NUMBER: _ClassVar[int]
    ver: str
    key_id: str
    valid_until: _timestamp_pb2.Timestamp
    ext: _struct_pb2.Struct
    ext_critical: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, ver: _Optional[str] = ..., key_id: _Optional[str] = ..., valid_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., ext: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., ext_critical: _Optional[_Iterable[str]] = ...) -> None: ...

class ErrorDetail(_message.Message):
    __slots__ = ("message", "domain", "metadata", "transaction_denial", "catalog_rejection", "registration_failure", "dispute_failure", "domain_verification_failure", "retrieval_auth_failure", "usage_report_rejection")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    TRANSACTION_DENIAL_FIELD_NUMBER: _ClassVar[int]
    CATALOG_REJECTION_FIELD_NUMBER: _ClassVar[int]
    REGISTRATION_FAILURE_FIELD_NUMBER: _ClassVar[int]
    DISPUTE_FAILURE_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_VERIFICATION_FAILURE_FIELD_NUMBER: _ClassVar[int]
    RETRIEVAL_AUTH_FAILURE_FIELD_NUMBER: _ClassVar[int]
    USAGE_REPORT_REJECTION_FIELD_NUMBER: _ClassVar[int]
    message: str
    domain: str
    metadata: _containers.ScalarMap[str, str]
    transaction_denial: TransactionDenial
    catalog_rejection: CatalogRejection
    registration_failure: RegistrationFailure
    dispute_failure: DisputeFailure
    domain_verification_failure: DomainVerificationFailure
    retrieval_auth_failure: RetrievalAuthFailure
    usage_report_rejection: UsageReportRejection
    def __init__(self, message: _Optional[str] = ..., domain: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ..., transaction_denial: _Optional[_Union[TransactionDenial, _Mapping]] = ..., catalog_rejection: _Optional[_Union[CatalogRejection, _Mapping]] = ..., registration_failure: _Optional[_Union[RegistrationFailure, _Mapping]] = ..., dispute_failure: _Optional[_Union[DisputeFailure, _Mapping]] = ..., domain_verification_failure: _Optional[_Union[DomainVerificationFailure, _Mapping]] = ..., retrieval_auth_failure: _Optional[_Union[RetrievalAuthFailure, _Mapping]] = ..., usage_report_rejection: _Optional[_Union[UsageReportRejection, _Mapping]] = ...) -> None: ...

class TransactionDenial(_message.Message):
    __slots__ = ("reason", "restriction_mismatches", "offer_id")
    REASON_FIELD_NUMBER: _ClassVar[int]
    RESTRICTION_MISMATCHES_FIELD_NUMBER: _ClassVar[int]
    OFFER_ID_FIELD_NUMBER: _ClassVar[int]
    reason: DenialReason
    restriction_mismatches: _containers.RepeatedScalarFieldContainer[RestrictionKind]
    offer_id: str
    def __init__(self, reason: _Optional[_Union[DenialReason, str]] = ..., restriction_mismatches: _Optional[_Iterable[_Union[RestrictionKind, str]]] = ..., offer_id: _Optional[str] = ...) -> None: ...

class CatalogRejection(_message.Message):
    __slots__ = ("reason", "rejected_paths")
    REASON_FIELD_NUMBER: _ClassVar[int]
    REJECTED_PATHS_FIELD_NUMBER: _ClassVar[int]
    reason: CatalogRejectionReason
    rejected_paths: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, reason: _Optional[_Union[CatalogRejectionReason, str]] = ..., rejected_paths: _Optional[_Iterable[str]] = ...) -> None: ...

class RegistrationFailure(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: RegistrationFailureReason
    def __init__(self, reason: _Optional[_Union[RegistrationFailureReason, str]] = ...) -> None: ...

class DisputeFailure(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: DisputeFailureReason
    def __init__(self, reason: _Optional[_Union[DisputeFailureReason, str]] = ...) -> None: ...

class DomainVerificationFailure(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: DomainVerificationFailureReason
    def __init__(self, reason: _Optional[_Union[DomainVerificationFailureReason, str]] = ...) -> None: ...

class RetrievalAuthFailure(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: RetrievalAuthFailureReason
    def __init__(self, reason: _Optional[_Union[RetrievalAuthFailureReason, str]] = ...) -> None: ...

class UsageReportRejection(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: UsageReportRejectionReason
    def __init__(self, reason: _Optional[_Union[UsageReportRejectionReason, str]] = ...) -> None: ...
