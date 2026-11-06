"""Configuration loading.

Sources: a local path, ``s3://bucket/key``, or ``ssm://<parameter-name>`` (AWS SSM Parameter Store),
so deployments keep their config in their own account instead of the repository or image.

Interpolation: ``${VAR}``, ``${VAR:-default}`` and ``${VAR!url}`` (URL-encoded, for passwords in
database URLs).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import yaml
from pydantic import BaseModel, Field

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(!url)?(?::-([^}]*))?\}")


def _sub(m: re.Match) -> str:
    val = os.environ.get(m.group(1), m.group(3) or "")
    return quote(val, safe="") if m.group(2) else val


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def read_config_text(path: str) -> str:
    if path.startswith("ssm://"):
        import boto3

        name = path.removeprefix("ssm://")
        name = name if name.startswith("/") else "/" + name.lstrip("/")
        return boto3.client("ssm").get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    if path.startswith("s3://"):
        import boto3

        bucket, key = path.removeprefix("s3://").split("/", 1)
        return boto3.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read().decode()
    return Path(path).read_text()


class ProviderConfig(BaseModel):
    type: str = "echo"     # openai | anthropic | bedrock | vertex | echo | a provider plug-in
    model: str = "echo"
    platform: Literal["anthropic", "bedrock", "vertex"] = "anthropic"   # anthropic provider only
    embedding_model: str | None = None
    embedding_provider: str | None = None  # openai | bedrock | vertex | echo; needed for anthropic
    region: str | None = None          # bedrock / vertex location
    project: str | None = None         # vertex
    store: bool = False                # openai: never persist responses by default
    options: dict[str, Any] = Field(default_factory=dict)


class PatternConfig(BaseModel):
    """A deployment-specific identifier: an element type, a regex, and optional context words that must
    appear within ``window`` characters before the match (case-insensitive)."""
    type: str                              # e.g. POLICY_NUMBER, CLAIM_NUMBER, LOAN_ACCOUNT, UHID
    regex: str
    context: list[str] = Field(default_factory=list)
    window: int = 40
    ignore_case: bool = False


class PIIConfig(BaseModel):
    # Detectors are combined; results are merged and de-overlapped.
    # regex | aws_comprehend | bedrock_guardrail | gcp_dlp | presidio | transformers_ner | remote_ner | llm | plug-ins
    detectors: list[str] = ["regex"]
    detector_options: dict[str, dict[str, Any]] = Field(default_factory=dict)   # options for plug-in detectors
    region: str | None = None
    project: str | None = None
    guardrail_id: str | None = None
    guardrail_version: str = "DRAFT"
    min_score: float = 0.8
    detect_names: bool = True
    presidio: dict[str, Any] = Field(default_factory=dict)          # PresidioDetector options
    transformers_ner: dict[str, Any] = Field(default_factory=dict)  # TransformersNerDetector options
    remote_ner: dict[str, Any] = Field(default_factory=dict)        # url, timeout_seconds, on_error (NER sidecar)
    llm: ProviderConfig | None = None       # model for the llm detector; keep it separate from `provider`
    llm_options: dict[str, Any] = Field(default_factory=dict)       # LLMDetector options (max_chars, score)
    # Element types stored as format-preserving surrogates instead of <TYPE_xxxx> tokens (opt-in):
    # PHONE_IN, PHONE, AADHAAR, CARD_NUMBER, PAN, EMAIL, BANK_ACCOUNT
    surrogates: list[str] = Field(default_factory=list)
    # Documents (protect_document): {"ocr": "none" | "textract" | "document_ai", "region": ..., "processor": ...}
    documents: dict[str, Any] = Field(default_factory=dict)
    allow_regex_only: bool = False   # production guardrail: regex misses names and free text
    # Your own identifiers (policy, claim, loan-account, hospital record numbers): docs/pii-detection.md
    patterns: list[PatternConfig] = Field(default_factory=list)


class VaultConfig(BaseModel):
    key_wrapper: str = "local"     # local | aws_kms | gcp_kms | a key_wrappers plug-in
    storage: str = "sql"           # sql | dynamodb | firestore | a vault_storage plug-in
    local_master_key_path: str = ".dpdp/master.key"
    sql_url: str | None = None          # defaults to lineage db url
    kms_key_id: str | None = None       # AWS KMS key ARN / alias, or GCP key resource name
    dynamodb_table_prefix: str = "dpdp_vault"
    firestore_collection_prefix: str = "dpdp_vault"
    firestore_database: str | None = None   # named Firestore database; None = "(default)"
    region: str | None = None
    project: str | None = None
    cache_ttl_seconds: int = 300        # unwrapped DEKs are cached in memory at most this long
    cache_max_entries: int = 10_000
    # Separate key-encryption key for sealed (legal-hold / escrow) DEKs, ideally usable only by a
    # break-glass IAM role, so application credentials cannot read sealed data at the cloud level.
    sealed_key_wrapper: str | None = None   # local | aws_kms | gcp_kms | a key_wrappers plug-in
    sealed_kms_key_id: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)   # for key_wrappers / vault_storage plug-ins
    sealed_role_arn: str | None = None   # aws: role assumed only for sealed unwraps
    sealed_local_master_key_path: str = ".dpdp/sealed.key"


class LineageConfig(BaseModel):
    url: str = "sqlite:///.dpdp/lineage.db"   # any SQLAlchemy URL (Aurora PG, Cloud SQL, AlloyDB...)


class ConnectorConfig(BaseModel):
    name: str
    type: str
    options: dict[str, Any] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    kind: str | None = None
    edge_type: str | None = None
    store: str | None = None
    purpose: str | None = None
    min_principals: int | None = None   # for aggregates
    action: str
    reason: str | None = None


class StatutoryRetentionConfig(BaseModel):
    """Minimum retention that survives an erasure request (sealed, not usable by applications)."""
    enabled: bool = True
    days: int = 365
    basis: str = ("DPDP Rules 2025, Rule 8(3) minimum retention: the principal's identifiers kept in a sealed "
                  "escrow, readable only through break-glass, for one year from processing")


class PolicyConfig(BaseModel):
    default_action: str = "delete"
    statutory_retention: StatutoryRetentionConfig = Field(default_factory=StatutoryRetentionConfig)
    rules: list[PolicyRule] = Field(default_factory=list)
    aggregate_k_threshold: int = 10
    sla_days: int = 30


class ApiKeyConfig(BaseModel):
    name: str
    sha256: str                          # hex sha256 of the key; never store raw keys in config
    roles: list[str] = Field(default_factory=lambda: ["service"])
    tenant: str | None = None


class OidcConfig(BaseModel):
    issuer: str
    audience: str
    jwks_url: str | None = None          # defaults to <issuer>/.well-known/jwks.json
    algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    roles_claim: str = "roles"           # Cognito: "cognito:groups"; Google: custom claim
    tenant_claim: str = "tenant"
    subject_claim: str = "sub"           # for self-service principals: maps to external_id


class AuthConfig(BaseModel):
    mode: Literal["none", "api_key", "oidc", "both"] = "none"
    api_keys: list[ApiKeyConfig] = Field(default_factory=list)
    oidc: OidcConfig | None = None


class ApiConfig(BaseModel):
    auth: AuthConfig = Field(default_factory=AuthConfig)
    console: bool = True               # the DPO console at /console (static files; data through this API's roles)


class QueueConfig(BaseModel):
    type: str = "database"         # the durable database queue, or a queues plug-in (e.g. SQS, Pub/Sub)
    options: dict[str, Any] = Field(default_factory=dict)
    lease_seconds: int = 300
    max_attempts: int = 5
    backoff_seconds: int = 60


class CertificateConfig(BaseModel):
    signer: Literal["none", "local", "aws_kms", "gcp_kms"] = "none"
    key_id: str | None = None            # KMS asymmetric key (ECC_NIST_P256) ARN / GCP key version name
    local_key_path: str = ".dpdp/cert_signing.key"
    archive: Literal["none", "local", "s3", "gcs"] = "none"
    archive_uri: str | None = None       # local dir, s3://bucket/prefix (Object Lock enabled), gs://bucket/prefix
    retain_days: int = 3650
    archive_mode: Literal["COMPLIANCE", "GOVERNANCE"] = "COMPLIANCE"   # S3 Object Lock mode; GOVERNANCE for test accounts
    region: str | None = None


class BreakGlassConfig(BaseModel):
    require_second_approver: bool = True
    max_grant_minutes: int = 60


class ObservabilityConfig(BaseModel):
    otel: bool = False                   # requires the [otel] extra
    service_name: str = "dpdp-rights"
    otlp_endpoint: str | None = None     # e.g. http://localhost:4318 (ADOT / OTel Collector)
    tokenize_spans: bool = True


class TenantRef(BaseModel):
    config: str                          # path to that tenant's own config (own DB, vault, keys)


class PurposeConfig(BaseModel):
    id: str
    description: str = ""
    legal_basis: str = "consent"
    retention_days: int | None = None
    legal_hold_basis: str | None = None
    # Children (Act s.9, docs/children.md). ``child_restricted``: the purpose involves tracking, behavioural
    # monitoring or advertising targeted at the user, which s.9(3) forbids for children. ``child_exemption``: an
    # exemption id from the rule set's ``children.exemptions`` (Rules r.12, Fourth Schedule), for counsel to confirm.
    child_restricted: bool = False
    child_exemption: str | None = None


class CmVerificationConfig(BaseModel):
    """How the framework checks that an inbound event really came from the Consent Manager."""
    mode: Literal["hmac", "ed25519"] = "hmac"
    secret_env: str | None = None          # hmac: environment variable holding the shared secret
    secret: str | None = None              # hmac: inline secret (development only; check-config flags it)
    public_key_pem: str | None = None      # ed25519: the Consent Manager's published key
    public_key_path: str | None = None
    replay_window_seconds: int = 300       # events signed longer ago (or this far in the future) are refused


class ConsentManagerConfig(BaseModel):
    """A registered Consent Manager this Data Fiduciary is onboarded with (Act s.6(7)-(9), Rules r.4)."""
    name: str                              # short id used in URLs, refs and the consent history
    type: str = "generic"                  # generic (provisional schema dpdp-cm-events/0.1) | a consent_managers plug-in
    registration_ref: str | None = None    # the Board's registration number, for the record
    verification: CmVerificationConfig = Field(default_factory=CmVerificationConfig)
    purpose_map: dict[str, str] = Field(default_factory=dict)    # Consent Manager purpose code -> purposes[].id
    element_map: dict[str, str] = Field(default_factory=dict)    # Consent Manager data item -> element type
    id_type: str = "EXTERNAL_ID"           # how the event's principal reference resolves in the vault
    create_principals: bool = True         # a consent given for an unknown reference creates the principal
    erase_on_withdrawal: bool = True       # queue a purpose-scoped erasure when no consent for the purpose remains
    erase_on_expiry: bool = True
    report_url: str | None = None          # https endpoint to tell the Consent Manager about withdrawals made here
    options: dict[str, Any] = Field(default_factory=dict)       # for consent_managers plug-ins


class GatewayConfig(BaseModel):
    """Model gateway in front of existing agents (docs/gateway.md)."""
    enabled: bool = False
    mode: Literal["observe", "enforce"] = "observe"
    upstream_base_url: str = "https://api.openai.com/v1"   # OpenAI-compatible: OpenAI, Azure OpenAI, vLLM, LiteLLM
    upstream_api_key_env: str | None = "OPENAI_API_KEY"
    # Enforce mode: where the person comes from (docs/gateway.md#binding-the-person-to-authentication).
    #   signed   an HMAC assertion minted by the app's backend after it authenticated its user (default)
    #   subject  the authenticated caller's own subject (an OIDC end-user token)
    #   key      LiteLLM only: dpdp_principal in the virtual key's metadata, set by the proxy admin
    #   header   trust the service caller's header or `user` field (development; refused with reveal in production)
    principal_binding: Literal["signed", "subject", "key", "header"] = "signed"
    assertion_header: str = "x-dpdp-assertion"
    assertion_secret_env: str = "DPDP_GATEWAY_ASSERTION_SECRET"
    assertion_max_ttl_seconds: int = 900
    principal_header: str = "x-dpdp-principal"            # the person's external id (header binding; else checked)
    purpose_header: str = "x-dpdp-purpose"
    use_user_field: bool = True                           # header binding: fall back to `user` / `safety_identifier`
    default_purpose: str | None = None
    missing_principal: Literal["block", "mask"] = "block"  # enforce mode, no person identified
    enforce_consent: bool = True
    reveal_responses: bool = False                        # turn tokens in responses back into values for the user
    force_store_false: bool = True                        # Responses API: do not keep state at the provider
    record_observations: bool = True
    timeout_seconds: float = 120


class ChildrenConfig(BaseModel):
    """Verifiable consent for children and persons with disability who have a lawful guardian (docs/children.md)."""
    enabled: bool = False
    # A principal with no recorded status: "deny" refuses consent-based processing until the status is set (safest);
    # "adult" treats them as adults (only where the service is not offered to children, documented as such).
    unknown_status: Literal["deny", "adult"] = "deny"
    parent_methods: list[str] = Field(default_factory=lambda: ["fiduciary_records", "voluntary_details", "virtual_token"])
    guardian_methods: list[str] = Field(default_factory=lambda: ["court", "designated_authority", "local_level_committee"])
    token_issuers: list[str] = Field(default_factory=list)      # accepted virtual-token issuers, e.g. ["digilocker"]


class NotificationConfig(BaseModel):
    type: str                      # webhook | log | a notifiers plug-in
    options: dict[str, Any] = Field(default_factory=dict)
    events: list[str] = ["request_completed", "request_completed_with_exceptions", "request_failed"]


class ChecklistItem(BaseModel):
    id: str
    text: str


DEFAULT_REVIEW_CHECKLIST = [
    {"id": "requester_verified",
     "text": "The upstream verification reference matches a real, closed verification case"},
    {"id": "scope_matches_request", "text": "The scope erased (full or purpose) is what the Data Principal asked for"},
    {"id": "exceptions_justified",
     "text": "Every retained, failed or crypto-shredded item has a documented basis"},
    {"id": "verification_reviewed",
     "text": "Verification results were reviewed; any leftovers were resolved or escalated"},
    {"id": "manual_systems_done",
     "text": "Systems without a connector (manual or processor-held) have a recorded manual action"},
]


class EvidenceConfig(BaseModel):
    """Case records, reviewer sign-off, evidence bundles and audit packs (docs/evidence.md)."""
    required_approvals: int = 1          # distinct reviewers who must approve before a case is signed off
    review_checklist: list[ChecklistItem] = Field(
        default_factory=lambda: [ChecklistItem(**c) for c in DEFAULT_REVIEW_CHECKLIST])
    reject_personal_data: bool = True    # refuse notes / references that look like personal data
    sign_off_due_days: int = 7           # audit pack flags completed cases unreviewed for longer


class RecipientConfig(BaseModel):
    """Another Data Fiduciary or a Data Processor that receives data held in a store (Act s.11(1)(b))."""
    store: str                            # connector name (or provider store, e.g. openai_platform)
    name: str                             # shown to the Data Principal, e.g. "OpenAI (model provider)"
    role: Literal["processor", "fiduciary"] = "processor"
    description: str = ""                 # what it does with the data, in plain language
    exempt_from_access: bool = False      # s.11(2): not disclosed in access reports
    exemption_basis: str | None = None


class ChannelConfig(BaseModel):
    name: str                             # "Mobile app", "Website", "Contact centre"
    how: str                              # "Profile > Privacy > My data rights"


class RightsConfig(BaseModel):
    """Rights workflow: access, correction, nomination, grievance cases (docs/rights.md)."""
    rule_set: str = "dpdp-in"
    rule_sets_dir: str | None = None      # your own (counsel-reviewed) rule-set versions
    overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)   # e.g. {grievance: {respond_within_days: 15}}
    review_required: list[str] | None = None   # default: the rule set's review_by_default
    access_values: Literal["masked", "none", "full"] = "masked"
    recipients: list[RecipientConfig] = Field(default_factory=list)
    channels: list[ChannelConfig] = Field(default_factory=list)
    identifiers: list[str] = Field(default_factory=list)   # what a principal supplies to be identified (r.14(1))
    contact: str | None = None            # DPO / grievance officer contact for the published notice
    # The deployment inventory (partner-pack/inventory.template.yaml). Access reports compare against it to say
    # whether they are complete; without it every report is marked "coverage unknown". Relative to the config file.
    inventory_path: str | None = None
    # Run every connector's discovery for each access request, so the report rests on a search made for this
    # request rather than on configuration. Turn off only if discovery is too costly; reports can then say at
    # most "configured coverage", never "complete".
    access_search: bool = True


class FrameworkConfig(BaseModel):
    environment: Literal["dev", "staging", "production"] = "dev"
    tenant: str | None = None
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    pii: PIIConfig = Field(default_factory=PIIConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    lineage: LineageConfig = Field(default_factory=LineageConfig)
    purposes: list[PurposeConfig] = Field(default_factory=list)
    connectors: list[ConnectorConfig] = Field(default_factory=list)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    enforce_consent: bool = True
    api: ApiConfig = Field(default_factory=ApiConfig)
    queue: QueueConfig = Field(default_factory=QueueConfig)
    notifications: list[NotificationConfig] = Field(default_factory=list)
    certificates: CertificateConfig = Field(default_factory=CertificateConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    rights: RightsConfig = Field(default_factory=RightsConfig)
    consent_managers: list[ConsentManagerConfig] = Field(default_factory=list)
    children: ChildrenConfig = Field(default_factory=ChildrenConfig)
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    break_glass: BreakGlassConfig = Field(default_factory=BreakGlassConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    tenants: dict[str, TenantRef] = Field(default_factory=dict)   # multi-tenant API (silo per tenant)

    @classmethod
    def load(cls, path: str | Path) -> "FrameworkConfig":
        raw = yaml.safe_load(read_config_text(str(path))) or {}
        cfg = cls.model_validate(_interpolate(raw))
        inv = cfg.rights.inventory_path
        if inv and "://" not in str(path) and not Path(inv).is_absolute():
            cfg.rights.inventory_path = str((Path(path).parent / inv).resolve())
        return cfg

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FrameworkConfig":
        return cls.model_validate(_interpolate(data))
