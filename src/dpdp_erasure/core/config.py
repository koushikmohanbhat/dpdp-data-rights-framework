"""Configuration loading. YAML file with ${ENV_VAR} / ${ENV_VAR:-default} interpolation."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


class ProviderConfig(BaseModel):
    type: Literal["openai", "anthropic", "bedrock", "vertex", "echo"] = "echo"
    model: str = "echo"
    platform: Literal["anthropic", "bedrock", "vertex"] = "anthropic"   # anthropic provider only
    embedding_model: str | None = None
    embedding_provider: Literal["openai", "bedrock", "vertex", "echo"] | None = None  # needed for anthropic
    region: str | None = None          # bedrock / vertex location
    project: str | None = None         # vertex
    store: bool = False                # openai: never persist responses by default
    options: dict[str, Any] = Field(default_factory=dict)


class PIIConfig(BaseModel):
    # Detectors are combined; results are merged and de-overlapped.
    detectors: list[Literal["regex", "aws_comprehend", "bedrock_guardrail", "gcp_dlp"]] = ["regex"]
    region: str | None = None
    project: str | None = None
    guardrail_id: str | None = None
    guardrail_version: str = "DRAFT"
    min_score: float = 0.8
    detect_names: bool = True


class VaultConfig(BaseModel):
    key_wrapper: Literal["local", "aws_kms", "gcp_kms"] = "local"
    storage: Literal["sql", "dynamodb", "firestore"] = "sql"
    local_master_key_path: str = ".dpdp/master.key"
    sql_url: str | None = None          # defaults to lineage db url
    kms_key_id: str | None = None       # AWS KMS key ARN / alias, or GCP key resource name
    dynamodb_table_prefix: str = "dpdp_vault"
    firestore_collection_prefix: str = "dpdp_vault"
    region: str | None = None
    project: str | None = None


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
    basis: str = ("DPDP Rules 2025, Rule 8(3): personal data, traffic data and processing logs retained for "
                  "at least one year from processing for Seventh Schedule purposes")


class PolicyConfig(BaseModel):
    default_action: str = "delete"
    statutory_retention: StatutoryRetentionConfig = Field(default_factory=StatutoryRetentionConfig)
    rules: list[PolicyRule] = Field(default_factory=list)
    aggregate_k_threshold: int = 10
    sla_days: int = 30


class PurposeConfig(BaseModel):
    id: str
    description: str = ""
    legal_basis: str = "consent"
    retention_days: int | None = None
    legal_hold_basis: str | None = None


class KitConfig(BaseModel):
    tenant: str | None = None
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    pii: PIIConfig = Field(default_factory=PIIConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    lineage: LineageConfig = Field(default_factory=LineageConfig)
    purposes: list[PurposeConfig] = Field(default_factory=list)
    connectors: list[ConnectorConfig] = Field(default_factory=list)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    enforce_consent: bool = True

    @classmethod
    def load(cls, path: str | Path) -> "KitConfig":
        raw = yaml.safe_load(Path(path).read_text()) or {}
        return cls.model_validate(_interpolate(raw))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KitConfig":
        return cls.model_validate(_interpolate(data))
