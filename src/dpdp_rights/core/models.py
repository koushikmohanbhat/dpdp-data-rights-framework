"""Domain model for DPDP erasure across GenAI systems.

The model has three layers:

* **Identity & consent** - DataPrincipal, DataElement, Purpose, ConsentRecord.
  Consent is tracked per (principal, element type, purpose), not just per user.
* **Lineage** - Artifact and LineageEdge. Every place personal data lands
  (log line, embedding, cache entry, eval row, summary, memory event...) is an
  Artifact; edges record how one artifact was derived from another.
* **Erasure** - ErasureRequest, ErasureAction, ErasureCertificate.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class PrincipalStatus(str, Enum):
    ACTIVE = "active"
    ERASURE_PENDING = "erasure_pending"
    ERASED = "erased"


class ArtifactKind(str, Enum):
    PROMPT = "prompt"
    COMPLETION = "completion"
    LOG = "log"
    TRACE = "trace"
    EMBEDDING = "embedding"
    CACHE_ENTRY = "cache_entry"
    EVAL_ROW = "eval_row"
    FINETUNE_ROW = "finetune_row"
    MODEL = "model"
    SUMMARY = "summary"
    MEMORY_EVENT = "memory_event"          # AgentCore / Vertex short-term memory
    MEMORY_RECORD = "memory_record"        # AgentCore / Vertex long-term memory
    KB_DOCUMENT = "kb_document"            # Bedrock KB / Vertex RAG document
    PROVIDER_RESPONSE = "provider_response"  # e.g. OpenAI stored response
    PROVIDER_FILE = "provider_file"
    RECORD = "record"                      # generic row in an app database


class EdgeType(str, Enum):
    COPY = "copy"            # same content, different place
    TRANSFORM = "transform"  # content derived 1:1 (completion, per-user summary)
    AGGREGATE = "aggregate"  # many principals -> one artifact (trend report)
    TRAIN = "train"          # dataset -> model weights
    EMBED = "embed"          # text -> vector


class ArtifactStatus(str, Enum):
    LIVE = "live"
    ERASED = "erased"
    REDACTED = "redacted"
    RETAINED = "retained"
    PENDING_RETRAIN = "pending_retrain"


class Action(str, Enum):
    DELETE = "delete"
    REDACT = "redact"                       # strip the principal's tokens
    REGENERATE = "regenerate"               # rebuild without the principal's inputs
    CRYPTO_SHRED = "crypto_shred"           # immutable store; rely on vault key destruction
    RETAIN_AGGREGATE = "retain_aggregate"   # anonymised aggregate, documented
    RETAIN_LEGAL_HOLD = "retain_legal_hold" # retention required by another law
    FLAG_RETRAIN = "flag_retrain"           # model weights; schedule retrain
    SKIP = "skip"


class RequestStatus(str, Enum):
    RECEIVED = "received"
    PLANNED = "planned"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
    FAILED = "failed"


@dataclass
class DataPrincipal:
    principal_id: str
    status: PrincipalStatus = PrincipalStatus.ACTIVE
    created_at: datetime = field(default_factory=utcnow)
    erased_at: datetime | None = None


@dataclass
class DataElement:
    element_id: str
    principal_id: str
    element_type: str          # EMAIL, PHONE_IN, AADHAAR, PAN, NAME, FREE_TEXT ...
    token: str | None
    third_party: bool = False  # mentioned in someone else's content
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class Purpose:
    purpose_id: str
    description: str
    legal_basis: str = "consent"       # consent | legitimate_use
    retention_days: int | None = None
    legal_hold_basis: str | None = None  # e.g. "RBI KYC Master Direction"


@dataclass
class ConsentRecord:
    consent_id: str
    principal_id: str
    purpose_id: str
    element_type: str = "*"            # '*' or a specific element type
    notice_version: str = "v1"
    status: str = "granted"            # granted | withdrawn
    consent_manager_ref: str | None = None
    granted_at: datetime = field(default_factory=utcnow)
    withdrawn_at: datetime | None = None


@dataclass
class Artifact:
    artifact_id: str
    kind: str
    store: str                          # connector name that can act on it
    locator: dict[str, Any]             # how the connector finds it
    purpose_id: str | None = None
    status: str = ArtifactStatus.LIVE.value
    contains_raw_pii: bool = False      # True if written before tokenisation
    created_at: datetime = field(default_factory=utcnow)
    retain_until: datetime | None = None


@dataclass
class LineageEdge:
    parent_artifact_id: str
    child_artifact_id: str
    edge_type: str
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class ErasureRequest:
    request_id: str
    principal_id: str
    scope: str = "full"                 # full | purpose:<id>
    requested_via: str = "api"
    status: str = RequestStatus.RECEIVED.value
    received_at: datetime = field(default_factory=utcnow)
    due_by: datetime | None = None
    dry_run: bool = False


@dataclass
class PlannedAction:
    artifact: Artifact
    action: Action
    reason: str
    edge_type: str | None = None
    depth: int = 0


@dataclass
class ActionResult:
    artifact_id: str
    store: str
    action: str
    ok: bool
    detail: dict[str, Any] = field(default_factory=dict)
    executed_at: datetime = field(default_factory=utcnow)
