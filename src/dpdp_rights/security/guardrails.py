"""Production guardrails: refuse to start with settings that are only safe for development."""
from __future__ import annotations

from ..core.config import FrameworkConfig

NER_DETECTORS = {"aws_comprehend", "bedrock_guardrail", "gcp_dlp", "presidio", "transformers_ner", "llm"}


class ProductionGuardrailError(RuntimeError):
    pass


def production_issues(cfg: FrameworkConfig) -> list[tuple[str, str]]:
    """Returns (level, message) pairs. level is 'error' (blocks startup) or 'warning'."""
    out: list[tuple[str, str]] = []

    def err(m):
        out.append(("error", m))

    def warn(m):
        out.append(("warning", m))

    if cfg.vault.key_wrapper == "local":
        err("vault.key_wrapper=local stores the master key on disk; use aws_kms or gcp_kms")
    if cfg.vault.sealed_key_wrapper is None:
        warn("vault.sealed_key_wrapper not set: sealed data uses the application KEK; use a separate "
             "KMS key that only a break-glass role can decrypt")
    elif cfg.vault.sealed_key_wrapper == "local":
        err("vault.sealed_key_wrapper=local is for development only")
    if cfg.provider.type == "echo":
        err("provider.type=echo is an offline test model")
    if cfg.lineage.url.startswith("sqlite"):
        err("lineage.url is SQLite; use PostgreSQL (Aurora, RDS, Cloud SQL, AlloyDB)")
    if cfg.vault.storage == "sql" and (cfg.vault.sql_url or cfg.lineage.url) == cfg.lineage.url:
        warn("vault shares the lineage database; put the vault in a separate account/project")
    if cfg.api.auth.mode == "none":
        err("api.auth.mode=none: the Rights API would accept unauthenticated requests")
    for k in cfg.api.auth.api_keys:
        if len(k.sha256) != 64:
            err(f"api key '{k.name}' must be configured as a 64-char sha256 hex digest")
    if cfg.certificates.signer == "none":
        err("certificates.signer=none: certificates are hash-chained but unsigned")
    elif cfg.certificates.signer == "local":
        warn("certificates.signer=local keeps the signing key on disk; prefer aws_kms or gcp_kms")
    if cfg.certificates.archive == "s3" and cfg.certificates.archive_mode != "COMPLIANCE":
        warn("certificates.archive_mode=GOVERNANCE lets privileged users delete certificates; use COMPLIANCE")
    if cfg.certificates.archive in ("none", "local"):
        warn("certificates.archive is not immutable; use s3 (Object Lock) or gcs (locked retention)")
    if not (set(cfg.pii.detectors) & NER_DETECTORS) and not cfg.pii.allow_regex_only:
        err("pii.detectors has no NER detector; regex misses names, addresses and free-text disclosures. "
            "Add aws_comprehend, bedrock_guardrail, gcp_dlp, presidio or transformers_ner "
            "(or set pii.allow_regex_only after review)")
    if "llm" in cfg.pii.detectors:
        llm = cfg.pii.llm
        if llm is None:
            err("pii.detectors includes llm but pii.llm (the detection model) is not configured")
        else:
            if llm.type == "echo":
                err("pii.llm.type=echo is an offline test model")
            warn(f"the llm PII detector sends raw text to {llm.type}/{llm.model or 'default'} before tokenisation; "
                 "use a model you control in your region with prompt logging and retention off")
            if llm.type == "openai" or (llm.type == "anthropic" and llm.platform == "anthropic"):
                warn("pii.llm uses a direct third-party API: raw personal data leaves your cloud for detection; "
                     "prefer Bedrock or Vertex in-region, or a zero-data-retention agreement")
            if (llm.type, llm.model) == (cfg.provider.type, cfg.provider.model):
                warn("pii.llm is the same model as provider: keep detection separate so the agent's model only "
                     "ever receives tokenised text")
    if cfg.vault.cache_ttl_seconds > 900:
        warn("vault.cache_ttl_seconds > 900 keeps unwrapped keys in memory for a long time")
    return out


def enforce(cfg: FrameworkConfig) -> list[str]:
    if cfg.environment != "production":
        return []
    issues = production_issues(cfg)
    errors = [m for lvl, m in issues if lvl == "error"]
    if errors:
        raise ProductionGuardrailError("refusing to start in production:\n - " + "\n - ".join(errors))
    return [m for lvl, m in issues if lvl == "warning"]
