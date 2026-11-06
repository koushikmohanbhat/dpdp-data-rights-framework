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
    from ..rights.rules import RuleError, resolve

    try:
        _, rule_warnings = resolve(cfg.rights.rule_set, None, cfg.rights.overrides, cfg.rights.rule_sets_dir)
        for w in rule_warnings:
            warn(f"rights rules: {w}")
    except RuleError as exc:
        err(f"rights rules: {exc}")
    if not (cfg.rights.channels and cfg.rights.identifiers and cfg.rights.contact):
        warn("rights.channels, rights.identifiers and rights.contact feed the Rule 14(1) notice; fill them in")
    if not cfg.rights.recipients:
        warn("rights.recipients is empty: access reports will not list Data Processors or other Data Fiduciaries "
             "(Act s.11(1)(b))")
    if cfg.policy.sla_days > 90:
        err("policy.sla_days is above 90")
    if cfg.evidence.required_approvals < 1:
        warn("evidence.required_approvals=0: cases are never reviewed; require at least one reviewer sign-off")
    if not cfg.evidence.reject_personal_data:
        warn("evidence.reject_personal_data=false: reviewer notes may capture personal data in case records")
    plugin_ner = set()
    for name in set(cfg.pii.detectors) - NER_DETECTORS - {"regex"}:
        try:
            from .. import plugins

            if getattr(plugins.get("detectors", name), "ner", False):   # plug-ins declare `ner = True`
                plugin_ner.add(name)
        except ValueError as exc:
            err(str(exc))
    if not (set(cfg.pii.detectors) & NER_DETECTORS) and not plugin_ner and not cfg.pii.allow_regex_only:
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
    _plugin_issues(cfg, err, warn)
    return out


def _plugin_issues(cfg: FrameworkConfig, err, warn) -> None:
    """Every connector must declare capabilities; plug-ins must load; webhooks should be signed."""
    from .. import plugins
    from ..connectors.base import connector_class

    for c in cfg.connectors:
        try:
            cls = connector_class(c.type)
        except ValueError as exc:
            err(f"connector '{c.name}': {exc}")
            continue
        if cls.capabilities is None:
            err(f"connector '{c.name}' ({c.type}) declares no capabilities: plug-in connectors must set "
                "`capabilities` so coverage reports and partners know what it can and cannot do")
    for n in cfg.notifications:
        try:
            plugins.get("notifiers", n.type)
        except ValueError as exc:
            err(str(exc))
        if n.type == "webhook" and not (n.options.get("secret") or n.options.get("secret_env")):
            warn("webhook notifier has no secret: receivers cannot verify notifications came from the framework")
        if n.type == "webhook" and n.options.get("secret"):
            warn("webhook secret is inline in the config: use secret_env and keep the secret in a secrets manager")
    for group, name in (("providers", cfg.provider.type), ("key_wrappers", cfg.vault.key_wrapper),
                        ("vault_storage", cfg.vault.storage), ("queues", cfg.queue.type)):
        try:
            plugins.get(group, name)
        except ValueError as exc:
            err(str(exc))


def enforce(cfg: FrameworkConfig) -> list[str]:
    if cfg.environment != "production":
        return []
    issues = production_issues(cfg)
    errors = [m for lvl, m in issues if lvl == "error"]
    if errors:
        raise ProductionGuardrailError("refusing to start in production:\n - " + "\n - ".join(errors))
    return [m for lvl, m in issues if lvl == "warning"]
