"""dpdp-rights CLI.

  dpdp-rights -c config/dpdp.local.yaml erase --external-id cust-1042 --dry-run
  dpdp-rights -c ... lineage --external-id cust-1042
  dpdp-rights -c ... certificate --request-id er_...
  dpdp-rights -c ... connectors
  dpdp-rights -c ... purge-escrows
  dpdp-rights -c ... serve --port 8080
  dpdp-rights -c ... worker [--once]
  dpdp-rights -c ... verify-certificate --request-id er_...
  dpdp-rights -c ... sla | check-config | hash-api-key <key>
  dpdp-rights -c ... case show|manual-action|review --request-id er_... [--format md|html|json]
  dpdp-rights -c ... evidence export --request-id er_... --output case.zip
  dpdp-rights evidence verify case.zip [--public-key key.pem | --fingerprint <sha256>]
  dpdp-rights -c ... audit-pack --from 2026-10-01 --to 2027-01-01 --output audit.zip [--inventory inv.yaml]
  dpdp-rights -c ... rights submit|show|list|decide|respond|access-report|nominations|notice|rules
  dpdp-rights -c ... breach assess --store app_log [--system "Call recordings"] --start ISO [--end ISO]
                     --aware-at ISO --by dpo:asha [--nature TEXT] [--vault-compromised] [--breach-id ID]
  dpdp-rights -c ... breach list | show ID | drafts ID --output DIR | export ID --output breach.zip | verify ID
  dpdp-rights -c ... consent history|verify --external-id ID
  dpdp-rights -c ... consent-managers list | receive NAME --body events.json --timestamp T --signature S | expire-due
  dpdp-rights -c ... children status --external-id ID --status child --basis verified [--ref REF] --by ACTOR
  dpdp-rights -c ... children guardian --external-id CHILD --guardian-external-id PARENT --method virtual_token
                     --issuer digilocker --ref REF --by ACTOR [--relationship mother]
  dpdp-rights -c ... children revoke GUARDIAN_ID --reason TEXT --by ACTOR | children show --external-id ID
  dpdp-rights -c ... pii-scan --input sample.jsonl [--format md]     # counts per detector, no values
  dpdp-rights -c ... gateway report [--since 2026-11-01T00:00:00+05:30] [--format md]
  dpdp-rights -c ... pii-benchmark [--dataset labelled.jsonl] [--min-recall NAME=0.8] [--detectors regex,remote_ner]
  dpdp-rights -c ... backfill STORE --purpose P [--apply --confirm STORE] [--unowned mask] | backfill --runs
  dpdp-rights [-c ...] scan [--store NAME] [--path exports/] [--limit 200] [--inventory-out draft.yaml]
  dpdp-rights ner-serve --model /models/IndicNER --port 8081      # the NER sidecar for remote_ner
  dpdp-rights packs list | show <pack> | init <pack> --output DIR [--base cfg] | test <pack|all> [--config cfg]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .framework import DataRightsFramework


def _pid(dpdp: DataRightsFramework, a) -> str:
    if a.principal_id:
        return a.principal_id
    pid = dpdp.vault.resolve_principal(a.external_id, create=False)
    if not pid:
        sys.exit(f"unknown data principal: {a.external_id}")
    return pid


def _rights(dpdp: DataRightsFramework, a):
    r = dpdp.rights
    if a.rights_cmd == "submit":
        fields = dict(kv.partition("=")[::2] for kv in a.set)
        pid = dpdp.vault.resolve_principal(a.external_id, create=False)
        if not pid:
            raise KeyError(f"unknown data principal: {a.external_id}")
        return r.submit(a.type, pid, requested_by=a.requested_by, verified_by=a.verified_by,
                        verification_ref=a.verification_ref, channel=a.channel, on_behalf_of=a.on_behalf_of, **fields)
    if a.rights_cmd == "show":
        return r.view(a.case_id, reveal=a.reveal)
    if a.rights_cmd == "list":
        return r.list(type=a.type, status=a.status, overdue=a.overdue)
    if a.rights_cmd == "decide":
        return r.decide(a.case_id, a.actor, a.decision, a.reason)
    if a.rights_cmd == "respond":
        return r.respond(a.case_id, a.actor, a.status, a.response)
    if a.rights_cmd == "nominations":
        pid = dpdp.vault.resolve_principal(a.external_id, create=False)
        if not pid:
            raise KeyError(f"unknown data principal: {a.external_id}")
        return r.nominations(pid)
    if a.rights_cmd == "access-report":
        from .rights.access import access_html

        rep = r.access_report(a.case_id, a.values)
        text = access_html(rep) if a.format == "html" else json.dumps(rep, indent=2, ensure_ascii=False)
    else:   # notice
        from .rights.notice import notice_html, notice_markdown, published_means

        n = published_means(dpdp)
        for g in n["gaps"]:
            print(f"warning: {g}", file=sys.stderr)
        text = (notice_markdown(n) if a.format == "md" else notice_html(n) if a.format == "html"
                else json.dumps(n, indent=2))
    if getattr(a, "output", None):
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(a.output)
    else:
        print(text)
    return None


def main(argv: list[str] | None = None) -> None:
    import signal

    if hasattr(signal, "SIGPIPE"):          # `dpdp-rights ... | head` should stop quietly
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    ap = argparse.ArgumentParser("dpdp-rights")
    ap.add_argument("-c", "--config", default="config/dpdp.local.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("erase", "lineage"):
        s = sub.add_parser(name)
        g = s.add_mutually_exclusive_group(required=True)
        g.add_argument("--external-id")
        g.add_argument("--principal-id")
        if name == "erase":
            s.add_argument("--scope", default="full")
            s.add_argument("--dry-run", action="store_true")
    c = sub.add_parser("certificate")
    c.add_argument("--request-id", required=True)
    sub.add_parser("connectors")
    sub.add_parser("purge-escrows", help="destroy retention-escrow keys whose window has ended (schedule daily)")
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=8080)
    w = sub.add_parser("worker", help="process erasure jobs from the durable queue")
    w.add_argument("--once", action="store_true", help="drain the queue once and exit (Cloud Run job / cron)")
    w.add_argument("--poll", type=float, default=5.0)
    vc = sub.add_parser("verify-certificate")
    vc.add_argument("--request-id", required=True)
    sub.add_parser("sla", help="open requests by SLA bucket and queue depth")
    sub.add_parser("check-config", help="list production guardrail issues for this config")
    hk = sub.add_parser("hash-api-key", help="print the sha256 to put in api.auth.api_keys")
    hk.add_argument("key")
    pl = sub.add_parser("plugins", help="built-in and installed plug-ins, by group")
    pl.add_argument("--format", choices=["table", "json"], default="table")
    cp = sub.add_parser("capabilities", help="what each connector type can find, do and verify")
    cp.add_argument("--format", choices=["md", "json", "doc"], default="md")
    cv = sub.add_parser("coverage", help="compare a deployment inventory with this config (offline)")
    cv.add_argument("--inventory", required=True, help="inventory YAML (see partner-pack/inventory.template.yaml)")
    cv.add_argument("--format", choices=["md", "json", "html"], default="md")
    cv.add_argument("--output", help="write to a file instead of stdout")
    cv.add_argument("--fail-on-gaps", action="store_true", help="exit 1 if any error finding (for CI)")
    cs = sub.add_parser("case", help="case record, manual actions and reviewer sign-off for one request")
    csub = cs.add_subparsers(dest="case_cmd", required=True)
    c1 = csub.add_parser("show")
    c1.add_argument("--request-id", required=True)
    c1.add_argument("--format", choices=["md", "html", "json"], default="md")
    c1.add_argument("--output")
    c2 = csub.add_parser("manual-action", help="record work done outside the framework")
    c2.add_argument("--request-id", required=True)
    c2.add_argument("--actor", required=True, help="who did it (your operator identity)")
    c2.add_argument("--system", required=True, help="system name from the deployment inventory")
    c2.add_argument("--action", required=True,
                    help="deleted | redacted | retained | processor_instructed | processor_confirmed | not_applicable | other")
    c2.add_argument("--reference", required=True, help="ticket / change / case number")
    c2.add_argument("--notes")
    c3 = csub.add_parser("review", help="approve, reject or ask for more information")
    c3.add_argument("--request-id", required=True)
    c3.add_argument("--reviewer", required=True)
    c3.add_argument("--decision", required=True, choices=["approved", "rejected", "needs_info"])
    c3.add_argument("--check", action="append", default=[], metavar="ITEM=yes|no|n/a",
                    help="answer a checklist item; repeat; --check all=yes answers every item")
    c3.add_argument("--notes")
    ev = sub.add_parser("evidence", help="signed evidence bundle for one request")
    esub = ev.add_subparsers(dest="ev_cmd", required=True)
    e1 = esub.add_parser("export")
    e1.add_argument("--request-id", required=True)
    e1.add_argument("--output", required=True)
    e2 = esub.add_parser("verify", help="check a case bundle or audit pack offline")
    e2.add_argument("bundle")
    e2.add_argument("--public-key", help="PEM you hold for the signing key (pins the key)")
    e2.add_argument("--fingerprint", help="published SHA-256 fingerprint of the signing key")
    au = sub.add_parser("audit-pack", help="signed audit pack for requests received in a period")
    au.add_argument("--from", dest="start", required=True, help="YYYY-MM-DD (inclusive)")
    au.add_argument("--to", dest="end", required=True, help="YYYY-MM-DD (exclusive)")
    au.add_argument("--output", required=True)
    au.add_argument("--inventory", help="include the coverage report for this inventory")
    au.add_argument("--no-cases", action="store_true", help="leave out per-request case records")
    au.add_argument("--fail-on-errors", action="store_true", help="exit 1 if there are error findings (for CI / cron)")
    rt = sub.add_parser("rights", help="rights cases: access, correction, nomination, grievance, erasure, withdrawal")
    rsub = rt.add_subparsers(dest="rights_cmd", required=True)
    r1 = rsub.add_parser("submit")
    r1.add_argument("--type", required=True)
    r1.add_argument("--external-id", required=True)
    r1.add_argument("--requested-by", required=True, help="who is entering the request (operator or system)")
    r1.add_argument("--verified-by")
    r1.add_argument("--verification-ref")
    r1.add_argument("--channel", default="cli")
    r1.add_argument("--on-behalf-of", help="nomination id when a nominee acts")
    r1.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="type-specific field, e.g. --set element_type=EMAIL --set new_value=... (repeat)")
    r2 = rsub.add_parser("show")
    r2.add_argument("--case-id", required=True)
    r2.add_argument("--reveal", choices=["none", "masked", "full"], default="masked")
    r3 = rsub.add_parser("list")
    r3.add_argument("--type")
    r3.add_argument("--status")
    r3.add_argument("--overdue", action="store_true")
    r4 = rsub.add_parser("decide")
    r4.add_argument("--case-id", required=True)
    r4.add_argument("--actor", required=True)
    r4.add_argument("--decision", required=True, choices=["approve", "reject"])
    r4.add_argument("--reason")
    r5 = rsub.add_parser("respond", help="grievances: acknowledge, resolve (fulfilled) or reject")
    r5.add_argument("--case-id", required=True)
    r5.add_argument("--actor", required=True)
    r5.add_argument("--status", required=True, choices=["acknowledged", "fulfilled", "rejected"])
    r5.add_argument("--response")
    r6 = rsub.add_parser("access-report")
    r6.add_argument("--case-id", required=True)
    r6.add_argument("--values", choices=["masked", "full", "none"])
    r6.add_argument("--format", choices=["json", "html"], default="json")
    r6.add_argument("--output")
    r7 = rsub.add_parser("nominations")
    r7.add_argument("--external-id", required=True)
    r8 = rsub.add_parser("notice", help="the Rule 14(1) notice to publish, from the effective rules and config")
    r8.add_argument("--format", choices=["md", "html", "json"], default="md")
    r9 = rsub.add_parser("rules", help="the effective rule set (after overrides), its hash and versions")
    r9.add_argument("--on", help="YYYY-MM-DD: the version in effect on that day")
    br = sub.add_parser("breach", help="personal data breach impact assessment (Act s.8(6), Rules r.7)")
    bsub = br.add_subparsers(dest="breach_cmd", required=True)
    b1 = bsub.add_parser("assess", help="who is affected, how, and the Rule 7 deadlines; signed and stored")
    b1.add_argument("--store", action="append", default=[], help="breached connector/store name; repeat")
    b1.add_argument("--system", action="append", default=[], help="breached inventory system name; repeat")
    b1.add_argument("--start", help="when the breach began (ISO 8601, with time zone)")
    b1.add_argument("--end", help="when it ended; omit if not yet known")
    b1.add_argument("--aware-at", help="when the organisation became aware (starts the 72-hour clock)")
    b1.add_argument("--by", required=True, dest="assessed_by", help="who is making this assessment")
    b1.add_argument("--nature", help="one line: what happened")
    b1.add_argument("--vault-compromised", action="store_true", help="the vault or its keys were also exposed")
    b1.add_argument("--breach-id", help="re-assess a known breach (each assessment is kept)")
    bsub.add_parser("list")
    b3 = bsub.add_parser("show")
    b3.add_argument("breach_id")
    b4 = bsub.add_parser("drafts", help="write Board intimations and per-person notices (Markdown, JSONL)")
    b4.add_argument("breach_id")
    b4.add_argument("--output", required=True, help="directory to write into")
    b5 = bsub.add_parser("export", help="signed bundle of the assessment and drafts")
    b5.add_argument("breach_id")
    b5.add_argument("--output", required=True)
    b6 = bsub.add_parser("verify", help="recheck every stored assessment's hash and signature")
    b6.add_argument("breach_id")
    cn = sub.add_parser("consent", help="a principal's signed consent history (Act s.6(10))")
    cnsub = cn.add_subparsers(dest="consent_cmd", required=True)
    for name in ("history", "verify"):
        x = cnsub.add_parser(name)
        x.add_argument("--external-id")
        x.add_argument("--principal-id")
    cm = sub.add_parser("consent-managers", help="registered Consent Managers (Act s.6(7)-(9), Rules r.4)")
    cmsub = cm.add_subparsers(dest="cm_cmd", required=True)
    cmsub.add_parser("list")
    cm2 = cmsub.add_parser("receive", help="apply a signed event file, exactly as the webhook would")
    cm2.add_argument("name")
    cm2.add_argument("--body", required=True, help="the request body (JSON file)")
    cm2.add_argument("--timestamp", required=True)
    cm2.add_argument("--signature", required=True)
    cmsub.add_parser("expire-due", help="expire artefacts past their validity (schedule daily)")
    ch = sub.add_parser("children", help="children and wards: status, verified guardians (Act s.9, Rules r.10-12)")
    chsub = ch.add_subparsers(dest="children_cmd", required=True)
    h1 = chsub.add_parser("status")
    h1.add_argument("--external-id", required=True)
    h1.add_argument("--status", required=True, choices=["adult", "child", "ward"])
    h1.add_argument("--basis", required=True)
    h1.add_argument("--ref", dest="verification_ref")
    h1.add_argument("--by", dest="actor", required=True)
    h2 = chsub.add_parser("guardian", help="record a verified parent or lawful guardian")
    h2.add_argument("--external-id", required=True)
    h2.add_argument("--guardian-external-id", required=True)
    h2.add_argument("--method", required=True)
    h2.add_argument("--ref", dest="verification_ref", required=True)
    h2.add_argument("--issuer")
    h2.add_argument("--relationship")
    h2.add_argument("--by", dest="actor", required=True)
    h3 = chsub.add_parser("revoke")
    h3.add_argument("guardian_id")
    h3.add_argument("--reason", required=True)
    h3.add_argument("--by", dest="actor", required=True)
    h4 = chsub.add_parser("show")
    h4.add_argument("--external-id", required=True)
    ps = sub.add_parser("pii-scan", help="what personal data a sample of conversations carries, per detector")
    ps.add_argument("--input", required=True, help=".txt (one record per line) or .jsonl (text field or messages)")
    ps.add_argument("--field", default="text")
    ps.add_argument("--format", choices=["json", "md"], default="json")
    gw = sub.add_parser("gateway", help="the model gateway (docs/gateway.md)")
    gwsub = gw.add_subparsers(dest="gateway_cmd", required=True)
    gr = gwsub.add_parser("report", help="what the gateway saw: personal data per purpose and model, decisions")
    gr.add_argument("--since")
    gr.add_argument("--until")
    gr.add_argument("--format", choices=["json", "md"], default="json")
    pb = sub.add_parser("pii-benchmark", help="precision and recall of the configured detectors on a labelled set")
    pb.add_argument("--dataset", help="JSON Lines labelled set (default: the built-in synthetic indic-pii-v1)")
    pb.add_argument("--label-studio", help="a Label Studio JSON export instead of --dataset")
    pb.add_argument("--label-map", action="append", default=[], help="Label Studio label=TYPE, e.g. PERSON=NAME")
    pb.add_argument("--detectors", help="comma-separated, overriding pii.detectors, e.g. regex,remote_ner")
    pb.add_argument("--match", choices=["overlap", "exact"], default="overlap")
    pb.add_argument("--min-recall", action="append", default=[], help="TYPE=0.9 (ALL for overall); exit 1 if below")
    pb.add_argument("--min-precision", action="append", default=[], help="TYPE=0.9 (ALL for overall)")
    pb.add_argument("--format", choices=["json", "md"], default="md")
    bf = sub.add_parser("backfill", help="tokenise personal data already in a store, in place (dry run by default)")
    bf.add_argument("store", nargs="?", help="connector name (sql_table with content_column, jsonl_dataset with "
                                              "text_field)")
    bf.add_argument("--purpose", help="the purpose the store's data is held for")
    bf.add_argument("--apply", action="store_true", help="rewrite the store; needs --confirm <store>")
    bf.add_argument("--confirm", help="the store name again, to confirm an --apply")
    bf.add_argument("--batch", type=int, default=100)
    bf.add_argument("--limit", type=int, help="stop after this many items")
    bf.add_argument("--unowned", choices=["skip", "mask"], default="skip",
                    help="items with personal data but no owner: leave raw and list (skip) or mask irreversibly")
    bf.add_argument("--id-type", default="EXTERNAL_ID", help="how owner values resolve in the vault")
    bf.add_argument("--resume", help="continue a failed run from its last finished batch")
    bf.add_argument("--price-per-million", type=float, help="embedding price per million tokens, for the estimate")
    bf.add_argument("--runs", action="store_true", help="list backfill runs")
    bf.add_argument("--format", choices=["json", "md"], default="md")
    sc = sub.add_parser("scan", help="read-only: where raw personal data sits today, in stores and exported files")
    sc.add_argument("--store", action="append", default=[], help="a connector name from the config (default: all)")
    sc.add_argument("--no-stores", action="store_true", help="scan only --path files, not the configured stores")
    sc.add_argument("--path", action="append", default=[], help="an exported file or folder (.log .txt .json .jsonl "
                                                               ".ndjson .csv, also .gz)")
    sc.add_argument("--limit", type=int, default=200, help="items sampled per source (max 10000)")
    sc.add_argument("--detectors", help="comma-separated, overriding pii.detectors")
    sc.add_argument("--format", choices=["json", "md"], default="md")
    sc.add_argument("--inventory-out", help="write draft inventory entries (YAML) for the coverage report")
    sc.add_argument("--client", default="<client name>")
    ns = sub.add_parser("ner-serve", help="serve an NER model (default AI4Bharat IndicNER) on localhost for remote_ner")
    ns.add_argument("--model", default="ai4bharat/IndicNER", help="Hugging Face id or a local path baked into the image")
    ns.add_argument("--host", default="127.0.0.1")
    ns.add_argument("--port", type=int, default=8081)
    ns.add_argument("--include-locations", action="store_true")
    ns.add_argument("--min-score", type=float, default=0.7)
    pk = sub.add_parser("packs", help="domain packs: insurance, lending, healthcare")
    psub = pk.add_subparsers(dest="packs_cmd", required=True)
    psub.add_parser("list")
    p2 = psub.add_parser("show")
    p2.add_argument("pack")
    p3 = psub.add_parser("init", help="start an engagement folder from a pack")
    p3.add_argument("pack")
    p3.add_argument("--output", required=True)
    p3.add_argument("--base", help="base config to merge into (e.g. config/dpdp.production.aws.yaml)")
    p4 = psub.add_parser("test", help="run a pack's offline scenarios")
    p4.add_argument("pack", help="pack id, or 'all'")
    p4.add_argument("--config", dest="client_config", help="test a client's config instead of the pack's settings")
    p4.add_argument("--scenarios", help="scenario file (default: the pack's)")
    p4.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "ner-serve":
        from .pii.ner_server import serve

        serve(a.model, a.host, a.port, a.include_locations, a.min_score)
        return
    if a.cmd == "scan":                              # config only: detectors and connectors, read-only
        import yaml as _yaml

        from . import scan as sc_
        from .connectors.base import build_connectors
        from .core.config import FrameworkConfig, PIIConfig
        from .pii.detectors import build_detector

        args = sys.argv[1:] if argv is None else argv
        explicit = any(x in ("-c", "--config") or x.startswith("--config=") for x in args)
        cfg = FrameworkConfig.load(a.config) if explicit else None    # the demo default is never scanned
        pii = cfg.pii if cfg else PIIConfig()
        if a.detectors:
            pii = pii.model_copy(update={"detectors": [d.strip() for d in a.detectors.split(",") if d.strip()]})
        if "llm" in pii.detectors:
            sys.exit("scan does not run the llm detector (it would send raw text to a model)")
        conns = {}
        if cfg and not a.no_stores:
            chosen = [c for c in cfg.connectors if not a.store or c.name in a.store]
            missing = set(a.store) - {c.name for c in cfg.connectors}
            if missing:
                sys.exit(f"unknown stores: {sorted(missing)}")
            conns = build_connectors(chosen)
        if not conns and not a.path:
            sys.exit("nothing to scan: give --path, or a config with connectors")
        try:
            rep = sc_.scan(build_detector(pii), conns, a.path, a.limit)
        except ValueError as e:
            sys.exit(str(e))
        rep["detectors"] = pii.detectors
        if a.inventory_out:
            out_p = Path(a.inventory_out)
            if out_p.exists():
                sys.exit(f"{out_p} exists; not overwriting")
            out_p.write_text(sc_.DRAFT_HEADER
                             + _yaml.safe_dump(sc_.draft_inventory(rep, a.client), sort_keys=False, allow_unicode=True))
        print(sc_.markdown(rep) if a.format == "md" else json.dumps(rep, indent=2, default=str), end="")
        return
    if a.cmd == "pii-benchmark":                     # config only: detectors, no vault or database
        from .core.config import FrameworkConfig
        from .pii import benchmark as bm
        from .pii.detectors import build_detector

        def pairs(items, cast=float):
            out = {}
            for it in items:
                k, _, v = it.partition("=")
                if not v:
                    sys.exit(f"expected KEY=VALUE, got {it}")
                out[k] = cast(v)
            return out
        pii = FrameworkConfig.load(a.config).pii
        if a.detectors:
            pii = pii.model_copy(update={"detectors": [d.strip() for d in a.detectors.split(",") if d.strip()]})
        if "llm" in pii.detectors:
            sys.exit("pii-benchmark does not run the llm detector; benchmark it through your own harness")
        recs = (bm.from_label_studio(a.label_studio, pairs(a.label_map, str)) if a.label_studio
                else bm.load(a.dataset))
        rep = bm.benchmark(recs, build_detector(pii), a.match)
        rep["dataset"] = a.label_studio or a.dataset or bm.DATASET_VERSION
        rep["detectors"] = pii.detectors
        fails = bm.check_thresholds(rep, pairs(a.min_recall), pairs(a.min_precision))
        rep["threshold_failures"] = fails
        print(bm.markdown(rep, f"PII benchmark: {', '.join(pii.detectors)} on {rep['dataset']}") if a.format == "md"
              else json.dumps(rep, indent=2))
        for f_ in fails:
            print(f"below threshold: {f_}", file=sys.stderr)
        sys.exit(1 if fails else 0)
    if a.cmd == "packs":
        from . import packs

        if a.packs_cmd == "list":
            for pid in packs.available():
                p = packs.load(pid)
                print(f"{pid:<12} {p['version']:<10} {p['title']}")
            return
        if a.packs_cmd == "show":
            p = packs.load(a.pack)
            print(json.dumps({k: v for k, v in p.items() if not k.startswith("_")}, indent=2, ensure_ascii=False))
            return
        if a.packs_cmd == "init":
            for path in packs.init(a.pack, a.output, a.base):
                print(path)
            return
        ids = packs.available() if a.pack == "all" else [a.pack]
        failed = 0
        for pid in ids:
            res = packs.test(pid, a.client_config, a.scenarios)
            bad = [r for r in res if not r.ok]
            failed += len(bad)
            print(f"{pid}: {len(res) - len(bad)}/{len(res)} checks passed")
            for r in res:
                if not r.ok or a.verbose:
                    print(f"  {'ok  ' if r.ok else 'FAIL'} {r.scenario} / {r.step}" + (f": {'; '.join(r.failures)}" if r.failures else ""))
        sys.exit(1 if failed else 0)

    if a.cmd == "rights" and a.rights_cmd == "notice":    # config only: works before anything is deployed
        from .core.config import FrameworkConfig
        from .rights.notice import notice_html, notice_markdown, published_means

        n = published_means(FrameworkConfig.load(a.config))
        for g in n["gaps"]:
            print(f"warning: {g}", file=sys.stderr)
        print(notice_markdown(n) if a.format == "md" else notice_html(n) if a.format == "html" else json.dumps(n, indent=2))
        return
    if a.cmd == "rights" and a.rights_cmd == "rules":
        from .core.config import FrameworkConfig
        from .rights.rules import resolve, versions

        rc = FrameworkConfig.load(a.config).rights
        rs, warnings = resolve(rc.rule_set, a.on, rc.overrides, rc.rule_sets_dir)
        print(json.dumps({"effective": rs.describe(), "warnings": warnings,
                          "versions": versions(rc.rule_set, rc.rule_sets_dir)}, indent=2, default=str))
        return

    if a.cmd == "evidence" and a.ev_cmd == "verify":
        from .evidence.bundle import verify_bundle

        pem = open(a.public_key, encoding="utf-8").read() if a.public_key else None
        out = verify_bundle(a.bundle, public_key_pem=pem, fingerprint=a.fingerprint)
        print(json.dumps(out, indent=2))
        sys.exit(0 if out["ok"] else 1)

    if a.cmd == "plugins":
        from . import plugins

        rows = plugins.listing()
        if a.format == "json":
            print(json.dumps([r.__dict__ for r in rows], indent=2))
        else:
            for r in rows:
                print(f"{r.group:<14} {r.name:<26} {r.source:<28} {r.error or ''}")
        sys.exit(1 if any(r.error for r in rows) else 0)
    if a.cmd == "capabilities":
        from .delivery.capabilities import capabilities_doc, load_matrix, matrix_markdown

        print(capabilities_doc() if a.format == "doc" else matrix_markdown() if a.format == "md"
              else json.dumps(load_matrix(), indent=2), end="" if a.format == "doc" else "\n")
        return
    if a.cmd == "coverage":
        from .core.config import FrameworkConfig
        from .delivery.inventory import Inventory, coverage_report, to_html, to_json, to_markdown

        rep = coverage_report(Inventory.load(a.inventory), FrameworkConfig.load(a.config))
        text = {"md": to_markdown, "json": to_json, "html": to_html}[a.format](rep)
        if a.output:
            with open(a.output, "w", encoding="utf-8") as f:
                f.write(text)
            s = rep["summary"]
            print(f"{a.output}: {s['in_scope']} systems with personal data, {s['automated_pct']}% automated, "
                  f"{s['tested_pct']}% tested, gaps {s['gaps']}, errors {s['errors']}, warnings {s['warnings']}")
        else:
            print(text, end="")
        sys.exit(1 if a.fail_on_gaps and rep["summary"]["errors"] else 0)

    if a.cmd == "hash-api-key":
        from .security.auth import hash_api_key

        print(hash_api_key(a.key))
        return
    if a.cmd == "check-config":
        from .core.config import FrameworkConfig
        from .security.guardrails import production_issues

        issues = production_issues(FrameworkConfig.load(a.config))
        print(json.dumps([{"level": lvl, "issue": m} for lvl, m in issues], indent=2))
        sys.exit(1 if any(lvl == "error" for lvl, _ in issues) else 0)

    dpdp = DataRightsFramework.from_yaml(a.config)
    if dpdp.config.observability.otel and a.cmd in ("serve", "worker"):
        from .observability.telemetry import install

        install(dpdp)
    if a.cmd == "erase":
        out = dpdp.erase(_pid(dpdp, a), scope=a.scope, dry_run=a.dry_run, requested_via="cli")
    elif a.cmd == "lineage":
        out = dpdp.lineage(_pid(dpdp, a))
    elif a.cmd == "certificate":
        cert = dpdp.store.get_certificate(a.request_id)
        out = {"sha256": cert["sha256"], "payload": json.loads(cert["payload"])} if cert else {"error": "not found"}
    elif a.cmd == "purge-escrows":
        out = dpdp.purge_due_escrows()
    elif a.cmd == "connectors":
        out = {n: type(c).type_name for n, c in dpdp.connectors.items()}
    elif a.cmd == "verify-certificate":
        out = dpdp.verify_certificate(a.request_id)
    elif a.cmd == "case":
        from .evidence.case import EvidenceError

        try:
            if a.case_cmd == "show":
                from .evidence.render import case_html, case_markdown

                c = dpdp.case(a.request_id)
                text = (case_markdown(c) if a.format == "md" else case_html(c) if a.format == "html"
                        else json.dumps(c, indent=2, default=str, ensure_ascii=False))
                if a.output:
                    with open(a.output, "w", encoding="utf-8") as f:
                        f.write(text)
                    print(f"{a.output}: sign-off {c['sign_off']['state']}")
                else:
                    print(text)
                return
            if a.case_cmd == "manual-action":
                out = dpdp.record_manual_action(a.request_id, a.actor, system=a.system, action=a.action,
                                                reference=a.reference, notes=a.notes)
            else:
                ids = [i.id for i in dpdp.config.evidence.review_checklist]
                checklist: dict = {}
                for item in a.check:
                    k, _, v = item.partition("=")
                    val = {"yes": True, "true": True, "no": False, "false": False}.get(v.lower(), v.lower())
                    for key in (ids if k == "all" else [k]):
                        checklist[key] = val
                out = dpdp.review(a.request_id, a.reviewer, decision=a.decision, checklist=checklist, notes=a.notes)
        except (EvidenceError, KeyError) as e:
            sys.exit(f"refused: {e}")
    elif a.cmd == "evidence":
        out = dpdp.export_evidence(a.request_id, a.output)
        out = {"path": out["path"], "bytes": out["bytes"], "files": list(out["manifest"]["files"]),
               "signed": bool(out["manifest"]["signer"]), "key_fingerprint": out["manifest"]["key_fingerprint"]}
    elif a.cmd == "audit-pack":
        from .evidence.audit import parse_day

        inv = None
        if a.inventory:
            from .delivery.inventory import Inventory

            inv = Inventory.load(a.inventory)
        res = dpdp.export_audit_pack(parse_day(a.start), parse_day(a.end), a.output, inventory=inv,
                                     include_cases=not a.no_cases)
        rep = res["report"]
        m = rep["metrics"]
        errors = sum(1 for f in rep["findings"] if f["level"] == "error")
        print(f"{a.output}: {m['requests_received']} requests, {m['completed_within_sla_pct']}% within SLA, "
              f"{m['signed_off_pct']}% signed off, findings {len(rep['findings'])} ({errors} errors), "
              f"chain {'ok' if rep['certificate_chain']['hash_ok'] and rep['certificate_chain']['links_ok'] else 'BROKEN'}")
        sys.exit(1 if a.fail_on_errors and errors else 0)
    elif a.cmd == "rights":
        from .rights.desk import RightsError
        from .rights.rules import RuleError

        try:
            out = _rights(dpdp, a)
        except (RightsError, RuleError, KeyError) as e:
            sys.exit(f"refused: {e}")
        if out is None:
            return
    elif a.cmd == "breach":
        from .breach import BreachError

        try:
            out = _breach(dpdp, a)
        except BreachError as e:
            sys.exit(f"refused: {e}")
    elif a.cmd == "backfill":
        from . import backfill as bf_
        from .evidence.case import iso

        if a.runs:
            out = [{**{k: r[k] for k in ("run_id", "store", "purpose_id", "status", "counts", "error", "started_by")},
                    "started_at": iso(r["started_at"]), "updated_at": iso(r["updated_at"])}
                   for r in dpdp.store.backfill_runs()]
        else:
            if not a.store or not a.purpose:
                sys.exit("give the store and --purpose (or --runs)")
            try:
                rep = bf_.run(dpdp, a.store, a.purpose, apply=a.apply, confirm=a.confirm, batch=a.batch,
                              limit=a.limit, unowned=a.unowned, id_type=a.id_type, resume=a.resume)
            except bf_.BackfillError as e:
                sys.exit(f"refused: {e}")
            d = rep.to_dict(a.price_per_million)
            if a.format == "md":
                print(bf_.markdown(d), end="")
                return
            out = d
    elif a.cmd == "pii-scan":
        from .pii.scan import read_sample, scan, scan_markdown

        rep = scan(read_sample(a.input, a.field), dpdp.tokenizer.detector)
        if a.format == "md":
            print(scan_markdown(rep), end="")
            return
        out = rep
    elif a.cmd == "gateway":
        from datetime import datetime

        from .gateway import report_markdown

        def when(v):
            if not v:
                return None
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if d.tzinfo is None:
                sys.exit("times need a time zone, e.g. 2026-11-01T00:00:00+05:30")
            return d
        rep = dpdp.gateway.report(when(a.since), when(a.until))
        if a.format == "md":
            print(report_markdown(rep), end="")
            return
        out = rep
    elif a.cmd == "consent":
        pid = _pid(dpdp, a)
        out = dpdp.consent_history.events(pid) if a.consent_cmd == "history" else dpdp.consent_history.verify(pid)
        if a.consent_cmd == "verify":
            print(json.dumps(out, indent=2))
            sys.exit(0 if out["ok"] else 1)
    elif a.cmd == "consent-managers":
        from .consent.managers import CmEventError, SignatureError

        if a.cm_cmd == "list":
            out = dpdp.consent_managers.describe()
        elif a.cm_cmd == "expire-due":
            out = dpdp.consent_managers.expire_due()
        else:
            try:
                out = dpdp.consent_managers.receive(a.name, {"X-CM-Timestamp": a.timestamp,
                                                             "X-CM-Signature": a.signature},
                                                    Path(a.body).read_bytes())
            except (KeyError, SignatureError, CmEventError) as e:
                sys.exit(f"refused: {e}")
    elif a.cmd == "children":
        from .consent.children import ChildrenError

        c = dpdp.children
        try:
            if a.children_cmd == "status":
                out = c.set_status(dpdp.principal(a.external_id), a.status, basis=a.basis, set_by=a.actor,
                                   verification_ref=a.verification_ref)
            elif a.children_cmd == "guardian":
                child = dpdp.vault.resolve_principal(a.external_id, create=False)
                if not child:
                    raise KeyError(f"unknown data principal: {a.external_id}")
                out = c.record_guardian(child, dpdp.principal(a.guardian_external_id), method=a.method,
                                        verification_ref=a.verification_ref, verified_by=a.actor, issuer=a.issuer,
                                        relationship=a.relationship)
            elif a.children_cmd == "revoke":
                out = c.revoke_guardian(a.guardian_id, reason=a.reason, actor=a.actor)
            else:
                pid = dpdp.vault.resolve_principal(a.external_id, create=False)
                if not pid:
                    raise KeyError(f"unknown data principal: {a.external_id}")
                out = c.view(pid)
        except (ChildrenError, KeyError) as e:
            sys.exit(f"refused: {e}")
    elif a.cmd == "sla":
        out = {"open_requests": dpdp.sla_counts(), "rights_cases": dpdp.rights.sla_counts(), "jobs": dpdp.queue.counts()}
    elif a.cmd == "worker":
        import time

        while True:
            for r in dpdp.process_jobs():
                print(json.dumps(r, default=str), flush=True)
            if a.once:
                return
            time.sleep(a.poll)
    else:
        import uvicorn

        from .api.app import create_app

        uvicorn.run(create_app(dpdp), host=a.host, port=a.port, server_header=False)
        return
    print(json.dumps(out, indent=2, default=str))


def _breach(dpdp, a):
    b = dpdp.breach
    if a.breach_cmd == "assess":
        r = b.assess(stores=a.store, systems=a.system, start=a.start, end=a.end, aware_at=a.aware_at,
                     assessed_by=a.assessed_by, nature=a.nature, vault_compromised=a.vault_compromised,
                     breach_id=a.breach_id)
        return {k: r[k] for k in ("breach_id", "assessment_id", "totals", "deadlines", "notes", "signed")}
    if a.breach_cmd == "list":
        return b.list()
    if a.breach_cmd == "show":
        return b.get(a.breach_id)
    if a.breach_cmd == "verify":
        out = b.verify(a.breach_id)
        if not out["ok"]:
            print(json.dumps(out, indent=2))
            sys.exit(1)
        return out
    if a.breach_cmd == "drafts":
        d, root = b.drafts(a.breach_id), Path(a.output)
        root.mkdir(parents=True, exist_ok=True)
        (root / "board-initial.md").write_text(d["board_initial"])
        (root / "board-detailed.md").write_text(d["board_detailed"])
        (root / "notices.jsonl").write_text("".join(json.dumps(n, ensure_ascii=False) + "\n" for n in d["notices"]))
        return {"output": str(root), "files": ["board-initial.md", "board-detailed.md", "notices.jsonl"],
                "notices": len(d["notices"])}
    out = b.export(a.breach_id, a.output)
    return {"path": out["path"], "files": out["files"], "signed": bool(out["manifest"].get("signer")),
            "key_fingerprint": out["manifest"].get("key_fingerprint")}


if __name__ == "__main__":
    main()
