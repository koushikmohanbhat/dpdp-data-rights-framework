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
  dpdp-rights packs list | show <pack> | init <pack> --output DIR [--base cfg] | test <pack|all> [--config cfg]
"""
from __future__ import annotations

import argparse
import json
import sys

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


if __name__ == "__main__":
    main()
