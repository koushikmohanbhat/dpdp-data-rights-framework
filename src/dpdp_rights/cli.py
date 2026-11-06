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


def main(argv: list[str] | None = None) -> None:
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
    cp = sub.add_parser("capabilities", help="what each connector type can find, do and verify")
    cp.add_argument("--format", choices=["md", "json", "doc"], default="md")
    cv = sub.add_parser("coverage", help="compare a deployment inventory with this config (offline)")
    cv.add_argument("--inventory", required=True, help="inventory YAML (see partner-pack/inventory.template.yaml)")
    cv.add_argument("--format", choices=["md", "json", "html"], default="md")
    cv.add_argument("--output", help="write to a file instead of stdout")
    cv.add_argument("--fail-on-gaps", action="store_true", help="exit 1 if any error finding (for CI)")
    a = ap.parse_args(argv)

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
    elif a.cmd == "sla":
        out = {"open_requests": dpdp.sla_counts(), "jobs": dpdp.queue.counts()}
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
