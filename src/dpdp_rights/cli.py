"""dpdp-rights CLI.

  dpdp-rights -c config/dpdp.local.yaml erase --external-id cust-1042 --dry-run
  dpdp-rights -c ... lineage --external-id cust-1042
  dpdp-rights -c ... certificate --request-id er_...
  dpdp-rights -c ... connectors
  dpdp-rights -c ... purge-escrows
  dpdp-rights -c ... serve --port 8080
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
    a = ap.parse_args(argv)

    dpdp = DataRightsFramework.from_yaml(a.config)
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
    else:
        import uvicorn

        from .api.app import create_app

        uvicorn.run(create_app(dpdp), host=a.host, port=a.port)
        return
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
