"""dpdp-erasure CLI.

  dpdp-erasure -c config/dpdp.local.yaml erase --external-id cust-1042 --dry-run
  dpdp-erasure -c ... lineage --external-id cust-1042
  dpdp-erasure -c ... certificate --request-id er_...
  dpdp-erasure -c ... connectors
  dpdp-erasure -c ... purge-escrows
  dpdp-erasure -c ... serve --port 8080
"""
from __future__ import annotations

import argparse
import json
import sys

from .kit import ErasureKit


def _pid(kit: ErasureKit, a) -> str:
    if a.principal_id:
        return a.principal_id
    pid = kit.vault.resolve_principal(a.external_id, create=False)
    if not pid:
        sys.exit(f"unknown data principal: {a.external_id}")
    return pid


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser("dpdp-erasure")
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

    kit = ErasureKit.from_yaml(a.config)
    if a.cmd == "erase":
        out = kit.erase(_pid(kit, a), scope=a.scope, dry_run=a.dry_run, requested_via="cli")
    elif a.cmd == "lineage":
        out = kit.lineage(_pid(kit, a))
    elif a.cmd == "certificate":
        cert = kit.store.get_certificate(a.request_id)
        out = {"sha256": cert["sha256"], "payload": json.loads(cert["payload"])} if cert else {"error": "not found"}
    elif a.cmd == "purge-escrows":
        out = kit.purge_due_escrows()
    elif a.cmd == "connectors":
        out = {n: type(c).type_name for n, c in kit.connectors.items()}
    else:
        import uvicorn

        from .api.app import create_app

        uvicorn.run(create_app(kit), host=a.host, port=a.port)
        return
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
