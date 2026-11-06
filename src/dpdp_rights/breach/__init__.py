"""Personal data breach impact assessment (DPDP Act s.8(6), Rules r.7).

Given the stores (and inventory systems) involved in a breach and when it happened, the lineage graph says who
was affected, what kinds of their data were there, in what form (raw values, or tokens that are unreadable
without the vault), which Data Processors run those systems, and what the deadlines are. The output is a signed
assessment plus *drafts* of the Board intimations and the notices to each affected Data Principal, for the DPO
to complete and send through the organisation's own channels. Nothing is sent from here.

    from dpdp_rights import DataRightsFramework
    fw = DataRightsFramework.from_file("config.yaml")
    a = fw.breach.assess(stores=["support_logs"], start="2026-11-17T22:00:00+05:30",
                         end="2026-11-18T02:00:00+05:30", aware_at="2026-11-18T09:10:00+05:30",
                         assessed_by="dpo:asha")
    fw.breach.export(a["breach_id"], "breach.zip")

What it can and cannot say is in docs/breach.md. In short: it lists only what the lineage graph records. A system
with no lineage records is reported as such ("affected people cannot be listed from the framework"), never as
zero affected.
"""
from .desk import BreachDesk, BreachError

__all__ = ["BreachDesk", "BreachError"]
