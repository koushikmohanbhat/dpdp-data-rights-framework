# Personal data breach: impact assessment and draft intimations

DPDP Act s.8(6) and Rules r.7 require a Data Fiduciary to intimate **every** personal data breach (there is no
risk threshold) to each affected Data Principal and to the Data Protection Board. The hard part in an AI system is
answering *who* was affected, *what* of theirs was there and *in what form*. The lineage graph already records
that, so the framework can produce the assessment in minutes and draft the intimations.

**What this covers:** impact assessment from lineage records, Rule 7 deadlines, and drafts of the Board
intimations and the notices to Data Principals, signed and stored.
**What it does not cover:** detecting a breach, investigating it, deciding the facts, or sending anything.
Those stay with the organisation's incident response; the drafts mark every fact the DPO must supply.

The rules apply from 13 May 2027. Have counsel review the `breach` section of the rule set (see
[rights](rights.md#legal-rules)) as you do the rest.

## The deadlines (rule set `dpdp-in` 2025.11-2 and later)

| Who | When | Basis |
|---|---|---|
| Each affected Data Principal | Without delay, through their account or registered contact | Rules r.7(1)(a) |
| Data Protection Board, initial intimation | Without delay | Rules r.7(2)(a) |
| Data Protection Board, detailed report | Within **72 hours** of becoming aware; the Board may extend this on a written request | Rules r.7(2)(b) |

The 72-hour clock runs from `aware_at`, the time the organisation became aware, not from when the breach
happened. The deadlines and the headings of each draft come from the versioned rule set, so an assessment records
which version it used.

## Run an assessment

```bash
dpdp-rights -c config.yaml breach assess \
  --store app_log --system "Contact-centre call recordings" \
  --start 2026-11-17T22:00:00+05:30 --aware-at 2026-11-18T09:00:00+05:30 \
  --nature "Unauthorised read access to the application log bucket" --by dpo:asha
dpdp-rights -c config.yaml breach drafts brc_... --output breach/
dpdp-rights -c config.yaml breach export brc_... --output breach.zip     # signed bundle
dpdp-rights evidence verify breach.zip --fingerprint <published sha256>
```

- `--store` names a connector; `--system` names a system in the deployment inventory (`rights.inventory_path`),
  which adds its platform, region and processor. Repeat either.
- `--end` is optional. Without it the drafts say "until at least <time> (end not yet known)".
- `--vault-compromised` when the vault or its keys were exposed too.
- `--breach-id brc_...` re-assesses a known breach as facts change. Every assessment is kept, signed, and shown in
  the breach's history; `breach show` returns the latest.

The API is the same: `POST /v1/breaches` (role `dpo`; the assessor is the authenticated caller, never a body
field), `GET /v1/breaches`, `GET /v1/breaches/{id}`, `/drafts` (dpo), `/verify` and `/bundle` (dpo or reviewer).
In the SDK: `fw.breach.assess(...)`, `.get`, `.list`, `.drafts`, `.export`, `.verify`.

## What the assessment says

**Affected Data Principals.** Everyone with an element linked to a live artifact in a breached store, up to the
end of the window. For each: the categories of data (never the values), the stores, whether they were only
*mentioned* in someone else's record (a nominee named in an application), whether a contact is on record, and
their **exposure**:

| Exposure | Meaning | Notice wording |
|---|---|---|
| `raw` | The artifact was written before tokenisation (`contains_raw_pii`) | Someone may have seen this information |
| `tokens_readable` | Tokens, and the vault was also compromised | Someone may have been able to read it |
| `tokens` | Tokens only; unreadable without the separately secured vault | Stored in a protected form that cannot be read without a separate key |
| `key_destroyed` | The person had already been erased; their key is gone | Cannot be read by anyone |

Every level is still a breach to intimate. The level shapes the "likely consequences" text; whether a tokenised
exposure causes harm is for the DPO to judge, and the draft asks for that judgement.

**Possibly affected.** People whose data is in the store only through a derived summary, aggregate or model, and
people whose data was in an artifact since erased (check whether it was removed before the breach). They are
listed separately with the reason.

**Systems.** Each breached store with record counts, the people in it, how many artifacts held raw values, and,
from the inventory, platform, region, processor and the processor contract clause.

**What it cannot see, said plainly.** A store with no lineage records in the window, and an inventory system with
no connector, are listed with a note that affected people **cannot be listed from the framework**. They are never
counted as zero. The drafts carry an "Incomplete" line until the DPO resolves them from the systems themselves.

## The drafts

| File | Contents |
|---|---|
| `board-initial.md` | Rule 7(2)(a): description (nature, extent, timing, location) and likely impact |
| `board-detailed.md` | Rule 7(2)(b): updated description; facts and reasons; mitigation; findings on who caused it; remedial measures; report on intimations to Data Principals; the due time |
| `notices.jsonl` | One draft per affected Data Principal with the five Rule 7(1)(a) parts: what happened, what it involved, what it may mean, what we have done, what you can do, plus the contact |
| `summary.md` | Deadlines, extent and systems on one page |
| `report.json` | The full assessment |

Facts the framework knows are filled in. Everything else is a visible `[DPO: ...]` placeholder. The drafts hold
pseudonymous principal ids and categories only, so they can be reviewed and circulated before anyone resolves
contacts. To send, resolve each `principal_id` to its contact through your own channel (with `reveal`, under your
access controls) and deliver through it. People already erased get no notice, since no contact remains; the
detailed report counts them.

## Evidence

Each assessment is stored in `breach_assessment` with the report, its SHA-256 and a signature from the
certificate signer. `breach verify` recomputes every stored hash and checks every signature. The exported bundle
is verified offline by `dpdp-rights evidence verify`, with the same key pinning as case bundles
([evidence](evidence.md)).

## Limits

- It knows only what the lineage graph records. Coverage depends on routing data through `protect()` and
  registering artifacts; run the [coverage report](getting-started.md) before you need this.
- "Within the window" uses each artifact's creation time. An artifact's content can change later (a redaction);
  the assessment does not replay history.
- Large stores: the assessment reads every artifact in the named stores; for millions of artifacts, narrow the
  window or run it from a worker.
- Escalation, regulator portals and delivery are integrations for your incident tooling (notifier plug-ins).
