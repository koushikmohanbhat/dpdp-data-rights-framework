# Brownfield backfill: tokenise data already in a store

Instrumenting an agent protects what it writes from now on. But most clients already have RAG chunks, tickets, transcripts and eval sets full of raw values, written before the framework existed. Until those are dealt with, an erasure or access request has to search them by content every time, and a breach of them exposes raw values.

`dpdp-rights backfill` tokenises such a store **in place**:
- each item gets its owner's tokens;
- vectors are re-computed from the tokenised text;
- every item is registered in lineage after the fact.

From then on, erasure, access reports and breach assessment treat the old data like new data. The application keeps working.

```bash
dpdp-rights -c client.yaml scan --store rag_chunks                       # 1. where are raw values? (read-only)
dpdp-rights -c client.yaml backfill rag_chunks --purpose support \
    --price-per-million 0.02                                             # 2. dry run: what would change, and the cost
# 3. take a backup or snapshot of the store
dpdp-rights -c client.yaml backfill rag_chunks --purpose support --apply --confirm rag_chunks
dpdp-rights -c client.yaml backfill --runs                               # 4. the run record
dpdp-rights -c client.yaml scan --store rag_chunks                       # 5. check: raw values left?
```

## Stores

| Connector | Needs | What is rewritten |
|---|---|---|
| `sql_table` (including pgvector, Aurora, Cloud SQL, AlloyDB) | `content_column`; the owner in `owner_column` (default `principal_column`) | The content column, and `embedding_column` re-computed with the configured embedding model |
| `jsonl_dataset` (eval and fine-tuning sets on disk, S3 or GCS) | `text_field`; the owner in `owner_field` | The text field, and `embedding_field` if set |

Rows are processed in id order (file order for JSONL), in batches (`--batch`, default 100). Each batch is written in one transaction.

Managed vector services (OpenSearch, Vertex Vector Search, Bedrock Knowledge Bases, Pinecone) are not rewritten in place yet. For those, run the backfill on the source table or files and re-ingest them through the usual pipeline. The [scan](scan.md) and the vector connectors on the roadmap cover the rest.

## Whose data it is

Every person has their own key, so every value needs an owner. The backfill takes it from the owner field, usually the customer id the document is filed under, and resolves it through the vault (`--id-type`, default `EXTERNAL_ID`). Owners not yet in the vault are created as principals.

Values about other people in an owner's item (a nominee in a claim, a caller's relative) are tokenised under the owner, exactly as `protect()` does for agents. When those people are erased, the item is redacted through lineage.

**Items with personal data but no owner** (shared notes, policy documents, multi-party tickets) can't be given anyone's key:
- With `--unowned skip` (default), they are left raw and **listed** in the report, so you can fix the owner field or handle them separately.
- With `--unowned mask`, the values are replaced irreversibly (`[EMAIL]`). Use this only where the values aren't needed.

**Consent.** The backfill tokenises without a consent check, because tokenising existing data lowers risk rather than adding processing. Owners with no consent record for the purpose are **counted** as a gap: either the data is held on another legal basis, or the consent record needs fixing.

## Retrieval after the backfill

Tokens are deterministic per person: the same value of the same person always becomes the same token. So:

- **A person's own queries:** tokenise the query in their context (`with dpdp.context(pid, purpose): dpdp.protect(q)`, or `dpdp.embed()`). Names and numbers in the query then match the tokens in their chunks, both lexically and semantically.
- **Staff search across people:** filter on the metadata (customer id, case id), not on names or numbers inside the text.
- **Answers to users:** turn tokens back into values at the edge with `reveal(..., for_principal=pid)`, or with the gateway's `reveal_responses`.

Measure retrieval on a held-out set of queries before and after, in a copy of the index. Tokens change the text the embedding model sees, and how much that matters depends on the corpus.

## Safety

- **Dry run first:** a dry run is the default and changes nothing. It doesn't even create principals.
- **What the dry run reports:**
  - items, and items with personal data;
  - items already tokenised;
  - owners, how many are new to the vault, and how many have no consent for the purpose;
  - items with personal data but no owner, with their locations;
  - the text that would be re-embedded, and a cost estimate (`--price-per-million`, using the provider's current price).
- **Applying:** `--apply` needs `--confirm <store>`. Take a backup or snapshot first; the backfill doesn't keep the old text, so the values exist only in the vault afterwards.
- **No stale vectors:** a store with vectors but no configured embedding model is refused before anything is written.
- **Failures resume:** a failure stops the run and records the cursor. `--resume <run id>` continues from the last finished batch.
- **Re-running is safe:** items already tokenised are left as they are.
- **Run records hold no content:** `backfill --runs` shows the counts, cursor, status, error and who started each run.
- **What's left:** after `--apply`, the report counts items where the detectors still find raw values. Those need better detectors ([benchmark](pii-benchmark.md)) or a manual look, and a follow-up [scan](scan.md) confirms the result.

## Limits

- **Detection:** only what the detectors find is tokenised. Regex alone misses most names that have no cue phrase, so add `remote_ner` or a cloud detector first.
- **Surrogates:** with storage surrogates on, items are rewritten with surrogates, and "already tokenised" isn't recognised for them.
- **Concurrent writes:** rows written by the application during a run are picked up only if their id is after the cursor. Run it in a quiet window, or run it twice.
- **Old copies:** backups, snapshots and replicas taken before the run still hold raw values until they age out. Record that in the case log and the retention plan.
