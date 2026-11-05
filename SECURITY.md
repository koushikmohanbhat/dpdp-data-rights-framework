# Security

- Run the vault (keys + values) in a separate account/project from application stores and the lineage DB.
- `local` key wrapping is for development only. Use AWS KMS or Cloud KMS in production.
- Raw values are only held in memory during an erasure run (verification probes) and cleared afterwards.
- Privileged reads of legal-hold / escrow tokens (`detokenize(..., privileged=True)`) should sit behind a
  separate IAM role with break-glass auditing.
- Report vulnerabilities privately to the maintainers. Do not open public issues.
