# Contributing

- New connector? Add it under `src/dpdp_erasure/connectors/`, register with `@register("type")`,
  implement `discover`, `_delete` (and `_redact` if the store is mutable), and add a Stubber/mock test.
- Keep raw PII out of fixtures: generate synthetic Aadhaar numbers with `verhoeff_check_digit`.
- Run `ruff check src tests && pytest -q` before opening a PR.
- Legal interpretations go in `docs/dpdp-mapping.md` with a source; mark anything unsettled.
