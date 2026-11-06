# Security policy

See [docs/security.md](docs/security.md) for the threat model, controls and production checklist.

Key points:
- Set `environment: production`; the framework refuses to start with development-only settings.
  Run `dpdp-rights -c <config> check-config` in CI.
- Keep the vault in a separate account/project. Use a separate sealed KEK that only a break-glass role can decrypt.
- Raw values are only held in memory during an erasure run (verification probes) and cleared afterwards.
- This project has not been independently audited. Pen-test your deployment.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories ("Report a vulnerability" on the
Security tab). Do not open public issues for security problems.
