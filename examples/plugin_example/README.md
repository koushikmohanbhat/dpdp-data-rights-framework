# Example plug-in

A complete, installable plug-in for the DPDP Data Rights Framework. Copy it to start a connector,
detector or notifier for a client system, without forking the framework.

| Entry point group | Name | What it is |
|---|---|---|
| `dpdp_rights.connectors` | `csv_records` | Connector for CSV record files (standing in for an HR or CRM export) |
| `dpdp_rights.detectors` | `employee_id` | Detector for a client-specific identifier (`EMP-123456`) |
| `dpdp_rights.notifiers` | `jsonl_outbox` | Notifier that appends request events to a file (standing in for ticketing) |

```bash
pip install -e examples/plugin_example
dpdp-rights plugins | grep example-plugin      # discovered through entry points
pytest examples/plugin_example                  # includes the connector conformance kit
```

Use it from a framework config:

```yaml
pii:
  detectors: [regex, aws_comprehend, employee_id]
  detector_options: {employee_id: {prefix: EMP, digits: 6}}
connectors:
  - name: hr_export
    type: csv_records
    options: {path: /data/hr/records.csv}
notifications:
  - type: jsonl_outbox
    options: {path: /var/log/dpdp-outbox.jsonl}
    events: [request_completed, request_completed_with_exceptions, request_failed]
```

How to write each kind of plug-in, and the rules a connector must follow: [docs/plugins.md](../../docs/plugins.md).
