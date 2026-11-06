"""Notifications when a rights request finishes, so operations, the DPO's case system or a ticketing tool
can follow up. Payloads never contain personal data: request id, pseudonymous principal id, status,
counts, due date and the certificate hash.

Built-in notifiers: ``webhook`` (HTTP POST, HMAC-SHA256 signed) and ``log``. Others (Slack, SNS, Pub/Sub,
ServiceNow, Jira) are plug-ins in the entry point group ``dpdp_rights.notifiers``: a callable taking the
configured options and returning an object with ``notify(event, payload)``.

A failing notifier is logged and never blocks or fails the erasure.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import urllib.request
from typing import Any, Protocol

from . import plugins

log = logging.getLogger("dpdp_rights.notify")

EVENTS = ("request_completed", "request_completed_with_exceptions", "request_failed", "request_planned",
          "case_reviewed", "rights_case_received", "rights_case_closed")


class Notifier(Protocol):
    def notify(self, event: str, payload: dict[str, Any]) -> None: ...


class LogNotifier:
    def __init__(self, level: str = "INFO"):
        self.level = getattr(logging, level.upper(), logging.INFO)

    def notify(self, event: str, payload: dict[str, Any]) -> None:
        log.log(self.level, "%s %s", event, json.dumps(payload, sort_keys=True, default=str))


class WebhookNotifier:
    """POST ``{"event": ..., "payload": ...}`` as JSON. With a secret, the body is signed:
    ``X-DPDP-Signature: sha256=<hex HMAC of the body>``, so the receiver can check it came from here."""

    def __init__(self, url: str, secret: str | None = None, secret_env: str | None = None,
                 timeout_seconds: float = 5.0, headers: dict[str, str] | None = None, opener=None):
        if not url.startswith("https://") and not url.startswith("http://localhost"):
            raise ValueError("webhook url must use https")
        self.url, self.timeout, self.headers = url, timeout_seconds, headers or {}
        self.secret = secret or (os.environ.get(secret_env) if secret_env else None)
        self._open = opener or urllib.request.urlopen

    def notify(self, event: str, payload: dict[str, Any]) -> None:
        body = json.dumps({"event": event, "payload": payload}, sort_keys=True, default=str).encode()
        headers = {"Content-Type": "application/json", **self.headers}
        if self.secret:
            headers["X-DPDP-Signature"] = "sha256=" + hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        with self._open(req, timeout=self.timeout) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"webhook returned {resp.status}")


plugins.register_builtin("notifiers", "log", LogNotifier)
plugins.register_builtin("notifiers", "webhook", WebhookNotifier)


class Notifications:
    """Fan-out to the configured notifiers, each filtered by the events it subscribes to."""

    def __init__(self, configs):
        self._targets: list[tuple[set[str], Notifier, str]] = []
        for c in configs:
            unknown = set(c.events) - set(EVENTS)
            if unknown:
                raise ValueError(f"unknown notification events {sorted(unknown)}; choose from {list(EVENTS)}")
            self._targets.append((set(c.events), plugins.get("notifiers", c.type)(**c.options), c.type))

    def emit(self, event: str, payload: dict[str, Any]) -> None:
        for events, target, name in self._targets:
            if event not in events:
                continue
            try:
                target.notify(event, payload)
            except Exception as exc:  # noqa: BLE001 - notifications must never break erasure
                log.warning("notifier %s failed for %s: %s", name, event, exc)
