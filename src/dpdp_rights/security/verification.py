"""Verify that an erasure / withdrawal request really comes from the Data Principal.

Three ways a request becomes verified:
  otp                    - a one-time code sent to the contact registered for the principal
                           (email via Amazon SES / webhook, SMS via Amazon SNS / webhook)
  authenticated_session  - the caller is the principal, authenticated through OIDC
  dpo_attested           - a DPO verified identity out of band (branch visit, video KYC) and
                           records the evidence reference

Only an HMAC of the code is stored. Codes expire and lock after too many attempts.
"""
from __future__ import annotations

import hmac
import json
import logging
import secrets
import urllib.request
from datetime import timedelta
from typing import Protocol

from sqlalchemy import select, update

from ..core.config import VerificationConfig
from ..core.models import utcnow
from ..lineage.store import LineageStore, verification_challenge
from ..vault.vault import Vault

log = logging.getLogger("dpdp_rights.verification")


class Notifier(Protocol):
    def send(self, channel: str, destination: str, message: str) -> None: ...


def mask(destination: str) -> str:
    if "@" in destination:
        user, dom = destination.split("@", 1)
        return f"{user[:1]}***@{dom}"
    digits = "".join(c for c in destination if c.isdigit())
    return f"******{digits[-4:]}" if digits else "***"


class LogNotifier:
    """Development only: logs a masked destination; the code is kept in memory for tests/demos."""

    def __init__(self):
        self.sent: list[tuple[str, str, str]] = []

    def send(self, channel, destination, message):
        self.sent.append((channel, destination, message))
        log.info("verification code sent via %s to %s", channel, mask(destination))


class SnsNotifier:
    def __init__(self, region=None, client=None):
        import boto3

        self.client = client or boto3.client("sns", region_name=region)

    def send(self, channel, destination, message):
        self.client.publish(PhoneNumber=destination, Message=message,
                            MessageAttributes={"AWS.SNS.SMS.SMSType": {"DataType": "String",
                                                                       "StringValue": "Transactional"}})


class SesNotifier:
    def __init__(self, from_email: str, region=None, client=None):
        import boto3

        self.client = client or boto3.client("sesv2", region_name=region)
        self.from_email = from_email

    def send(self, channel, destination, message):
        self.client.send_email(FromEmailAddress=self.from_email, Destination={"ToAddresses": [destination]},
                               Content={"Simple": {"Subject": {"Data": "Confirm your data request"},
                                                   "Body": {"Text": {"Data": message}}}})


class WebhookNotifier:
    """POSTs {channel, destination, message} to your messaging service (Gupshup, Twilio, Pub/Sub push...)."""

    def __init__(self, url: str):
        self.url = url

    def send(self, channel, destination, message):
        req = urllib.request.Request(self.url, data=json.dumps(
            {"channel": channel, "destination": destination, "message": message}).encode(),
            headers={"content-type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10).read()


def build_notifier(cfg: VerificationConfig) -> Notifier:
    if cfg.notifier == "aws_sns":
        return SnsNotifier(cfg.region)
    if cfg.notifier == "aws_ses":
        if not cfg.from_email:
            raise ValueError("verification.from_email is required for aws_ses")
        return SesNotifier(cfg.from_email, cfg.region)
    if cfg.notifier == "webhook":
        if not cfg.webhook_url:
            raise ValueError("verification.webhook_url is required for webhook")
        return WebhookNotifier(cfg.webhook_url)
    return LogNotifier()


class VerificationError(Exception):
    pass


class VerificationService:
    def __init__(self, store: LineageStore, vault: Vault, cfg: VerificationConfig, notifier: Notifier):
        self.store, self.vault, self.cfg, self.notifier = store, vault, cfg, notifier

    def _hash(self, request_id: str, code: str) -> str:
        return self.vault.mac(f"otp|{request_id}|{code}".encode())

    def start(self, request_id: str, principal_id: str) -> dict:
        etype = "EMAIL" if self.cfg.channel == "email" else "PHONE_IN"
        dests = self.vault.values_of_type(principal_id, etype)
        if not dests:
            raise VerificationError(f"no registered {etype} for this principal; use dpo_attested verification")
        code = f"{secrets.randbelow(10**6):06d}"
        expires = utcnow() + timedelta(seconds=self.cfg.otp_ttl_seconds)
        with self.store.engine.begin() as c:
            c.execute(verification_challenge.delete().where(verification_challenge.c.request_id == request_id))
            c.execute(verification_challenge.insert().values(
                request_id=request_id, channel=self.cfg.channel, code_hash=self._hash(request_id, code),
                expires_at=expires, attempts=0, status="pending"))
        self.notifier.send(self.cfg.channel, dests[0],
                           f"Your code to confirm your data request is {code}. It expires in "
                           f"{self.cfg.otp_ttl_seconds // 60} minutes. Ignore this if you did not ask.")
        return {"channel": self.cfg.channel, "destination": mask(dests[0]), "expires_at": expires.isoformat()}

    def verify(self, request_id: str, code: str) -> bool:
        with self.store.engine.begin() as c:
            r = c.execute(select(verification_challenge).where(
                verification_challenge.c.request_id == request_id)).first()
            if r is None or r.status != "pending":
                raise VerificationError("no pending verification for this request")
            exp = r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=utcnow().tzinfo)
            if exp < utcnow():
                c.execute(update(verification_challenge).where(verification_challenge.c.request_id == request_id)
                          .values(status="expired"))
                raise VerificationError("code expired; start verification again")
            ok = hmac.compare_digest(r.code_hash, self._hash(request_id, code.strip()))
            attempts = r.attempts + 1
            status = "verified" if ok else ("locked" if attempts >= self.cfg.max_attempts else "pending")
            c.execute(update(verification_challenge).where(verification_challenge.c.request_id == request_id)
                      .values(attempts=attempts, status=status))
        if status == "locked":
            raise VerificationError("too many attempts; verification locked")
        return ok
