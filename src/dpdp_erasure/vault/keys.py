"""Key wrappers: protect per-principal data encryption keys (DEKs).

local    - AES-GCM master key in a file (dev / tests only)
aws_kms  - AWS KMS Encrypt/Decrypt
gcp_kms  - Google Cloud KMS encrypt/decrypt
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyWrapper(Protocol):
    def wrap(self, dek: bytes, context: str) -> bytes: ...
    def unwrap(self, blob: bytes, context: str) -> bytes: ...


class LocalKeyWrapper:
    def __init__(self, master_key_path: str):
        p = Path(master_key_path)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(AESGCM.generate_key(bit_length=256))
            os.chmod(p, 0o600)
        self._aead = AESGCM(p.read_bytes())

    def wrap(self, dek: bytes, context: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, dek, context.encode())

    def unwrap(self, blob: bytes, context: str) -> bytes:
        return self._aead.decrypt(blob[:12], blob[12:], context.encode())


class AwsKmsKeyWrapper:
    """Uses the KMS encryption context to bind each wrapped DEK to its principal."""

    def __init__(self, key_id: str, region: str | None = None, client=None):
        import boto3

        self.key_id = key_id
        self.client = client or boto3.client("kms", region_name=region)

    def wrap(self, dek: bytes, context: str) -> bytes:
        r = self.client.encrypt(KeyId=self.key_id, Plaintext=dek, EncryptionContext={"dpdp:principal": context})
        return r["CiphertextBlob"]

    def unwrap(self, blob: bytes, context: str) -> bytes:
        r = self.client.decrypt(CiphertextBlob=blob, EncryptionContext={"dpdp:principal": context})
        return r["Plaintext"]


class GcpKmsKeyWrapper:
    def __init__(self, key_name: str, client=None):
        from google.cloud import kms  # type: ignore

        self.key_name = key_name
        self.client = client or kms.KeyManagementServiceClient()

    def wrap(self, dek: bytes, context: str) -> bytes:
        r = self.client.encrypt(
            request={"name": self.key_name, "plaintext": dek, "additional_authenticated_data": context.encode()}
        )
        return r.ciphertext

    def unwrap(self, blob: bytes, context: str) -> bytes:
        r = self.client.decrypt(
            request={"name": self.key_name, "ciphertext": blob, "additional_authenticated_data": context.encode()}
        )
        return r.plaintext


def build_key_wrapper(cfg) -> KeyWrapper:
    if cfg.key_wrapper == "local":
        return LocalKeyWrapper(cfg.local_master_key_path)
    if cfg.key_wrapper == "aws_kms":
        if not cfg.kms_key_id:
            raise ValueError("vault.kms_key_id is required for aws_kms")
        return AwsKmsKeyWrapper(cfg.kms_key_id, cfg.region)
    if cfg.key_wrapper == "gcp_kms":
        if not cfg.kms_key_id:
            raise ValueError("vault.kms_key_id (projects/../cryptoKeys/..) is required for gcp_kms")
        return GcpKmsKeyWrapper(cfg.kms_key_id)
    raise ValueError(f"Unknown key wrapper {cfg.key_wrapper}")
