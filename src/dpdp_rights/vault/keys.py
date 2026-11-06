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
    """Uses the KMS encryption context to bind each wrapped DEK to its principal.

    With ``role_arn``, Decrypt calls are made with credentials from that role (e.g. a break-glass
    role for sealed keys), while Encrypt uses the application's own credentials.
    """

    def __init__(self, key_id: str, region: str | None = None, client=None, role_arn: str | None = None,
                 decrypt_client=None):
        import boto3

        self.key_id, self.region, self.role_arn = key_id, region, role_arn
        self.client = client or boto3.client("kms", region_name=region)
        self._decrypt_client = decrypt_client

    def _dclient(self):
        if self._decrypt_client is not None:
            return self._decrypt_client
        if not self.role_arn:
            return self.client
        import boto3

        creds = boto3.client("sts", region_name=self.region).assume_role(
            RoleArn=self.role_arn, RoleSessionName="dpdp-break-glass", DurationSeconds=900)["Credentials"]
        return boto3.client("kms", region_name=self.region, aws_access_key_id=creds["AccessKeyId"],
                            aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])

    def wrap(self, dek: bytes, context: str) -> bytes:
        r = self.client.encrypt(KeyId=self.key_id, Plaintext=dek, EncryptionContext={"dpdp:principal": context})
        return r["CiphertextBlob"]

    def unwrap(self, blob: bytes, context: str) -> bytes:
        r = self._dclient().decrypt(CiphertextBlob=blob, EncryptionContext={"dpdp:principal": context})
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


def _local(cfg, sealed: bool) -> KeyWrapper:
    return LocalKeyWrapper(cfg.sealed_local_master_key_path if sealed else cfg.local_master_key_path)


def _aws_kms(cfg, sealed: bool) -> KeyWrapper:
    key = cfg.sealed_kms_key_id if sealed else cfg.kms_key_id
    if not key:
        raise ValueError(f"vault.{'sealed_kms_key_id' if sealed else 'kms_key_id'} is required for aws_kms")
    return AwsKmsKeyWrapper(key, cfg.region, role_arn=cfg.sealed_role_arn) if sealed else AwsKmsKeyWrapper(key, cfg.region)


def _gcp_kms(cfg, sealed: bool) -> KeyWrapper:
    key = cfg.sealed_kms_key_id if sealed else cfg.kms_key_id
    if not key:
        raise ValueError(f"vault.{'sealed_kms_key_id' if sealed else 'kms_key_id'} (projects/../cryptoKeys/..) "
                         "is required for gcp_kms")
    return GcpKmsKeyWrapper(key)


def _register_builtins() -> None:
    from .. import plugins

    for name, f in {"local": _local, "aws_kms": _aws_kms, "gcp_kms": _gcp_kms}.items():
        plugins.register_builtin("key_wrappers", name, f)


_register_builtins()


def build_key_wrapper(cfg) -> KeyWrapper:
    """Built-in key wrappers, or a plug-in in the entry point group dpdp_rights.key_wrappers."""
    from .. import plugins

    return plugins.get("key_wrappers", cfg.key_wrapper)(cfg, False)


def build_sealed_key_wrapper(cfg) -> KeyWrapper | None:
    if cfg.sealed_key_wrapper is None:
        return None
    from .. import plugins

    return plugins.get("key_wrappers", cfg.sealed_key_wrapper)(cfg, True)
