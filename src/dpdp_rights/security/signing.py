"""Signed, immutable erasure certificates.

Signers sign the SHA-256 of the canonical certificate payload:
  local    - Ed25519 key file (development)
  aws_kms  - AWS KMS asymmetric key (ECC_NIST_P256, ECDSA_SHA_256); private key never leaves KMS
  gcp_kms  - Cloud KMS asymmetric key version (EC_SIGN_P256_SHA256)

Archives keep a copy that cannot be altered or deleted before its retention date:
  s3     - S3 Object Lock in COMPLIANCE mode (bucket must have Object Lock enabled)
  gcs    - GCS bucket with a locked retention policy
  local  - read-only file (development)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Protocol

from ..core.config import CertificateConfig
from ..core.models import utcnow


class Signer(Protocol):
    key_id: str
    def sign(self, digest: bytes) -> bytes: ...
    def verify(self, digest: bytes, signature: bytes) -> bool: ...
    def public_key_pem(self) -> str: ...


class LocalEd25519Signer:
    def __init__(self, key_path: str):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        p = Path(key_path)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            key = Ed25519PrivateKey.generate()
            p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
            os.chmod(p, 0o600)
        self._key = serialization.load_pem_private_key(p.read_bytes(), password=None)
        pub = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = f"local-ed25519:{hashlib.sha256(pub).hexdigest()[:16]}"

    def sign(self, digest):
        return self._key.sign(digest)

    def public_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def verify(self, digest, signature):
        try:
            self._key.public_key().verify(signature, digest)
            return True
        except Exception:  # noqa: BLE001
            return False


class AwsKmsSigner:
    ALG = "ECDSA_SHA_256"

    def __init__(self, key_id: str, region: str | None = None, client=None):
        import boto3

        self.client = client or boto3.client("kms", region_name=region)
        self.key_id = key_id

    def sign(self, digest):
        return self.client.sign(KeyId=self.key_id, Message=digest, MessageType="DIGEST",
                                SigningAlgorithm=self.ALG)["Signature"]

    def verify(self, digest, signature):
        r = self.client.verify(KeyId=self.key_id, Message=digest, MessageType="DIGEST", Signature=signature,
                               SigningAlgorithm=self.ALG)
        return bool(r.get("SignatureValid"))

    def public_key_pem(self) -> str:
        der = self.client.get_public_key(KeyId=self.key_id)["PublicKey"]
        b = base64.b64encode(der).decode()
        body = "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
        return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


class GcpKmsSigner:
    def __init__(self, key_version: str, client=None):
        from google.cloud import kms  # type: ignore

        self.client = client or kms.KeyManagementServiceClient()
        self.key_id = key_version

    def sign(self, digest):
        return self.client.asymmetric_sign(request={"name": self.key_id, "digest": {"sha256": digest}}).signature

    def verify(self, digest, signature):
        return verify_with_public_key(self.public_key_pem(), digest, signature)

    def public_key_pem(self) -> str:
        return self.client.get_public_key(request={"name": self.key_id}).pem


class Archive(Protocol):
    def put(self, name: str, body: bytes) -> str: ...


class LocalArchive:
    def __init__(self, directory: str):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def put(self, name, body):
        p = self.dir / name
        if p.exists():
            raise FileExistsError(f"certificate {name} already archived")
        p.write_bytes(body)
        os.chmod(p, 0o444)
        return str(p)


class S3ObjectLockArchive:
    def __init__(self, uri: str, retain_days: int, region: str | None = None, client=None,
                 mode: str = "COMPLIANCE"):
        import boto3

        self.bucket, _, self.prefix = uri.removeprefix("s3://").partition("/")
        self.retain_days, self.mode = retain_days, mode
        self.client = client or boto3.client("s3", region_name=region)

    def put(self, name, body):
        key = f"{self.prefix.rstrip('/')}/{name}" if self.prefix else name
        self.client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json",
                               ChecksumAlgorithm="SHA256", ObjectLockMode=self.mode,
                               ObjectLockRetainUntilDate=utcnow() + timedelta(days=self.retain_days))
        return f"s3://{self.bucket}/{key}"


class GcsLockedArchive:
    def __init__(self, uri: str, client=None):
        from google.cloud import storage  # type: ignore

        self.bucket_name, _, self.prefix = uri.removeprefix("gs://").partition("/")
        self.bucket = (client or storage.Client()).bucket(self.bucket_name)

    def put(self, name, body):
        key = f"{self.prefix.rstrip('/')}/{name}" if self.prefix else name
        blob = self.bucket.blob(key)
        blob.upload_from_string(body, content_type="application/json", if_generation_match=0)
        return f"gs://{self.bucket_name}/{key}"


def build_signer(cfg: CertificateConfig) -> Signer | None:
    if cfg.signer == "none":
        return None
    if cfg.signer == "local":
        return LocalEd25519Signer(cfg.local_key_path)
    if not cfg.key_id:
        raise ValueError("certificates.key_id is required for KMS signing")
    if cfg.signer == "aws_kms":
        return AwsKmsSigner(cfg.key_id, cfg.region)
    return GcpKmsSigner(cfg.key_id)


def build_archive(cfg: CertificateConfig) -> Archive | None:
    if cfg.archive == "none":
        return None
    if not cfg.archive_uri:
        raise ValueError("certificates.archive_uri is required")
    if cfg.archive == "local":
        return LocalArchive(cfg.archive_uri)
    if cfg.archive == "s3":
        return S3ObjectLockArchive(cfg.archive_uri, cfg.retain_days, cfg.region, mode=cfg.archive_mode)
    return GcsLockedArchive(cfg.archive_uri)


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def verify_with_public_key(pem: str, digest: bytes, signature: bytes) -> bool:
    """Verify a signature from any of the signers above with only the public key (offline checks).

    Ed25519 signs the digest bytes; KMS ECDSA P-256 signs the pre-computed SHA-256 digest."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    try:
        pub = serialization.load_pem_public_key(pem.encode())
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, digest)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        else:
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def key_fingerprint(pem: str) -> str:
    """SHA-256 of the DER public key: publish this so auditors can pin the signing key."""
    from cryptography.hazmat.primitives import serialization

    der = serialization.load_pem_public_key(pem.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()
