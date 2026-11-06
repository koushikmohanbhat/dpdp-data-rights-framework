"""Signed evidence bundles: a zip with a manifest of SHA-256 hashes, signed by the certificate signer.

    case bundle  : case.json, case.md, case.html, certificate.json, public_key.pem, manifest.json, manifest.sig
    audit pack   : audit.json, audit.md, audit.html, cases/<request_id>.json, coverage.json?, manifest.json, ...

`verify_bundle` works offline. The public key inside a bundle only proves the files were signed by
*that* key: pin the key by passing `--public-key` (a copy you hold) or `--fingerprint` (published by
the Data Fiduciary), otherwise the result says the key is not pinned.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile

from .. import __version__
from ..core.models import utcnow
from .case import build_case, canonical, request_anchor, verify_events
from .render import case_html, case_markdown

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
PUBKEY = "public_key.pem"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write_signed_zip(path: str | None, files: dict[str, bytes], meta: dict, signer=None) -> tuple[bytes, dict]:
    """Write files + manifest (+ signature and public key). Returns the zip bytes and the manifest."""
    from ..security.signing import b64, key_fingerprint

    files = dict(files)
    pem = None
    if signer is not None and hasattr(signer, "public_key_pem"):
        try:
            pem = signer.public_key_pem()
            files[PUBKEY] = pem.encode()
        except Exception:  # noqa: BLE001 - a signer without public-key access still signs
            pem = None
    manifest = meta | {"generator": f"dpdp-rights {__version__}", "generated_at": utcnow().isoformat(),
                       "files": {n: _sha(b) for n, b in sorted(files.items())},
                       "signer": getattr(signer, "key_id", None),
                       "key_fingerprint": key_fingerprint(pem) if pem else None}
    mbytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in sorted(files.items()):
            z.writestr(n, b)
        z.writestr(MANIFEST, mbytes)
        if signer is not None:
            z.writestr(SIGNATURE, b64(signer.sign(hashlib.sha256(mbytes).digest())))
    data = buf.getvalue()
    if path:
        with open(path, "wb") as f:
            f.write(data)
    return data, manifest


def export_case_bundle(dpdp, request_id: str, path: str | None = None) -> dict:
    case = build_case(dpdp, request_id)
    cert = dpdp.store.get_certificate(request_id)
    files = {"case.json": json.dumps(case, indent=2, default=str, ensure_ascii=False).encode(),
             "case.md": case_markdown(case).encode(),
             "case.html": case_html(case).encode()}
    if cert:
        files["certificate.json"] = json.dumps({"payload": cert["payload"], "sha256": cert["sha256"],
                                                "prev_sha256": cert["prev_sha256"], "signature": cert["signature"],
                                                "signer": cert["signer"], "archive_uri": cert["archive_uri"]},
                                               indent=2).encode()
    data, manifest = write_signed_zip(path, files, {"schema": "dpdp-rights/evidence-bundle/v1", "kind": "case",
                                                    "request_id": request_id, "sign_off": case["sign_off"]["state"]},
                                      dpdp.orchestrator.signer)
    return {"path": path, "bytes": len(data), "manifest": manifest, "data": data if path is None else None}


def verify_bundle(source: str | bytes, public_key_pem: str | None = None, fingerprint: str | None = None) -> dict:
    """Check file hashes, the manifest signature, and (for case bundles) the certificate and case log."""
    from ..security.signing import key_fingerprint, unb64, verify_with_public_key

    z = zipfile.ZipFile(io.BytesIO(source) if isinstance(source, bytes) else source)
    names = set(z.namelist())
    out: dict = {"ok": True, "problems": []}

    def bad(msg):
        out["ok"] = False
        out["problems"].append(msg)

    if MANIFEST not in names:
        bad("manifest.json missing")
        return out
    mbytes = z.read(MANIFEST)
    manifest = json.loads(mbytes)
    out.update(kind=manifest.get("kind"), request_id=manifest.get("request_id"), signer=manifest.get("signer"))
    for n, h in manifest.get("files", {}).items():
        if n not in names:
            bad(f"missing file {n}")
        elif _sha(z.read(n)) != h:
            bad(f"file changed after signing: {n}")
    extra = names - set(manifest.get("files", {})) - {MANIFEST, SIGNATURE}
    if extra:
        bad(f"files not in manifest: {', '.join(sorted(extra))}")

    embedded = z.read(PUBKEY).decode() if PUBKEY in names else None
    pem = public_key_pem or embedded
    out["key_fingerprint"] = key_fingerprint(pem) if pem else None
    out["key_pinned"] = bool(public_key_pem) or bool(fingerprint and out["key_fingerprint"] == fingerprint)
    if fingerprint and out["key_fingerprint"] != fingerprint:
        bad("signing key does not match the expected fingerprint")
    if public_key_pem and embedded and key_fingerprint(embedded) != key_fingerprint(public_key_pem):
        bad("bundle was signed with a different key than the one supplied")
    if SIGNATURE in names:
        out["signed"] = True
        out["signature_ok"] = bool(pem) and verify_with_public_key(
            pem, hashlib.sha256(mbytes).digest(), unb64(z.read(SIGNATURE).decode()))
        if not out["signature_ok"]:
            bad("manifest signature invalid" if pem else "manifest signed but no public key to check it")
    else:
        out["signed"] = False
        out["signature_ok"] = None

    if manifest.get("kind") == "case" and "case.json" in names:
        case = json.loads(z.read("case.json"))
        anchors = []
        if "certificate.json" in names:
            cert = json.loads(z.read("certificate.json"))
            digest = hashlib.sha256(cert["payload"].encode()).digest()
            out["certificate_hash_ok"] = digest.hex() == cert["sha256"]
            if not out["certificate_hash_ok"]:
                bad("certificate payload does not match its hash")
            if cert.get("signature") and pem:
                out["certificate_signature_ok"] = verify_with_public_key(pem, digest, unb64(cert["signature"]))
                if not out["certificate_signature_ok"]:
                    bad("certificate signature invalid with this key")
            if (case.get("certificate") or {}).get("sha256") != cert["sha256"]:
                bad("case record refers to a different certificate")
            anchors.append(cert["sha256"])
        anchors.append(request_anchor(case["request"]["request_id"]))
        chk = verify_events(case["request"]["request_id"], case.get("case_log", []), anchors, public_key_pem=pem)
        out["case_log_ok"] = chk["ok"]
        if not chk["ok"]:
            bad(f"case log broken at {chk['broken_at']}")
        out["sign_off"] = case.get("sign_off", {}).get("state")
    if not out["key_pinned"] and out.get("signed"):
        out["note"] = "signature checked with the key inside the bundle; pass --public-key or --fingerprint to pin it"
    return out


__all__ = ["export_case_bundle", "verify_bundle", "write_signed_zip", "canonical"]
