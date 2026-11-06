"""PII vault with per-principal keys.

* Each data principal gets a random 256-bit DEK, stored wrapped by a key-encryption
  key (KEK) held in AWS KMS, Google Cloud KMS, or a local file for development.
* PII values are encrypted with that DEK; prompts, logs, embeddings and caches
  only ever see tokens like ``<EMAIL_3f9a1c0b7d2e>``.
* Tokens are HMAC(DEK, type|value): stable per principal (so joins, caching and
  retrieval still work) but unlinkable once the DEK is destroyed.
* Erasure = ``shred(principal)``: delete DEK + ciphertexts + lookup entries.
  Every copy of every token, in every log, backup or vector index, becomes
  permanently meaningless (crypto-shredding).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import OrderedDict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import KeyWrapper
from .storage import VaultStorage

TOKEN_RE = re.compile(r"<([A-Z][A-Z0-9_]*?)_([0-9a-f]{12})>")
ERASED_MARKER = "[ERASED]"
_LOOKUP_ID = "__lookup__"
RESTRICTED_PREFIXES = ("hold_", "escrow_")   # sealed keys: legal hold / statutory retention


def normalise(element_type: str, value: str) -> str:
    v = value.strip()
    if element_type in {"EMAIL", "UPI_ID"}:
        return v.lower()
    if element_type in {"PHONE_IN", "PHONE", "AADHAAR", "CARD_NUMBER", "BANK_ACCOUNT"}:
        digits = re.sub(r"\D", "", v)
        if element_type == "PHONE_IN" and len(digits) > 10:
            digits = digits[-10:]
        return digits
    if element_type == "PAN":
        return v.upper().replace(" ", "")
    return " ".join(v.split()).lower()


class Vault:
    def __init__(self, storage: VaultStorage, wrapper: KeyWrapper, sealed_wrapper: KeyWrapper | None = None,
                 cache_ttl_seconds: int = 300, cache_max_entries: int = 10_000):
        self.storage = storage
        self.wrapper = wrapper
        # Sealed (hold_/escrow_) DEKs are wrapped by a separate KEK. Applications need only
        # Encrypt on it; Decrypt is reserved for the break-glass role.
        self.sealed_wrapper = sealed_wrapper or wrapper
        self.cache_ttl = cache_ttl_seconds
        self.cache_max = cache_max_entries
        self._cache: OrderedDict[str, tuple[bytes, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._lookup_key = self._dek(_LOOKUP_ID, create=True)

    # ---- keys ------------------------------------------------------------
    def _wrapper_for(self, principal_id: str) -> KeyWrapper:
        return self.sealed_wrapper if principal_id.startswith(RESTRICTED_PREFIXES) else self.wrapper

    def _dek(self, principal_id: str, create: bool = False) -> bytes | None:
        sealed = principal_id.startswith(RESTRICTED_PREFIXES)
        with self._lock:
            hit = self._cache.get(principal_id)
            if hit and hit[1] > time.monotonic():
                self._cache.move_to_end(principal_id)
                return hit[0]
            self._cache.pop(principal_id, None)
            wrapped = self.storage.get_key(principal_id)
            if wrapped is None:
                if not create:
                    return None
                dek = AESGCM.generate_key(bit_length=256)
                self.storage.put_key(principal_id, self._wrapper_for(principal_id).wrap(dek, principal_id))
            else:
                dek = self._wrapper_for(principal_id).unwrap(wrapped, principal_id)
            if not sealed:          # sealed keys are never cached: every read goes back to KMS
                self._cache[principal_id] = (dek, time.monotonic() + self.cache_ttl)
                while len(self._cache) > self.cache_max:
                    self._cache.popitem(last=False)
            return dek

    def mac(self, data: bytes) -> str:
        """Keyed hash with the vault's secret lookup key (for OTP hashes etc.)."""
        return hmac.new(self._lookup_key, data, hashlib.sha256).hexdigest()

    def values_of_type(self, principal_id: str, element_type: str) -> list[str]:
        out = []
        for t in self.tokens_for(principal_id):
            rec = self.storage.get_value(t)
            if rec and rec[1] == element_type:
                v = self.detokenize(t)
                if v:
                    out.append(v)
        return out

    def has_key(self, principal_id: str) -> bool:
        return self._dek(principal_id) is not None

    # ---- principal resolution -------------------------------------------
    def _lookup_hash(self, identifier_type: str, value: str) -> str:
        msg = f"{identifier_type}|{normalise(identifier_type, value)}".encode()
        return hmac.new(self._lookup_key, msg, hashlib.sha256).hexdigest()

    def resolve_principal(self, external_id: str, id_type: str = "EXTERNAL_ID", create: bool = True) -> str | None:
        h = self._lookup_hash(id_type, external_id)
        pid = self.storage.get_lookup(h)
        if pid is None and create:
            pid = f"dp_{secrets.token_hex(10)}"
            self.storage.put_lookup(h, pid)
            self._dek(pid, create=True)
        return pid

    def link_identifier(self, principal_id: str, id_type: str, value: str) -> None:
        """Register an identifier (email, phone...) so mentions elsewhere resolve to this principal."""
        self.storage.put_lookup(self._lookup_hash(id_type, value), principal_id)

    def find_principal_by_identifier(self, id_type: str, value: str) -> str | None:
        return self.storage.get_lookup(self._lookup_hash(id_type, value))

    # ---- tokenisation ------------------------------------------------------
    def tokenize(self, principal_id: str, element_type: str, value: str, third_party: bool = False) -> str:
        dek = self._dek(principal_id, create=True)
        digest = hmac.new(dek, f"{element_type}|{normalise(element_type, value)}".encode(), hashlib.sha256)
        token = f"<{element_type}_{digest.hexdigest()[:12]}>"
        nonce = os.urandom(12)
        ct = nonce + AESGCM(dek).encrypt(nonce, value.encode(), token.encode())
        self.storage.put_value(token, principal_id, element_type, ct, third_party)
        return token

    def detokenize(self, token: str, privileged: bool = False) -> str | None:
        """Privileged access is required for tokens sealed under a legal-hold or retention-escrow key
        (e.g. a DPO answering a lawful request); ordinary application reads get None."""
        rec = self.storage.get_value(token)
        if rec is None:
            return None
        principal_id, _, ct = rec
        if principal_id.startswith(RESTRICTED_PREFIXES) and not privileged:
            return None
        dek = self._dek(principal_id)
        if dek is None:
            return None
        return AESGCM(dek).decrypt(ct[:12], ct[12:], token.encode()).decode()

    def owner_of(self, token: str) -> str | None:
        rec = self.storage.get_value(token)
        return rec[0] if rec else None

    def tokens_for(self, principal_id: str) -> list[str]:
        return self.storage.tokens_for(principal_id)

    def reveal(self, text: str, allowed_principals: set[str] | None = None) -> str:
        """Replace tokens with values. Erased or unauthorised tokens become [ERASED] / stay masked."""
        def sub(m: re.Match[str]) -> str:
            tok = m.group(0)
            owner = self.owner_of(tok)
            if owner is None:
                return ERASED_MARKER
            if allowed_principals is not None and owner not in allowed_principals:
                return tok
            if owner.startswith(RESTRICTED_PREFIXES):
                return ERASED_MARKER
            val = self.detokenize(tok)
            return val if val is not None else ERASED_MARKER
        return TOKEN_RE.sub(sub, text)

    # ---- erasure -------------------------------------------------------------
    def snapshot_values(self, principal_id: str) -> dict[str, str]:
        """Plaintext values held in memory only, used as verification probes before shredding."""
        out = {}
        for t in self.tokens_for(principal_id):
            v = self.detokenize(t)
            if v:
                out[t] = v
        return out

    def _reseal(self, tokens, new_owner: str) -> int:
        # Wrap a fresh sealed DEK (Encrypt only); if one exists, it must be unwrapped via the sealed KEK.
        dek = self._dek(new_owner, create=True)
        n = 0
        for tok in tokens:
            val = self.detokenize(tok)
            rec = self.storage.get_value(tok)
            if val is None or rec is None:
                continue
            nonce = os.urandom(12)
            self.storage.put_value(tok, new_owner, rec[1], nonce + AESGCM(dek).encrypt(nonce, val.encode(), tok.encode()), False)
            n += 1
        return n

    def shred(self, principal_id: str, retain_tokens: set[str] | None = None, hold_id: str | None = None,
              escrow: bool = False) -> dict:
        """Crypto-shred a principal's operational key.

        * retain_tokens -> re-sealed under ``hold_<pid>`` (retention required by another law)
        * escrow=True   -> every other token re-sealed under ``escrow_<pid>`` for the statutory
                           minimum-retention window (DPDP Rules 2025, Rule 8(3)); the escrow key is
                           destroyed later by ``destroy()`` when the window ends.
        In both cases the data is no longer usable by any application: only privileged reads work.
        """
        retain_tokens = retain_tokens or set()
        retained = self._reseal(retain_tokens, hold_id or f"hold_{principal_id}") if retain_tokens else 0
        escrowed, escrow_id = 0, None
        if escrow:
            escrow_id = f"escrow_{principal_id}"
            escrowed = self._reseal([t for t in self.tokens_for(principal_id) if t not in retain_tokens], escrow_id)
        values = self.storage.delete_values(principal_id)
        lookups = self.storage.delete_lookups(principal_id)
        self.storage.delete_key(principal_id)
        with self._lock:
            self._cache.pop(principal_id, None)
        return {"values_deleted": values, "lookups_deleted": lookups, "key_destroyed": True,
                "tokens_moved_to_legal_hold": retained, "tokens_in_retention_escrow": escrowed,
                "escrow_id": escrow_id}

    def destroy(self, sealed_id: str) -> dict:
        """Destroy a hold/escrow key and its ciphertexts (end of retention window)."""
        values = self.storage.delete_values(sealed_id)
        self.storage.delete_key(sealed_id)
        with self._lock:
            self._cache.pop(sealed_id, None)
        return {"sealed_id": sealed_id, "values_deleted": values, "key_destroyed": True}
