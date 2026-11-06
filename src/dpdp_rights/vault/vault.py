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

from ..pii.detectors import verhoeff_valid
from .keys import KeyWrapper
from .storage import VaultStorage

TOKEN_RE = re.compile(r"<([A-Z][A-Z0-9_]*?)_([0-9a-f]{12})>")
ERASED_MARKER = "[ERASED]"
MASK = "\u2022"   # bullet used in masked display

# ---- format-preserving surrogates -------------------------------------------------------------------------
# A surrogate is a token shaped like the value it replaces, for systems that validate formats. It is derived
# from the person's key like any token, so crypto-shredding makes it meaningless. Where the identifier has a
# checksum, the surrogate deliberately fails it, so it can never equal a real number.
SURROGATE_TYPES = {"PHONE_IN", "PHONE", "AADHAAR", "CARD_NUMBER", "PAN", "EMAIL", "BANK_ACCOUNT"}
SURROGATE_EMAIL_DOMAIN = "surrogate.invalid"           # RFC 2606 reserved TLD: never a real mailbox
# Shapes a surrogate can take in text; candidates are only treated as surrogates if the vault holds them.
SURROGATE_CANDIDATE_RE = re.compile(
    r"\b[a-z0-9]{6,32}@surrogate\.invalid\b"
    r"|\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b"
    r"|(?<![\w+])\+?\d[\d \-]{7,22}\d(?!\w)"
)
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


def _luhn_ok(d: str) -> bool:
    total, alt = 0, False
    for ch in reversed(d):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def make_surrogate(element_type: str, value: str, digest: bytes) -> str:
    """Same separators, length and character classes as ``value``; content from ``digest``."""
    stream = iter(digest * 4)
    if element_type == "EMAIL":
        return f"u{digest.hex()[:11]}@{SURROGATE_EMAIL_DOMAIN}"
    keep_prefix = ""
    body = value
    if element_type in ("PHONE_IN", "PHONE") and value.lstrip().startswith("+"):
        m = re.match(r"\s*(\+\d{1,3}[\s\-]?)", value)
        keep_prefix, body = (m.group(1), value[m.end():]) if m else ("", value)
    out, first_digit = [], True
    for ch in body:
        if ch.isdigit():
            n = next(stream) % 10
            if first_digit and element_type == "PHONE_IN":
                n = 6 + n % 4                     # Indian mobile numbers start with 6-9
            elif first_digit and element_type == "AADHAAR":
                n = 2 + n % 8                     # Aadhaar never starts with 0 or 1
            first_digit = False
            out.append(str(n))
        elif ch.isalpha():
            letter = chr(ord("A") + next(stream) % 26)
            out.append(letter if ch.isupper() else letter.lower())
        else:
            out.append(ch)
    sur = list(keep_prefix + "".join(out))
    digits_at = [i for i, c in enumerate(sur) if c.isdigit()]
    if element_type == "PAN" and len(sur) == 10:
        sur[3] = value[3]                          # keep the holder-type letter (P, C, H, ...)
    if element_type in ("AADHAAR", "CARD_NUMBER") and digits_at:
        check = verhoeff_valid if element_type == "AADHAAR" else _luhn_ok
        last = digits_at[-1]
        while check("".join(sur[i] for i in digits_at)):
            sur[last] = str((int(sur[last]) + 1) % 10)
    return "".join(sur)


class Vault:
    def __init__(self, storage: VaultStorage, wrapper: KeyWrapper, sealed_wrapper: KeyWrapper | None = None,
                 cache_ttl_seconds: int = 300, cache_max_entries: int = 10_000,
                 surrogate_types: set[str] | frozenset[str] = frozenset()):
        unknown = set(surrogate_types) - SURROGATE_TYPES
        if unknown:
            raise ValueError(f"surrogates are not supported for {sorted(unknown)}; choose from {sorted(SURROGATE_TYPES)}")
        self.surrogate_types = set(surrogate_types)
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
        if element_type in self.surrogate_types:
            sur = make_surrogate(element_type, value, digest.digest())
            existing = self.storage.get_value(sur)
            if existing is None or existing[0] == principal_id:   # on a (rare) clash keep the plain token
                token = sur
        existing = self.storage.get_value(token)
        current = self._decrypt(dek, token, existing[2]) if existing and existing[0] == principal_id else None
        if current is not None and normalise(element_type, current) != normalise(element_type, value):
            # This token's value was corrected (Act s.12). Never overwrite the correction with the old value
            # seen again later; give the old value a token of its own instead.
            digest = hmac.new(dek, f"{element_type}|{normalise(element_type, value)}|superseded".encode(),
                              hashlib.sha256)
            token = f"<{element_type}_{digest.hexdigest()[:12]}>"
        nonce = os.urandom(12)
        ct = nonce + AESGCM(dek).encrypt(nonce, value.encode(), token.encode())
        self.storage.put_value(token, principal_id, element_type, ct, third_party)
        return token

    @staticmethod
    def _decrypt(dek: bytes, token: str, ct: bytes) -> str | None:
        try:
            return AESGCM(dek).decrypt(ct[:12], ct[12:], token.encode()).decode()
        except Exception:  # noqa: BLE001
            return None

    def correct(self, token: str, new_value: str) -> dict:
        """Correct the value behind a token (Act s.12(1)-(2)). Every stored copy that holds the token reads
        the corrected value from now on; nothing in the stores is rewritten. Returns the old and new
        element type and whether the token is a surrogate (its shape keeps the old value's format)."""
        rec = self.storage.get_value(token)
        if rec is None:
            raise KeyError("unknown or erased token")
        principal_id, element_type, _ = rec
        if principal_id.startswith(RESTRICTED_PREFIXES):
            raise PermissionError("sealed (legal hold / escrow) values cannot be corrected")
        dek = self._dek(principal_id)
        if dek is None:
            raise KeyError("principal key destroyed")
        nonce = os.urandom(12)
        ct = nonce + AESGCM(dek).encrypt(nonce, new_value.encode(), token.encode())
        self.storage.put_value(token, principal_id, element_type, ct, False)
        return {"token": token, "principal_id": principal_id, "element_type": element_type,
                "surrogate": not TOKEN_RE.fullmatch(token)}

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

    def find_tokens(self, text: str) -> list[tuple[int, int, str]]:
        """Spans of tokens in ``text``: ``<TYPE_xxxx>`` tokens, plus surrogates the vault holds."""
        spans = [(m.start(), m.end(), m.group(0)) for m in TOKEN_RE.finditer(text)]
        if self.surrogate_types:
            taken = [(s, e) for s, e, _ in spans]
            for m in SURROGATE_CANDIDATE_RE.finditer(text):
                if any(s < m.end() and m.start() < e for s, e in taken):
                    continue
                if self.storage.get_value(m.group(0)) is not None:
                    spans.append((m.start(), m.end(), m.group(0)))
            spans.sort()
        return spans

    def element_type_of(self, token: str) -> str | None:
        m = TOKEN_RE.fullmatch(token)
        if m:
            return m.group(1)
        rec = self.storage.get_value(token)
        return rec[1] if rec else None

    def reveal(self, text: str, allowed_principals: set[str] | None = None, masked: bool = False) -> str:
        """Replace tokens (and surrogates) with values for an authorised viewer.

        Erased tokens become [ERASED]; tokens of other people stay as they are. With ``masked=True`` the
        value is shown in a masked display form (``+91 •••••  •3210``, ``p••••@example.in``) instead.
        A surrogate whose key was destroyed is indistinguishable from ordinary text, so it is left as is.
        """
        out, cursor = [], 0
        for start, end, tok in self.find_tokens(text):
            out.append(text[cursor:start])
            out.append(self._reveal_one(tok, allowed_principals, masked))
            cursor = end
        out.append(text[cursor:])
        return "".join(out)

    def _reveal_one(self, tok: str, allowed: set[str] | None, masked: bool) -> str:
        rec = self.storage.get_value(tok)
        if rec is None:
            return ERASED_MARKER
        owner, etype = rec[0], rec[1]
        if allowed is not None and owner not in allowed:
            return tok
        if owner.startswith(RESTRICTED_PREFIXES):
            return ERASED_MARKER
        val = self.detokenize(tok)
        if val is None:
            return ERASED_MARKER
        return mask_value(etype, val) if masked else val

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


def mask_value(element_type: str, value: str, keep_last: int = 4) -> str:
    """Display form that keeps the shape: separators kept, most characters replaced with a bullet."""
    if element_type in ("EMAIL", "UPI_ID") and "@" in value:
        local, _, domain = value.partition("@")
        return local[:1] + MASK * max(len(local) - 1, 1) + "@" + domain
    if element_type == "NAME":
        return " ".join(w[:1] + MASK * (len(w) - 1) for w in value.split())
    if element_type in ("ADDRESS", "FREE_TEXT", "HEALTH", "RIGHTS_NOTE"):
        return MASK * 6
    prefix = ""
    m = re.match(r"\s*\+\d{1,3}[\s\-]?", value) if element_type in ("PHONE_IN", "PHONE") else None
    if m:
        prefix, value = value[:m.end()], value[m.end():]
    alnum = [i for i, c in enumerate(value) if c.isalnum()]
    show = set(alnum[-keep_last:]) if len(alnum) > keep_last else set()
    return prefix + "".join(c if (not c.isalnum() or i in show) else MASK for i, c in enumerate(value))
