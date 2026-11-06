"""Model gateway: DPDP controls in front of an existing agent, with a URL change (docs/gateway.md).

Two modes:

- ``observe``: requests pass through unchanged. For each one the gateway records which kinds of personal data it
  carried, for which purpose, whether the person was identified, and what an enforce-mode gateway would have
  decided. Never values. ``gateway report`` turns this into the evidence for a readiness assessment.
- ``enforce``: the person and purpose are taken from headers (or the ``user`` field, or a LiteLLM key's metadata),
  consent is checked, and every text field sent to the model is tokenised. Responses can be revealed back to real
  values for the end user (``reveal_responses``), at the cost that the app then stores real values again.

A gateway only sees model traffic. Memory, vector stores, CRMs and the app's own logs never pass through it, so
it does not replace instrumentation for lineage and complete erasure; it is the quick first layer.

Used by the OpenAI-compatible endpoint (``/v1/gateway/openai/v1/...``) and by the LiteLLM guardrail
(``dpdp_rights.integrations.litellm``).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..consent.ledger import ConsentDenied
from ..core import context as ctxmod
from ..core.context import ContextEnvelope
from ..core.models import utcnow

ROUTES = ("chat", "responses", "embeddings")


class GatewayRefused(PermissionError):
    def __init__(self, status: int, message: str, decision: str):
        super().__init__(message)
        self.status, self.decision = status, decision


@dataclass
class CallState:
    route: str
    model: str | None
    principal_id: str | None
    purpose_id: str | None
    decision: str = "observed"
    entities: Counter = field(default_factory=Counter)
    strings: int = 0
    would: str | None = None


# ---- where text lives in OpenAI-style bodies -------------------------------------------------------------------------
def _text_slots(route: str, body: dict) -> list[tuple[Any, Any]]:
    """(container, key) pairs holding text sent to the model. Only known text fields: images, files, audio, ids
    and tool names are never touched."""
    slots: list[tuple[Any, Any]] = []

    def content(holder: dict, key: str = "content") -> None:
        c = holder.get(key)
        if isinstance(c, str):
            slots.append((holder, key))
        elif isinstance(c, list):
            for part in c:
                if isinstance(part, dict) and part.get("type") in ("text", "input_text", "output_text") \
                        and isinstance(part.get("text"), str):
                    slots.append((part, "text"))

    if route == "chat":
        for m in body.get("messages") or []:
            if not isinstance(m, dict):
                continue
            content(m)
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") if isinstance(tc, dict) else None
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    slots.append((fn, "arguments"))
    elif route == "responses":
        if isinstance(body.get("instructions"), str):
            slots.append((body, "instructions"))
        inp = body.get("input")
        if isinstance(inp, str):
            slots.append((body, "input"))
        elif isinstance(inp, list):
            for item in inp:
                if not isinstance(item, dict):
                    continue
                if "content" in item:
                    content(item)
                for k in ("output", "arguments"):
                    if isinstance(item.get(k), str):
                        slots.append((item, k))
    elif route == "embeddings":
        inp = body.get("input")
        if isinstance(inp, str):
            slots.append((body, "input"))
        elif isinstance(inp, list):
            slots += [(inp, i) for i, v in enumerate(inp) if isinstance(v, str)]
    return slots


def _response_slots(route: str, resp: Any) -> list[tuple[Any, Any]]:
    """Text in a model response (dicts or SDK objects with attributes)."""
    def get(o, k):
        return o.get(k) if isinstance(o, dict) else getattr(o, k, None)

    slots = []
    if route == "chat":
        for ch in get(resp, "choices") or []:
            msg = get(ch, "message")
            if msg is None:
                continue
            if isinstance(get(msg, "content"), str):
                slots.append((msg, "content"))
            for tc in get(msg, "tool_calls") or []:
                fn = get(tc, "function")
                if fn is not None and isinstance(get(fn, "arguments"), str):
                    slots.append((fn, "arguments"))
    elif route == "responses":
        for item in get(resp, "output") or []:
            for part in get(item, "content") or []:
                if get(part, "type") == "output_text" and isinstance(get(part, "text"), str):
                    slots.append((part, "text"))
            if isinstance(get(item, "arguments"), str):
                slots.append((item, "arguments"))
    return slots


def _read(c, k):
    return c[k] if isinstance(c, (dict, list)) else getattr(c, k)


def _write(c, k, v):
    if isinstance(c, (dict, list)):
        c[k] = v
    else:
        setattr(c, k, v)


class Gateway:
    def __init__(self, f):
        self.f, self.cfg = f, f.config.gateway

    # ---- who and why ------------------------------------------------------------------------------------------
    def claimed(self, headers: dict[str, str] | None, body: dict, request_meta: dict | None = None) \
            -> tuple[str | None, str | None]:
        """What the request itself says (headers, request metadata, the ``user`` field). Untrusted: the caller
        controls all of it. Used as-is only with ``principal_binding: header``, and in observe mode."""
        h = {k.lower(): v for k, v in (headers or {}).items()}
        ext = h.get(self.cfg.principal_header.lower())
        purpose = h.get(self.cfg.purpose_header.lower())
        for src in (request_meta or {}, body.get("metadata") if isinstance(body.get("metadata"), dict) else {}):
            ext = ext or src.get("dpdp_principal") or src.get("dpdp_principal_id")
            purpose = purpose or src.get("dpdp_purpose")
        if not ext and self.cfg.use_user_field:
            ext = body.get("user") or body.get("safety_identifier")
        return (str(ext) if ext else None), (str(purpose) if purpose else None)

    def identify(self, headers: dict[str, str] | None, body: dict, request_meta: dict | None = None,
                 trusted: dict | None = None, mode: str | None = None) -> tuple[str | None, str | None]:
        """The person's external id and the purpose for this call.

        ``trusted`` holds what the server, not the caller, vouches for: ``subject`` (the authenticated caller's
        own subject) and, for LiteLLM, ``key_principal`` / ``key_purpose`` from the virtual key's metadata.
        In enforce mode the person must come from the configured binding; anything the request claims that
        disagrees with it is refused, so a caller cannot act for another person by changing a header."""
        mode = mode or self.cfg.mode
        trusted = trusted or {}
        c_ext, c_purpose = self.claimed(headers, body, request_meta)
        binding = self.cfg.principal_binding
        if mode == "observe" or binding == "header":
            ext = c_ext or trusted.get("key_principal") or trusted.get("subject")
            return ext, c_purpose or trusted.get("key_purpose") or self.cfg.default_purpose
        if binding == "signed":
            h = {k.lower(): v for k, v in (headers or {}).items()}
            token = h.get(self.cfg.assertion_header.lower())
            if not token:
                if c_ext:
                    raise GatewayRefused(403, f"the person must be vouched for by a signed {self.cfg.assertion_header}"
                                         " (principal_binding: signed); a bare header or user field is not enough",
                                         "blocked:unverified_principal")
                return None, c_purpose or self.cfg.default_purpose
            ext, a_purpose = verify_assertion(self._secret(), token, self.cfg.assertion_max_ttl_seconds)
            purpose = a_purpose or c_purpose or self.cfg.default_purpose
            if a_purpose and c_purpose and c_purpose != a_purpose:
                raise GatewayRefused(403, "the purpose in the request differs from the signed assertion",
                                     "blocked:purpose_mismatch")
        elif binding == "subject":
            ext = trusted.get("subject")
            if not ext:
                if c_ext:
                    raise GatewayRefused(403, "principal_binding is subject: the caller's token carries no subject, "
                                         "so it cannot act for a person", "blocked:unverified_principal")
                return None, c_purpose or self.cfg.default_purpose
            purpose = c_purpose or self.cfg.default_purpose
        else:  # key
            ext = trusted.get("key_principal")
            if not ext:
                if c_ext:
                    raise GatewayRefused(403, "principal_binding is key: set dpdp_principal in the virtual key's "
                                         "metadata; the request cannot choose the person", "blocked:unverified_principal")
                return None, c_purpose or self.cfg.default_purpose
            purpose = trusted.get("key_purpose") or c_purpose or self.cfg.default_purpose
        if c_ext and c_ext != ext:
            raise GatewayRefused(403, "the person named in the request differs from the authenticated one",
                                 "blocked:principal_mismatch")
        return ext, purpose

    def _secret(self) -> bytes:
        import os

        v = os.environ.get(self.cfg.assertion_secret_env or "")
        if not v or len(v) < 32:
            raise GatewayRefused(500, f"principal_binding is signed but {self.cfg.assertion_secret_env} is not set "
                                 "(at least 32 characters)", "blocked:gateway_misconfigured")
        return v.encode()

    # ---- inbound --------------------------------------------------------------------------------------------------
    def inbound(self, route: str, body: dict, headers: dict | None = None, extra: dict | None = None,
                mode: str | None = None, trusted: dict | None = None) -> tuple[dict, CallState]:
        """Returns the body to send upstream (a modified copy in enforce mode) and the call state.
        Raises GatewayRefused when enforce mode blocks the call."""
        if route not in ROUTES:
            raise ValueError(f"route must be one of {ROUTES}")
        mode = mode or self.cfg.mode
        st = CallState(route, body.get("model"), None, None)
        try:
            ext, purpose = self.identify(headers, body, extra, trusted, mode)
        except GatewayRefused as e:
            st.decision = e.decision
            self.record(st, mode)
            raise
        st.purpose_id = purpose
        if mode == "observe":
            self._observe(route, body, ext, st)
            self.record(st, mode)
            return body, st
        try:
            out = self._enforce(route, body, ext, st)
        except GatewayRefused as e:
            st.decision = e.decision
            self.record(st, mode)
            raise
        self.record(st, mode)
        return out, st

    def _observe(self, route: str, body: dict, ext: str | None, st: CallState) -> None:
        det = self.f.tokenizer.detector
        for c, k in _text_slots(route, body):
            st.strings += 1
            st.entities.update(e.type for e in det.detect(_read(c, k)))
        pid = self.f.vault.resolve_principal(ext, create=False) if ext else None
        if not ext:
            st.would = "blocked:missing_principal" if self.cfg.missing_principal == "block" else "masked"
        elif not st.purpose_id:
            st.would = "blocked:missing_purpose"
        elif self.f.store.get_purpose(st.purpose_id) is None:
            st.would = "blocked:unknown_purpose"
        elif pid is None:
            st.would = "blocked:no_consent_record" if self.cfg.enforce_consent else "tokenised"
        elif self.cfg.enforce_consent:
            d = self.f.ledger.check(pid, st.purpose_id, set(st.entities))
            st.would = "tokenised" if d.allowed else f"blocked:{d.basis}"
        else:
            st.would = "tokenised"

    def _enforce(self, route: str, body: dict, ext: str | None, st: CallState) -> dict:
        import copy

        out = copy.deepcopy(body)
        if route == "responses" and self.cfg.force_store_false and out.get("store") is not False:
            out["store"] = False
        slots = _text_slots(route, out)
        if not ext:
            if self.cfg.missing_principal == "block":
                how = {"signed": f"a signed {self.cfg.assertion_header}", "subject": "an end-user token with a subject",
                       "key": "a virtual key with dpdp_principal", "header": f"the {self.cfg.principal_header} header"}
                raise GatewayRefused(403, f"say whose data this is: send {how[self.cfg.principal_binding]}",
                                     "blocked:missing_principal")
            det = self.f.tokenizer.detector
            for c, k in slots:              # irreversible masking: nobody to hold a key for
                text, parts, cur = _read(c, k), [], 0
                for e in det.detect(text):
                    st.entities[e.type] += 1
                    parts += [text[cur:e.start], f"[{e.type}]"]
                    cur = e.end
                _write(c, k, "".join(parts) + text[cur:])
                st.strings += 1
            st.decision = "masked"
            return out
        if not st.purpose_id:
            raise GatewayRefused(403, f"say why: send the {self.cfg.purpose_header} header", "blocked:missing_purpose")
        if self.f.store.get_purpose(st.purpose_id) is None:
            raise GatewayRefused(403, f"unknown purpose '{st.purpose_id}'", "blocked:unknown_purpose")
        pid = self.f.principal(ext)
        st.principal_id = pid
        env = ContextEnvelope(pid, st.purpose_id)
        tok = ctxmod.set_current(env)
        try:
            for c, k in slots:
                st.strings += 1
                try:
                    p = self.f.protect(_read(c, k), enforce_consent=self.cfg.enforce_consent)
                except ConsentDenied as e:
                    raise GatewayRefused(403, str(e), f"blocked:{_basis(e)}") from e
                st.entities.update(m.entity.type for m in (p.tokenized.mentions if p.tokenized else []))
                _write(c, k, p.text)
        finally:
            ctxmod.reset(tok)
        st.decision = "tokenised"
        return out

    # ---- outbound -------------------------------------------------------------------------------------------------
    def outbound(self, st: CallState, response: Any) -> Any:
        """Reveal tokens in the response for the end user, when configured (enforce mode only)."""
        if not self.cfg.reveal_responses or st.decision != "tokenised" or not st.principal_id:
            return response
        for c, k in _response_slots(st.route, response):
            _write(c, k, self.f.reveal(_read(c, k), for_principal=st.principal_id))
        return response

    # ---- observations and the report ---------------------------------------------------------------------------
    def record(self, st: CallState, mode: str) -> None:
        if not self.cfg.record_observations:
            return
        self.f.store.add_gateway_observation({
            "at": utcnow(), "mode": mode, "route": st.route, "model": (st.model or "")[:128] or None,
            "purpose_id": st.purpose_id, "principal_known": st.principal_id is not None or (
                st.would is not None and st.would not in ("blocked:missing_principal", "masked")),
            "decision": st.decision, "would": st.would, "strings": st.strings,
            "entities": dict(st.entities)})

    def report(self, since: datetime | None = None, until: datetime | None = None) -> dict:
        rows = self.f.store.gateway_observations(since, until)
        n = len(rows)
        ent, by_purpose, by_model, decisions, would = Counter(), Counter(), Counter(), Counter(), Counter()
        with_pii = known = 0
        for r in rows:
            e = r["entities"] or {}
            ent.update(e)
            if e:
                with_pii += 1
            known += bool(r["principal_known"])
            by_purpose[r["purpose_id"] or "(none)"] += 1
            by_model[r["model"] or "(none)"] += 1
            decisions[r["decision"]] += 1
            if r["would"]:
                would[r["would"]] += 1

        def pct(x):
            return round(100 * x / n, 1) if n else 0.0
        return {"requests": n, "from": rows[0]["at"].isoformat() if rows else None,
                "to": rows[-1]["at"].isoformat() if rows else None,
                "with_personal_data": with_pii, "with_personal_data_pct": pct(with_pii),
                "person_identified_pct": pct(known), "entity_types": dict(ent.most_common()),
                "by_purpose": dict(by_purpose.most_common()), "by_model": dict(by_model.most_common()),
                "decisions": dict(decisions.most_common()), "would_have_decided": dict(would.most_common())}


def _basis(e: Exception) -> str:
    import re

    m = re.search(r"basis=([a-z0-9_]+)", str(e))
    return m.group(1) if m else "consent"


def report_markdown(rep: dict) -> str:
    lines = ["# Model gateway report", "",
             f"- Requests: **{rep['requests']}** ({rep['from'] or '-'} to {rep['to'] or '-'})",
             f"- With personal data: **{rep['with_personal_data']}** ({rep['with_personal_data_pct']}%)",
             f"- Person identified: {rep['person_identified_pct']}%", ""]
    for title, key in (("Kinds of personal data (detections)", "entity_types"), ("By purpose", "by_purpose"),
                       ("By model", "by_model"), ("Decisions", "decisions"),
                       ("What enforce mode would have decided", "would_have_decided")):
        if rep[key]:
            lines += [f"## {title}", "", "| | Count |", "|---|---|"]
            lines += [f"| {k} | {v} |" for k, v in rep[key].items()]
            lines.append("")
    lines.append("Counts only; the gateway never records values. Detection is only as good as the configured "
                 "detectors.")
    return "\n".join(lines) + "\n"


# ---- signed assertions (principal_binding: signed) --------------------------------------------------------------------
def _b64(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint_assertion(secret: str | bytes, principal: str, purpose: str | None = None, ttl_seconds: int = 300,
                   now: float | None = None) -> str:
    """For the app's backend: vouch that the user it just authenticated is ``principal``, for ``purpose``.

    Send the result as the ``X-DPDP-Assertion`` header. ``v1.<payload>.<HMAC-SHA256>``, URL-safe base64."""
    import hashlib
    import hmac
    import json
    import time

    key = secret.encode() if isinstance(secret, str) else secret
    issued = int(now if now is not None else time.time())
    payload = _b64(json.dumps({"sub": principal, "purpose": purpose, "iat": issued, "exp": issued + ttl_seconds},
                              separators=(",", ":"), sort_keys=True).encode())
    sig = _b64(hmac.new(key, f"v1.{payload}".encode(), hashlib.sha256).digest())
    return f"v1.{payload}.{sig}"


def verify_assertion(secret: bytes, token: str, max_ttl_seconds: int, now: float | None = None,
                     skew_seconds: int = 30) -> tuple[str, str | None]:
    import hashlib
    import hmac
    import json
    import time

    def bad(why: str) -> GatewayRefused:
        return GatewayRefused(403, f"assertion refused: {why}", "blocked:bad_assertion")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        raise bad("not a v1 assertion")
    want = hmac.new(secret, f"v1.{parts[1]}".encode(), hashlib.sha256).digest()
    try:
        got = _unb64(parts[2])
        claims = json.loads(_unb64(parts[1]))
    except ValueError as e:
        raise bad("malformed") from e
    if not hmac.compare_digest(want, got):
        raise bad("signature does not match")
    t = now if now is not None else time.time()
    iat, exp = claims.get("iat"), claims.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int) or not claims.get("sub"):
        raise bad("missing sub, iat or exp")
    if exp - iat > max_ttl_seconds:
        raise bad(f"lifetime over {max_ttl_seconds}s")
    if t > exp + skew_seconds:
        raise bad("expired")
    if iat > t + skew_seconds:
        raise bad("issued in the future")
    return str(claims["sub"]), claims.get("purpose")
