from _db import lineage_url

from dpdp_rights.core.context import ContextEnvelope
from dpdp_rights.pii.detectors import RegexDetector, luhn_valid, verhoeff_check_digit, verhoeff_valid
from dpdp_rights.vault.vault import ERASED_MARKER, TOKEN_RE


def aadhaar(prefix="23456789012"):
    return prefix + verhoeff_check_digit(prefix)


def test_verhoeff_roundtrip():
    n = aadhaar()
    assert verhoeff_valid(n)
    assert not verhoeff_valid(n[:-1] + str((int(n[-1]) + 1) % 10))


def test_regex_detects_indian_identifiers():
    a = aadhaar()
    text = (f"Aadhaar {a[:4]} {a[4:8]} {a[8:]}, PAN ABCPR1234K, call +91 98765 43210, "
            f"mail x.y@example.in, upi foo@okhdfc, card 4111 1111 1111 1111. My name is Asha Nair.")
    types = {e.type for e in RegexDetector().detect(text)}
    assert {"AADHAAR", "PAN", "PHONE_IN", "EMAIL", "UPI_ID", "CARD_NUMBER", "NAME"} <= types


def test_regex_rejects_invalid_aadhaar_and_card():
    bad = aadhaar()[:-1] + str((int(aadhaar()[-1]) + 1) % 10)
    assert not [e for e in RegexDetector().detect(f"id {bad}") if e.type == "AADHAAR"]
    assert not luhn_valid("4111111111111112")


def test_tokens_stable_and_shreddable(dpdp):
    pid = dpdp.principal("c-1")
    t1 = dpdp.vault.tokenize(pid, "EMAIL", "A@x.in")
    t2 = dpdp.vault.tokenize(pid, "EMAIL", "a@x.in ")
    assert t1 == t2 and TOKEN_RE.fullmatch(t1)
    assert dpdp.vault.reveal(f"hi {t1}") == "hi A@x.in" or dpdp.vault.reveal(f"hi {t1}") == "hi a@x.in "
    dpdp.vault.shred(pid)
    assert dpdp.vault.reveal(f"hi {t1}") == f"hi {ERASED_MARKER}"
    assert not dpdp.vault.has_key(pid)


def test_same_value_different_principals_unlinkable(dpdp):
    a, b = dpdp.principal("a"), dpdp.principal("b")
    assert dpdp.vault.tokenize(a, "PHONE_IN", "9876543210") != dpdp.vault.tokenize(b, "PHONE_IN", "9876543210")


def test_legal_hold_survives_shred(dpdp):
    pid = dpdp.principal("c-2")
    tok = dpdp.vault.tokenize(pid, "PAN", "ABCPR1234K")
    dpdp.vault.shred(pid, retain_tokens={tok})
    assert dpdp.vault.detokenize(tok) is None                       # sealed: not readable by apps
    assert dpdp.vault.detokenize(tok, privileged=True) == "ABCPR1234K"


def test_retention_escrow_then_purge(dpdp):
    pid = dpdp.principal("c-3")
    tok = dpdp.vault.tokenize(pid, "EMAIL", "e@x.in")
    out = dpdp.vault.shred(pid, escrow=True)
    assert out["tokens_in_retention_escrow"] == 1
    assert dpdp.vault.reveal(tok) == ERASED_MARKER and dpdp.vault.detokenize(tok, privileged=True) == "e@x.in"
    dpdp.vault.destroy(out["escrow_id"])
    assert dpdp.vault.detokenize(tok, privileged=True) is None


def test_baggage_roundtrip():
    env = ContextEnvelope("dp_1", "service", "s/1", ("art_a", "art_b"), "acme")
    back = ContextEnvelope.from_headers(env.to_headers())
    assert back == env


def test_digits_inside_a_token_are_not_retokenised(tmp_path):
    """Regression: a token whose hex suffix is 12 digits passing the Aadhaar checksum."""
    from dpdp_rights.pii.detectors import verhoeff_check_digit
    from dpdp_rights.pii.tokenizer import TOKEN_RE

    digits = "24241050814"
    digits += verhoeff_check_digit(digits)
    fake_token = f"<EMAIL_{digits}>"
    assert TOKEN_RE.fullmatch(fake_token)

    from dpdp_rights import DataRightsFramework
    from dpdp_rights.core.config import FrameworkConfig

    cfg = FrameworkConfig.model_validate({
        "vault": {"key_wrapper": "local", "local_master_key_path": str(tmp_path / "k")},
        "lineage": {"url": lineage_url(tmp_path)},
    })
    dpdp = DataRightsFramework(cfg)
    pid = dpdp.principal("t-1")
    out = dpdp.tokenizer.tokenize(f"Refund raised for {fake_token}", pid)
    assert out.text == f"Refund raised for {fake_token}"
    assert out.mentions == []


def test_upi_id_at_end_of_sentence_is_detected():
    d = RegexDetector()
    assert [(e.type, e.text) for e in d.detect("Premium via UPI rahulv@okhdfc.")] == [("UPI_ID", "rahulv@okhdfc")]
    types = {e.type for e in d.detect("mail asha@example.in today")}
    assert "UPI_ID" not in types and "EMAIL" in types
