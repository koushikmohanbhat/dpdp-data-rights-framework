import pytest
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


# ---- concurrency (found by the agent-framework integrations, 18 Nov 2026) ----------------------------------
def test_two_processes_creating_one_persons_key_end_up_with_the_same_key(dpdp):
    """Two vaults over one storage stand in for two worker processes. The second key write must not overwrite
    the first, or everything encrypted under the first key becomes unreadable."""
    from dpdp_rights.vault.vault import Vault
    v1 = dpdp.vault
    v2 = Vault(v1.storage, v1.wrapper)
    pid = "dp_race_key"
    original = v1.storage.put_key
    calls = []

    def put_key_late(principal_id, wrapped):        # v1 writes its key just before v2 does
        calls.append(principal_id)
        if len(calls) == 1:
            v2_token[0] = v2.tokenize(pid, "EMAIL", "late@example.in")
        original(principal_id, wrapped)
    v2_token = [None]
    v1.storage.put_key = put_key_late
    try:
        t1 = v1.tokenize(pid, "EMAIL", "first@example.in")
    finally:
        v1.storage.put_key = original
    assert v1.reveal(t1, {pid}) == "first@example.in"
    assert v2.reveal(v2_token[0], {pid}) == "late@example.in"
    assert v1.reveal(v2_token[0], {pid}) == "late@example.in"     # both use the one stored key


def test_concurrent_tokenisation_of_the_same_value_succeeds(dpdp):
    from concurrent.futures import ThreadPoolExecutor
    pid = dpdp.principal("race-person")
    with ThreadPoolExecutor(8) as ex:
        tokens = set(ex.map(lambda _: dpdp.vault.tokenize(pid, "EMAIL", "same@example.in"), range(40)))
    assert len(tokens) == 1 and dpdp.vault.reveal(tokens.pop(), {pid}) == "same@example.in"


def test_dynamodb_key_write_never_overwrites_an_existing_key(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    from dpdp_rights.vault.storage import DynamoDBVaultStorage
    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="ap-south-1")
        ddb.create_table(TableName="v_keys", KeySchema=[{"AttributeName": "principal_id", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "principal_id", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        s = DynamoDBVaultStorage("v", resource=ddb)
        s.put_key("dp_1", b"first")
        s.put_key("dp_1", b"second")                  # a second process racing: must not replace the key
        assert s.get_key("dp_1") == b"first"


# ---- envelope encryption: KMS calls (20 Nov 2026) ----------------------------------------------------------
class _CountingWrapper:
    def __init__(self, inner):
        self.inner, self.wraps, self.unwraps = inner, 0, 0

    def wrap(self, dek, context):
        self.wraps += 1
        return self.inner.wrap(dek, context)

    def unwrap(self, blob, context):
        self.unwraps += 1
        return self.inner.unwrap(blob, context)


def test_a_new_person_costs_one_kms_call_and_cached_use_costs_none(dpdp):
    from dpdp_rights.vault.vault import Vault
    w = _CountingWrapper(dpdp.vault.wrapper)
    v = Vault(dpdp.vault.storage, w)
    w.wraps = w.unwraps = 0                         # ignore the lookup key loaded at start-up
    pid = "dp_kms_count"
    t = v.tokenize(pid, "EMAIL", "count@example.in")
    assert (w.wraps, w.unwraps) == (1, 0)           # wrap only: we already hold the plaintext we generated
    for i in range(20):
        v.tokenize(pid, "PHONE_IN", f"98765432{i:02d}")
    assert v.reveal(t, {pid}) == "count@example.in"
    assert (w.wraps, w.unwraps) == (1, 0)           # served from the DEK cache
    v2 = Vault(dpdp.vault.storage, w)               # another process: one unwrap on its first use
    w.wraps = w.unwraps = 0
    assert v2.reveal(t, {pid}) == "count@example.in"
    assert (w.wraps, w.unwraps) == (0, 1)


def test_erasure_deletes_the_wrapped_key_row_without_calling_kms(dpdp):
    from dpdp_rights.vault.vault import Vault
    w = _CountingWrapper(dpdp.vault.wrapper)
    v = Vault(dpdp.vault.storage, w)
    pid = "dp_kms_shred"
    v.tokenize(pid, "EMAIL", "gone@example.in")
    w.wraps = w.unwraps = 0
    v.shred(pid)
    assert v.storage.get_key(pid) is None
    assert (w.wraps, w.unwraps) == (0, 0)
