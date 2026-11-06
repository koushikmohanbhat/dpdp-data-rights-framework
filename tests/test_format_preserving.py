"""Format-preserving surrogates (storage) and masked display (reveal)."""
import hashlib
import re
import sqlite3

import pytest
from _db import lineage_url

from dpdp_rights import DataRightsFramework
from dpdp_rights.core.config import FrameworkConfig
from dpdp_rights.pii.detectors import luhn_valid, verhoeff_check_digit, verhoeff_valid
from dpdp_rights.vault.vault import TOKEN_RE, make_surrogate, mask_value

AADHAAR = "2345 6789 012" + verhoeff_check_digit("23456789012")
DIG = hashlib.sha256(b"k").digest()


def shape(s: str) -> str:
    return re.sub(r"[A-Z]", "A", re.sub(r"[a-z]", "a", re.sub(r"\d", "9", s)))


def test_surrogates_keep_shape_and_cannot_be_real():
    phone = make_surrogate("PHONE_IN", "+91 98765 43210", DIG)
    assert phone.startswith("+91 ") and shape(phone) == shape("+91 98765 43210") and phone[4] in "6789"
    aad = make_surrogate("AADHAAR", AADHAAR, DIG)
    assert shape(aad) == shape(AADHAAR) and aad[0] in "23456789"
    assert not verhoeff_valid(aad.replace(" ", ""))            # never a valid Aadhaar
    card = make_surrogate("CARD_NUMBER", "4111 1111 1111 1111", DIG)
    assert shape(card) == shape("4111 1111 1111 1111") and not luhn_valid(card.replace(" ", ""))
    pan = make_surrogate("PAN", "ABCPS1234K", DIG)
    assert shape(pan) == shape("ABCPS1234K") and pan[3] == "P"
    assert make_surrogate("EMAIL", "priya@example.in", DIG).endswith("@surrogate.invalid")
    assert make_surrogate("PHONE_IN", "+91 98765 43210", DIG) == phone          # deterministic


def test_masked_display_values():
    assert mask_value("PHONE_IN", "+91 98765 43210") == "+91 ••••• •3210"
    assert mask_value("EMAIL", "priya@example.in") == "p••••@example.in"
    assert mask_value("AADHAAR", AADHAAR).endswith(AADHAAR[-4:]) and mask_value("AADHAAR", AADHAAR).count("•") == 8
    assert mask_value("NAME", "Priya Sharma") == "P•••• S•••••"


@pytest.fixture
def fpe(tmp_path):
    cfg = FrameworkConfig.model_validate({
        "vault": {"key_wrapper": "local", "local_master_key_path": str(tmp_path / "k")},
        "lineage": {"url": lineage_url(tmp_path)},
        "purposes": [{"id": "service", "description": "Service"}],
        "pii": {"surrogates": ["PHONE_IN", "AADHAAR", "EMAIL"]},
        "connectors": [{"name": "crm", "type": "sql_table", "options": {
            "url": f"sqlite:///{tmp_path}/crm.db", "table": "notes", "id_column": "id", "content_column": "body"}}],
    })
    con = sqlite3.connect(tmp_path / "crm.db")
    con.execute("CREATE TABLE notes (id TEXT PRIMARY KEY, body TEXT)")
    con.commit()
    return DataRightsFramework(cfg), con


def test_surrogates_round_trip_and_are_not_retokenised(fpe):
    dpdp, _ = fpe
    pid = dpdp.principal("c-1")
    dpdp.grant_consent(pid, "service")
    raw = f"Call +91 98765 43210, Aadhaar {AADHAAR}, mail asha@example.in, PAN ABCPS1234K"
    with dpdp.context(pid, purpose="service"):
        safe = dpdp.protect(raw)
        again = dpdp.protect(safe.text)          # stored text passing through again
    assert "98765" not in safe.text and "asha@" not in safe.text
    assert len(TOKEN_RE.findall(safe.text)) == 1      # only PAN uses a <TYPE_xxxx> token
    assert again.text == safe.text
    assert shape(safe.text.split(", Aadhaar")[0]) == shape("Call +91 98765 43210")
    assert dpdp.vault.reveal(safe.text) == raw
    masked = dpdp.vault.reveal(safe.text, masked=True)
    assert "+91 ••••• •3210" in masked and "a•••@example.in" in masked


def test_erasure_reaches_surrogates(fpe):
    dpdp, con = fpe
    asha, ravi = dpdp.principal("c-asha"), dpdp.principal("c-ravi")
    for p in (asha, ravi):
        dpdp.grant_consent(p, "service")
    dpdp.register_identifier(asha, "PHONE_IN", "+91 98765 43210")
    with dpdp.context(asha, purpose="service"):
        own = dpdp.protect("my number is +91 98765 43210")
        con.execute("INSERT INTO notes VALUES ('n1', ?)", (own.text,))
        dpdp.track_artifact("record", "crm", {"id": "n1"}, content=own.text, element_ids=own.element_ids)
    with dpdp.context(ravi, purpose="service"):
        other = dpdp.protect("nominee phone +91 98765 43210")
        con.execute("INSERT INTO notes VALUES ('n2', ?)", (other.text,))
        dpdp.track_artifact("record", "crm", {"id": "n2"}, content=other.text, element_ids=other.element_ids)
    con.commit()
    sur = own.text.split("is ")[1]
    assert sur in other.text                        # third-party mention resolved to Asha's surrogate

    out = dpdp.erase(asha)
    assert out["status"] == "completed", out["verification"]
    assert con.execute("SELECT count(*) FROM notes WHERE id='n1'").fetchone()[0] == 0
    assert con.execute("SELECT body FROM notes WHERE id='n2'").fetchone()[0] == "nominee phone [ERASED]"
