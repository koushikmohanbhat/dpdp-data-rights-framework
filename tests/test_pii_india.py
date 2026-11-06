"""India-specific detection: identifiers, Indic digits, names in Indian languages, addresses."""
import pytest

from dpdp_rights.pii.detectors import RegexDetector, merge_entities, verhoeff_check_digit


def found(text: str) -> list[tuple[str, str]]:
    return [(e.type, e.text) for e in merge_entities(RegexDetector().detect(text))]


AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")


@pytest.mark.parametrize("text,expected", [
    ("cover for KA-01-AB-1234", ("VEHICLE_REG", "KA-01-AB-1234")),
    ("car MH12DE1433 parked", ("VEHICLE_REG", "MH12DE1433")),
    ("new BH series 22 BH 1234 AA", ("VEHICLE_REG", "22 BH 1234 AA")),
    ("GSTIN 27AAPFU0939F1ZV", ("GSTIN", "27AAPFU0939F1ZV")),
    ("ABHA 91-1234-5678-9012", ("ABHA_NUMBER", "91-1234-5678-9012")),
    ("DL MH14 20110012345", ("DRIVING_LICENCE", "MH14 20110012345")),
    ("Passport no. K1234567", ("PASSPORT", "K1234567")),
    ("account number 123456789012", ("BANK_ACCOUNT", "123456789012")),
    ("voter id ABC1234567", ("VOTER_ID", "ABC1234567")),
])
def test_indian_identifiers(text, expected):
    assert expected in found(text)


def test_context_required_identifiers_are_not_guessed():
    assert found("Invoice INV2024001 total 1500") == []        # looks like a voter ID
    assert found("Order K1234567 shipped") == []               # looks like a passport
    assert found("GSTIN 27AAPFU0939F1ZX") == []                 # bad checksum


def test_indic_digits_keep_offsets():
    deva = AADHAAR.translate(str.maketrans("0123456789", "०१२३४५६७८९"))
    text = f"मेरा आधार {deva[:4]} {deva[4:8]} {deva[8:]} है"
    (etype, value), = [f for f in found(text) if f[0] == "AADHAAR"]
    assert value == f"{deva[:4]} {deva[4:8]} {deva[8:]}"
    assert ("PHONE_IN", "९८७६५ ४३२१०") in found("phone ९८७६५ ४३२१०")


@pytest.mark.parametrize("text,name", [
    ("मेरा नाम प्रिया शर्मा है", "प्रिया शर्मा"),
    ("माझे नाव प्रिया आहे", "प्रिया"),
    ("আমার নাম প্রিয়া শর্মা", "প্রিয়া শর্মা"),
    ("என் பெயர் பிரியா", "பிரியா"),
    ("నా పేరు ప్రియ", "ప్రియ"),
    ("ನನ್ನ ಹೆಸರು ಪ್ರಿಯಾ", "ಪ್ರಿಯಾ"),
    ("મારું નામ પ્રિયા છે", "પ્રિયા"),
    ("मेरा नाम विक्रम अय्यर है। Travel cover", "विक्रम अय्यर"),
    ("mera naam priya sharma hai", "priya sharma"),
    ("My name is Priya Sharma", "Priya Sharma"),
])
def test_names_in_indian_languages(text, name):
    assert ("NAME", name) in found(text)


def test_address_needs_cue_and_pin():
    assert ("ADDRESS", "Flat 4B, Prestige Lakeside, Whitefield, Bengaluru 560066") in \
        found("Address: Flat 4B, Prestige Lakeside, Whitefield, Bengaluru 560066. Call me")
    assert ("ADDRESS", "12, गांधी नगर, जयपुर 302015") in found("पता: 12, गांधी नगर, जयपुर 302015")
    assert not [f for f in found("Bengaluru 560066 is a nice area") if f[0] == "ADDRESS"]
