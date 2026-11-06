"""Documents: local text extraction for digital PDFs; OCR backends (fakes) for scans and images."""
import io
from types import SimpleNamespace

import pytest
from _db import lineage_url

from dpdp_rights import DataRightsFramework
from dpdp_rights.core.config import FrameworkConfig
from dpdp_rights.pii.detectors import verhoeff_check_digit
from dpdp_rights.pii.documents import DocumentAIOCR, TextractOCR, extract_text, guess_mime

pytest.importorskip("pypdf")
canvas = pytest.importorskip("reportlab.pdfgen.canvas")

AADHAAR = "2345 6789 012" + verhoeff_check_digit("23456789012")


def make_pdf(pages: list[list[str]]) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    for lines in pages:
        for i, line in enumerate(lines):
            c.drawString(72, 750 - 18 * i, line)
        c.showPage()
    c.save()
    return buf.getvalue()


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


@pytest.fixture
def dpdp(tmp_path):
    cfg = FrameworkConfig.model_validate({
        "vault": {"key_wrapper": "local", "local_master_key_path": str(tmp_path / "k")},
        "lineage": {"url": lineage_url(tmp_path)},
        "purposes": [{"id": "kyc", "description": "KYC"}],
    })
    return DataRightsFramework(cfg)


def test_digital_pdf_is_read_locally_with_pages(dpdp):
    pdf = make_pdf([["Application form", "Name: Priya Sharma"],
                    [f"Aadhaar {AADHAAR}", "PAN ABCPS1234K", "Address: 12 MG Road, Bengaluru 560001"]])
    pid = dpdp.principal("doc-1")
    dpdp.grant_consent(pid, "kyc")
    with dpdp.context(pid, purpose="kyc"):
        out = dpdp.protect_document(pdf, filename="kyc.pdf")
    assert out.source == "pdf_text" and out.pages == 2
    assert AADHAAR not in out.text and "ABCPS1234K" not in out.text and "MG Road" not in out.text
    pages = {(d.entity.type, d.page) for d in out.entities}
    assert {("NAME", 1), ("AADHAAR", 2), ("PAN", 2), ("ADDRESS", 2)} <= pages
    assert dpdp.vault.reveal(out.text).count(AADHAAR) == 1


def test_scans_need_ocr(dpdp):
    blank = make_pdf([[]])
    with pytest.raises(ValueError, match="needs OCR"):
        extract_text(blank)
    with pytest.raises(ValueError, match="unsupported"):
        guess_mime(b"hello")


class FakeTextract:
    def __init__(self):
        self.calls = []

    def detect_document_text(self, Document):
        self.calls.append("sync")
        return {"Blocks": [{"BlockType": "LINE", "Page": 1, "Text": "PAN ABCPS1234K"},
                           {"BlockType": "WORD", "Page": 1, "Text": "PAN"}]}

    def start_document_text_detection(self, DocumentLocation):
        self.calls.append(DocumentLocation["S3Object"]["Name"])
        return {"JobId": "j1"}

    def get_document_text_detection(self, JobId, NextToken=None):
        if NextToken is None:
            return {"JobStatus": "SUCCEEDED", "NextToken": "n",
                    "Blocks": [{"BlockType": "LINE", "Page": 1, "Text": "page one"}]}
        return {"JobStatus": "SUCCEEDED", "Blocks": [{"BlockType": "LINE", "Page": 2, "Text": f"Aadhaar {AADHAAR}"}]}


def test_textract_image_and_multipage_s3():
    t = TextractOCR(client=FakeTextract())
    doc = extract_text(PNG, ocr=t)
    assert doc.source == "textract" and doc.text == "PAN ABCPS1234K"
    doc = extract_text(s3_uri="s3://kyc-bucket/uploads/a.pdf", ocr=t)
    assert [p.text for p in doc.pages] == ["page one", f"Aadhaar {AADHAAR}"]
    assert doc.page_of(doc.text.index("Aadhaar")) == 2
    assert t.client.calls == ["sync", "uploads/a.pdf"]


def test_document_ai_pages():
    text = "Name: Asha Rao\nPAN ABCPR1234K"
    seg = lambda s, e: SimpleNamespace(start_index=s, end_index=e)        # noqa: E731
    page = lambda s, e: SimpleNamespace(layout=SimpleNamespace(text_anchor=SimpleNamespace(text_segments=[seg(s, e)])))  # noqa: E731
    doc = SimpleNamespace(text=text, pages=[page(0, 14), page(15, len(text))])
    client = SimpleNamespace(process_document=lambda request: SimpleNamespace(document=doc))
    out = extract_text(PNG, ocr=DocumentAIOCR("projects/p/locations/us/processors/x", client=client))
    assert [p.text for p in out.pages] == ["Name: Asha Rao", "PAN ABCPR1234K"]
