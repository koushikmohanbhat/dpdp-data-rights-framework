"""Personal data in documents: KYC scans, uploaded PDFs, photos of ID cards.

``extract_text`` turns a document into text, page by page:

* PDFs with a text layer are read locally (``pypdf``); nothing leaves your environment.
* Scans and images go to an OCR service you choose: Amazon Textract or Google Document AI.
  Configure one in your own account and region, since the raw document is sent to it.

``DataRightsFramework.protect_document`` then runs the normal detectors and tokenisation on the text, so the
agent, logs and indexes only receive the tokenised text. The original file is still personal data: keep it
in a store with a connector (for example ``aws_s3_objects``) and register it with ``track_artifact`` so
erasure deletes it.
"""
from __future__ import annotations

import io
import time
from dataclasses import dataclass, field

from .detectors import Entity


@dataclass
class Page:
    number: int          # 1-based
    text: str
    start: int           # offset of this page in ExtractedDocument.text


@dataclass
class ExtractedDocument:
    text: str
    pages: list[Page]
    source: str          # pdf_text | textract | document_ai

    def page_of(self, offset: int) -> int:
        for p in reversed(self.pages):
            if offset >= p.start:
                return p.number
        return 1


@dataclass
class DocumentEntity:
    entity: Entity
    page: int


@dataclass
class ProtectedDocument:
    text: str                                   # tokenised text, safe to store, embed or send to a model
    element_ids: list[str]
    entities: list[DocumentEntity] = field(default_factory=list)
    pages: int = 0
    source: str = ""


def _join(pages: list[str], source: str) -> ExtractedDocument:
    out, parts, pos = [], [], 0
    for i, t in enumerate(pages, start=1):
        out.append(Page(i, t, pos))
        parts.append(t)
        pos += len(t) + 2
    return ExtractedDocument("\n\n".join(parts), out, source)


def is_pdf(data: bytes) -> bool:
    return data[:5] == b"%PDF-"


def pdf_text(data: bytes) -> ExtractedDocument:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    return _join([(p.extract_text() or "").strip() for p in reader.pages], "pdf_text")


class TextractOCR:
    """Amazon Textract. Images and single-page PDFs are sent inline; multi-page PDFs need ``s3_uri``
    (Textract reads them asynchronously from S3)."""

    def __init__(self, region: str | None = None, client=None, poll_seconds: float = 2.0, timeout_seconds: int = 300):
        if client is None:
            import boto3

            client = boto3.client("textract", region_name=region)
        self.client, self.poll, self.timeout = client, poll_seconds, timeout_seconds

    @staticmethod
    def _pages(blocks: list[dict]) -> list[str]:
        pages: dict[int, list[str]] = {}
        for b in blocks:
            if b.get("BlockType") == "LINE":
                pages.setdefault(int(b.get("Page", 1)), []).append(b.get("Text", ""))
        return ["\n".join(pages[k]) for k in sorted(pages)] or [""]

    def extract(self, data: bytes | None = None, s3_uri: str | None = None) -> ExtractedDocument:
        if s3_uri:
            bucket, _, key = s3_uri.removeprefix("s3://").partition("/")
            job = self.client.start_document_text_detection(
                DocumentLocation={"S3Object": {"Bucket": bucket, "Name": key}})["JobId"]
            blocks, token, waited = [], None, 0.0
            while True:
                kw = {"JobId": job, **({"NextToken": token} if token else {})}
                r = self.client.get_document_text_detection(**kw)
                if r["JobStatus"] == "IN_PROGRESS":
                    if waited >= self.timeout:
                        raise TimeoutError(f"Textract job {job} still running after {self.timeout}s")
                    time.sleep(self.poll)
                    waited += self.poll
                    continue
                if r["JobStatus"] != "SUCCEEDED":
                    raise RuntimeError(f"Textract job {job} ended {r['JobStatus']}")
                blocks += r.get("Blocks", [])
                token = r.get("NextToken")
                if not token:
                    break
            return _join(self._pages(blocks), "textract")
        r = self.client.detect_document_text(Document={"Bytes": data})
        return _join(self._pages(r.get("Blocks", [])), "textract")


class DocumentAIOCR:
    """Google Document AI, using an OCR processor you create. ``processor`` is its full resource name
    (``projects/<p>/locations/<loc>/processors/<id>``). Check which Document AI locations your data
    residency rules allow before choosing one."""

    def __init__(self, processor: str, client=None):
        if client is None:
            from google.api_core.client_options import ClientOptions  # type: ignore
            from google.cloud import documentai  # type: ignore

            location = processor.split("/locations/")[1].split("/")[0]
            client = documentai.DocumentProcessorServiceClient(
                client_options=ClientOptions(api_endpoint=f"{location}-documentai.googleapis.com"))
        self.client, self.processor = client, processor

    def extract(self, data: bytes, mime_type: str) -> ExtractedDocument:
        r = self.client.process_document(request={"name": self.processor,
                                                   "raw_document": {"content": data, "mime_type": mime_type}})
        doc = r.document
        pages = []
        for p in doc.pages:
            segs = p.layout.text_anchor.text_segments
            pages.append("".join(doc.text[int(s.start_index or 0):int(s.end_index)] for s in segs).strip())
        return _join(pages or [doc.text], "document_ai")


def guess_mime(data: bytes, filename: str | None = None) -> str:
    if is_pdf(data):
        return "application/pdf"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    name = (filename or "").lower()
    for ext, mime in ((".pdf", "application/pdf"), (".png", "image/png"), (".jpg", "image/jpeg"),
                      (".jpeg", "image/jpeg"), (".tif", "image/tiff"), (".tiff", "image/tiff")):
        if name.endswith(ext):
            return mime
    raise ValueError("unsupported document type: expected PDF, PNG, JPEG or TIFF")


def build_ocr(cfg: dict):
    kind = (cfg or {}).get("ocr", "none")
    if kind == "textract":
        return TextractOCR(region=cfg.get("region"))
    if kind == "document_ai":
        if not cfg.get("processor"):
            raise ValueError("pii.documents.processor is required for document_ai")
        return DocumentAIOCR(cfg["processor"])
    if kind == "none":
        return None
    raise ValueError(f"Unknown OCR backend {kind}")


def extract_text(data: bytes | None = None, *, filename: str | None = None, ocr=None,
                 s3_uri: str | None = None, min_chars_per_page: int = 20) -> ExtractedDocument:
    """Text of a document. PDFs with a text layer are read locally; scans and images use ``ocr``."""
    if s3_uri:
        if not isinstance(ocr, TextractOCR):
            raise ValueError("s3_uri needs Textract OCR (pii.documents.ocr: textract)")
        return ocr.extract(s3_uri=s3_uri)
    if data is None:
        raise ValueError("pass the document bytes or s3_uri")
    mime = guess_mime(data, filename)
    if mime == "application/pdf":
        doc = pdf_text(data)
        if all(len(p.text) >= min_chars_per_page for p in doc.pages):
            return doc                         # digital PDF: no OCR needed
    if ocr is None:
        raise ValueError("this document needs OCR (a scan or an image); configure pii.documents.ocr")
    if isinstance(ocr, TextractOCR):
        return ocr.extract(data=data)
    return ocr.extract(data, mime)
