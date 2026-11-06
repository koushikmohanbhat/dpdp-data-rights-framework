"""NER sidecar: a token-classification model (default AI4Bharat IndicNER) behind a small local HTTP API.

Run it next to whatever calls ``protect()`` (the agent, the Rights API, the worker), listening on localhost only,
and point the ``remote_ner`` detector at it. The model is baked into the image at build time
(deploy/ner/Dockerfile), so the container needs no internet access and text never leaves the task or pod.

    dpdp-rights ner-serve --model /models/IndicNER --port 8081

    POST /v1/ner   {"texts": ["..."]}  ->  {"model": "...", "entities": [[{"type", "start", "end", "score"}], ...]}
    GET  /healthz                      ->  {"ok": true, "model": "..."}

No authentication: bind it to 127.0.0.1 (the default) inside a task or pod, never to a shared network.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from pydantic import BaseModel

from .detectors import Entity, TransformersNerDetector

MAX_TEXTS, MAX_CHARS = 64, 20_000


class NerIn(BaseModel):
    texts: list[str]


def create_ner_app(detector, model_name: str):
    from fastapi import FastAPI, HTTPException

    app = FastAPI(title="DPDP NER sidecar", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def health():
        return {"ok": True, "model": model_name}

    @app.post("/v1/ner")
    def ner(body: NerIn):
        if len(body.texts) > MAX_TEXTS:
            raise HTTPException(413, f"at most {MAX_TEXTS} texts per call")
        if any(len(t) > MAX_CHARS for t in body.texts):
            raise HTTPException(413, f"texts are limited to {MAX_CHARS} characters")
        return {"model": model_name, "entities": [
            [{"type": e.type, "start": e.start, "end": e.end, "score": round(e.score, 4)} for e in detector.detect(t)]
            for t in body.texts]}

    return app


def serve(model: str, host: str = "127.0.0.1", port: int = 8081, include_locations: bool = False,
          min_score: float = 0.7) -> None:  # pragma: no cover - needs the model
    import uvicorn

    det = TransformersNerDetector(model=model, include_locations=include_locations, min_score=min_score)
    uvicorn.run(create_ner_app(det, model), host=host, port=port, log_level="warning")


class RemoteNerDetector:
    """Calls the NER sidecar. ``on_error``: ``raise`` (default) stops the caller, so text is never passed on
    unchecked because the sidecar was down; ``skip`` carries on with the other detectors and counts the miss."""

    def __init__(self, url: str = "http://127.0.0.1:8081", timeout_seconds: float = 5.0, on_error: str = "raise",
                 opener=None):
        if on_error not in ("raise", "skip"):
            raise ValueError("remote_ner on_error must be raise or skip")
        self.url, self.timeout, self.on_error = url.rstrip("/"), timeout_seconds, on_error
        self._open = opener or urllib.request.urlopen
        self.skipped = 0

    def detect(self, text: str) -> list[Entity]:
        if not text.strip():
            return []
        req = urllib.request.Request(self.url + "/v1/ner", data=json.dumps({"texts": [text]}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        last = None
        for attempt in range(2):
            try:
                with self._open(req, timeout=self.timeout) as resp:
                    ents = json.loads(resp.read())["entities"][0]
                return [Entity(e["type"], int(e["start"]), int(e["end"]), text[int(e["start"]):int(e["end"])],
                               float(e.get("score", 1.0))) for e in ents]
            except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
                last = exc
                time.sleep(0.05 * (attempt + 1))
        if self.on_error == "skip":
            self.skipped += 1
            return []
        raise RuntimeError(f"NER sidecar at {self.url} is unavailable: {type(last).__name__}") from last
