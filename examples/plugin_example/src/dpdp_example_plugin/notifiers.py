"""A notifier that appends events to a JSONL file, standing in for a ticketing or messaging integration."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class JsonlOutboxNotifier:
    def __init__(self, path: str = "dpdp-outbox.jsonl"):
        self.path = Path(path)

    def notify(self, event: str, payload: dict) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "event": event,
                                "payload": payload}, default=str) + "\n")
