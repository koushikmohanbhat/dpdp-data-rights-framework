"""A detector for an identifier specific to one client: employee IDs such as ``EMP-123456``."""
from __future__ import annotations

import re

from dpdp_rights.pii.detectors import Entity


class EmployeeIdDetector:
    #: True only for detectors that find names, addresses and free text (counts towards the production
    #: guardrail that requires an NER detector). An ID pattern is not NER.
    ner = False

    def __init__(self, prefix: str = "EMP", digits: int = 6):
        self.pattern = re.compile(rf"\b{re.escape(prefix)}-\d{{{digits}}}\b")

    def detect(self, text: str) -> list[Entity]:
        return [Entity("EMPLOYEE_ID", m.start(), m.end(), m.group(0), 0.95) for m in self.pattern.finditer(text)]
