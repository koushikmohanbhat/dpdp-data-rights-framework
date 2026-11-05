"""Detect PII in text and replace it with vault tokens, attributing each mention
to the right data principal (including third parties named in someone else's content)."""
from __future__ import annotations

from dataclasses import dataclass

from ..vault.vault import TOKEN_RE, Vault
from .detectors import CompositeDetector, Entity

# Identifier types that can be resolved to a *known* principal via the vault lookup index.
RESOLVABLE = {"EMAIL", "PHONE_IN", "PHONE", "PAN", "AADHAAR", "UPI_ID"}


@dataclass
class Mention:
    entity: Entity
    token: str
    principal_id: str
    third_party: bool


@dataclass
class TokenizedText:
    text: str
    mentions: list[Mention]

    @property
    def principals(self) -> set[str]:
        return {m.principal_id for m in self.mentions}


class Tokenizer:
    def __init__(self, detector: CompositeDetector, vault: Vault):
        self.detector = detector
        self.vault = vault

    def tokenize(self, text: str, principal_id: str) -> TokenizedText:
        entities = [e for e in self.detector.detect(text) if not TOKEN_RE.fullmatch(e.text)]
        mentions: list[Mention] = []
        pieces: list[str] = []
        cursor = 0
        for e in entities:
            owner, third = principal_id, False
            if e.type in RESOLVABLE:
                other = self.vault.find_principal_by_identifier(e.type, e.text)
                if other and other != principal_id:
                    owner, third = other, True
            # Identifiers are only linked to a principal explicitly (kit.register_identifier),
            # never auto-learned, so a third party's email typed by the speaker is not
            # wrongly attributed to the speaker's account later.
            token = self.vault.tokenize(owner, e.type, e.text, third_party=third)
            pieces.append(text[cursor:e.start])
            pieces.append(token)
            cursor = e.end
            mentions.append(Mention(e, token, owner, third))
        pieces.append(text[cursor:])
        return TokenizedText("".join(pieces), mentions)
