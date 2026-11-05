"""DPDP Data Rights Framework for AI Agents: consent, lineage and verifiable erasure for GenAI and agentic systems."""
from .core.config import FrameworkConfig
from .core.models import Action, ArtifactKind, EdgeType
from .framework import DataRightsFramework

__version__ = "0.1.0"
__all__ = ["DataRightsFramework", "FrameworkConfig", "Action", "ArtifactKind", "EdgeType"]
