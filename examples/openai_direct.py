"""Example: OpenAI API direct. The model only ever sees tokens.

    export OPENAI_API_KEY=... ; python examples/openai_direct.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dpdp_erasure import ErasureKit, KitConfig  # noqa: E402

cfg = KitConfig.from_dict({
    "provider": {"type": "openai", "model": os.environ.get("OPENAI_MODEL", "gpt-5-mini"), "store": False},
    "purposes": [{"id": "support_resolution"}],
    "connectors": [{"name": "openai_platform", "type": "openai_platform"}],
    "lineage": {"url": "sqlite:///.dpdp/openai_demo.db"},
})
kit = ErasureKit(cfg)
pid = kit.principal("cust-77")
kit.grant_consent(pid, "support_resolution")

with kit.context(pid, purpose="support_resolution"):
    msg = "Hi, I'm Meera Iyer (meera@example.in, +91 98111 22334). My UPI refund to meera@okaxis failed."
    safe = kit.protect(msg)
    print("Sent to OpenAI :", safe.text)
    ans = kit.generate(safe.text, system="You are a concise support agent.", already_protected=True)
    print("Model output   :", ans.text)
    print("Shown to Meera :", ans.reveal())

print(kit.erase(pid)["status"])
