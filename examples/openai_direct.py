"""Example: OpenAI API direct. The model only ever sees tokens.

    export OPENAI_API_KEY=... ; python examples/openai_direct.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dpdp_rights import DataRightsFramework, FrameworkConfig  # noqa: E402

cfg = FrameworkConfig.from_dict({
    "provider": {"type": "openai", "model": os.environ.get("OPENAI_MODEL", "gpt-5-mini"), "store": False},
    "purposes": [{"id": "service_delivery"}],
    "connectors": [{"name": "openai_platform", "type": "openai_platform"}],
    "lineage": {"url": "sqlite:///.dpdp/openai_demo.db"},
})
dpdp = DataRightsFramework(cfg)
pid = dpdp.principal("cust-77")
dpdp.grant_consent(pid, "service_delivery")

with dpdp.context(pid, purpose="service_delivery"):
    msg = "Hi, I'm Meera Iyer (meera@example.in, +91 98111 22334). My UPI refund to meera@okaxis failed."
    safe = dpdp.protect(msg)
    print("Sent to OpenAI :", safe.text)
    ans = dpdp.generate(safe.text, system="You are a concise insurance onboarding agent.", already_protected=True)
    print("Model output   :", ans.text)
    print("Shown to Meera :", ans.reveal())

print(dpdp.erase(pid)["status"])
