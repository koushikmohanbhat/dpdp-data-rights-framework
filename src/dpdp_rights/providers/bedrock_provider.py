"""Amazon Bedrock via the Converse API (works for Anthropic, Amazon Nova, Meta,
Mistral, OpenAI open-weight models, etc. hosted on Bedrock).

Note: if Bedrock *model invocation logging* is enabled, prompts land in
CloudWatch Logs and/or S3. Because the framework tokenises before calling, those
logs hold tokens only; register the log group with the ``aws_cloudwatch_logs``
connector so they are covered by discovery and verification.
"""
from __future__ import annotations

import json

from .base import ProviderResult


class BedrockProvider:
    name = "bedrock"

    def __init__(self, model: str, embedding_model: str | None = None, region: str | None = None,
                 guardrail_id: str | None = None, guardrail_version: str = "DRAFT", client=None, **_):
        if client is None:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=region)
        self.client = client
        self.model = model
        self.embedding_model = embedding_model or "amazon.titan-embed-text-v2:0"
        self.guardrail = ({"guardrailIdentifier": guardrail_id, "guardrailVersion": guardrail_version}
                          if guardrail_id else None)

    def generate(self, prompt: str, system: str | None = None, **kw) -> ProviderResult:
        args = {"modelId": self.model, "messages": [{"role": "user", "content": [{"text": prompt}]}]}
        if system:
            args["system"] = [{"text": system}]
        if self.guardrail:
            args["guardrailConfig"] = self.guardrail
        if kw:
            args["inferenceConfig"] = kw
        r = self.client.converse(**args)
        text = "".join(c.get("text", "") for c in r["output"]["message"]["content"])
        return ProviderResult(text=text, usage=r.get("usage", {}))

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            r = self.client.invoke_model(modelId=self.embedding_model, body=json.dumps({"inputText": t}))
            out.append(json.loads(r["body"].read())["embedding"])
        return out
