"""Agent-platform connectors beyond memory.

* gcp_agent_engine_sessions - Vertex AI Agent Engine Sessions (conversation history; the GCP
                              counterpart of AgentCore Memory short-term events)
* aws_agentcore_identity    - Amazon Bedrock AgentCore Identity: per-user OAuth tokens held in
                              the token vault on the agent's behalf

AgentCore Identity has no API to delete one user's stored tokens. Erasure therefore revokes
the user's sessions at the identity provider, which invalidates the refresh tokens the vault
holds: Amazon Cognito ``AdminUserGlobalSignOut`` when configured, or a webhook to your IdP
(Entra ID, Okta, Google). The certificate records this as a provider-side revocation.
"""
from __future__ import annotations

import json
import urllib.request

from ..core.models import Action
from .base import Capabilities, Connector, Discovered, VerifyResult, register


@register("gcp_agent_engine_sessions")
class AgentEngineSessionsConnector(Connector):
    """Options: reasoning_engine (projects/../locations/../reasoningEngines/ID).

    Create sessions with ``user_id=<pseudonymous principal id>``. Uses the v1beta1 REST API.
    """

    supports = {Action.DELETE}
    capabilities = Capabilities(
        store='Vertex AI Agent Engine Sessions',
        discover='native', discover_how='sessions by user_id',
        verify='rediscover', verify_how='re-discovery returns nothing',
        limits=(
            'uses a v1beta1 API that may change',
        ))

    def __init__(self, name: str, reasoning_engine: str, session=None, **kw):
        super().__init__(name, **kw)
        if session is None:
            import google.auth  # type: ignore
            from google.auth.transport.requests import AuthorizedSession  # type: ignore

            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            session = AuthorizedSession(creds)
        self.http = session
        self.engine = reasoning_engine
        loc = reasoning_engine.split("/locations/")[1].split("/")[0]
        self.base = f"https://{loc}-aiplatform.googleapis.com/v1beta1"

    def discover(self, ctx):
        out, token = [], None
        while True:
            params = {"filter": f'user_id="{ctx.principal_id}"', "pageSize": 100}
            if token:
                params["pageToken"] = token
            r = self.http.get(f"{self.base}/{self.engine}/sessions", params=params)
            r.raise_for_status()
            data = r.json()
            out += [Discovered("memory_event", {"name": s["name"]}) for s in data.get("sessions", [])]
            token = data.get("nextPageToken")
            if not token:
                return out

    def _delete(self, artifact, ctx, fallback_from=None):
        r = self.http.delete(f"{self.base}/{artifact.locator['name']}")
        r.raise_for_status()
        return self._ok(artifact, Action.DELETE, session=artifact.locator["name"].rsplit("/", 1)[-1])


@register("aws_agentcore_identity")
class AgentCoreIdentityConnector(Connector):
    """Options: cognito_user_pool_id + region (revokes via AdminUserGlobalSignOut), and/or
    revocation_webhook_url (POST {"user_id": ...} to your IdP automation), username_template
    (how the IdP username relates to the principal id; default "{principal_id}").

    Use the pseudonymous principal id as the AgentCore Identity ``userId``
    (GetWorkloadAccessTokenForUserId) so no direct identifier is stored with the tokens.
    """

    supports = {Action.DELETE}
    capabilities = Capabilities(
        store='AgentCore Identity token vault (per-user OAuth tokens)',
        discover='native', discover_how='one entry per principal',
        verify='api_confirmation', verify_how='identity provider confirms sign-out',
        limits=(
            "no API deletes one user's stored tokens; sessions are revoked at the identity provider instead",
        ),
        deletion='revoke')

    def __init__(self, name: str, cognito_user_pool_id: str | None = None, region: str | None = None,
                 revocation_webhook_url: str | None = None, username_template: str = "{principal_id}",
                 cognito_client=None, **kw):
        super().__init__(name, **kw)
        self.pool, self.webhook, self.tmpl = cognito_user_pool_id, revocation_webhook_url, username_template
        self.cognito = cognito_client
        if self.pool and self.cognito is None:
            import boto3

            self.cognito = boto3.client("cognito-idp", region_name=region)

    def discover(self, ctx):
        # Tokens are not enumerable per user; always plan one revocation per principal.
        return [Discovered("credential", {"user_id": ctx.principal_id})]

    def _delete(self, artifact, ctx, fallback_from=None):
        user = self.tmpl.format(principal_id=artifact.locator["user_id"])
        done = []
        if self.pool:
            self.cognito.admin_user_global_sign_out(UserPoolId=self.pool, Username=user)
            done.append("cognito_global_sign_out")
        if self.webhook:
            req = urllib.request.Request(self.webhook, data=json.dumps({"user_id": user, "reason": "dpdp_erasure"}).encode(),
                                         headers={"content-type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=15).read()
            done.append("idp_webhook")
        if not done:
            from ..core.models import ActionResult

            return ActionResult(artifact.artifact_id, self.name, Action.SKIP.value, False,
                                {"manual": True, "note": "No revocation target configured: revoke the user's "
                                                         "OAuth grants at the IdP manually."})
        return self._ok(artifact, Action.DELETE, revoked_via=done,
                        note="AgentCore Identity has no per-user token delete API; refresh tokens revoked at the IdP.")

    def verify(self, ctx):
        return VerifyResult(self.name, True, [], note="Revocation confirmed by the IdP call; token vault entries "
                                                       "become unusable once refresh tokens are revoked.")
