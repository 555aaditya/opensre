"""SigNoz demo bootstrap APIs, confined to a fresh owned organization."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

import httpx


class DemoAdmin:
    """Admin bootstrap is separate from the agent's viewer query credential."""

    def __init__(self, url: str, namespace: str, root: Path) -> None:
        self.url, self.namespace, self.root = url, namespace, root
        self.token = ""
        self.password_path = root / "signoz-admin-password"

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any
    ) -> Any:
        """Never include provider responses or admin tokens in errors or reports."""
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            response = httpx.request(
                method, self.url + path, json=body, headers=headers, timeout=15, **kwargs
            )
            response.raise_for_status()
            if not response.content:
                return None
            payload = response.json()
            return payload.get("data") if isinstance(payload, dict) else None
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            raise RuntimeError(
                f"SigNoz demo API {method} {path} failed ({type(exc).__name__})"
            ) from None

    def login(self) -> None:
        """Register the fresh stack and keep its UI password only in the demo directory."""
        if self.password_path.exists():
            password = self.password_path.read_text().strip()
        else:
            password = "Aa1!" + secrets.token_urlsafe(28)
            self.password_path.write_text(password + "\n")
            self.password_path.chmod(0o600)
        email = f"{self.namespace}@example.invalid"
        context = self.request("GET", "/api/v2/sessions/context", params={"email": email})
        if not context.get("exists"):
            self.request(
                "POST",
                "/api/v1/register",
                {
                    "name": "OpenSRE demo",
                    "email": email,
                    "password": password,
                    "orgName": self.namespace,
                    "orgDisplayName": "Disposable OpenSRE demo",
                },
            )
            context = self.request("GET", "/api/v2/sessions/context", params={"email": email})
        orgs = context.get("orgs", [])
        if len(orgs) != 1:
            raise ValueError("Demo registration did not resolve exactly one owned organization")
        session = self.request(
            "POST",
            "/api/v2/sessions/email_password",
            {"email": email, "password": password, "orgId": orgs[0]["id"]},
        )
        self.token = session["accessToken"]

    def query_key(self) -> str:
        """Grant only signoz-viewer and return an ephemeral service-account key."""
        name = self.namespace + "-viewer"
        accounts = self.request("GET", "/api/v1/service_accounts")
        account = next((a for a in accounts if a["name"] == name), None)
        if account is None:
            account = self.request("POST", "/api/v1/service_accounts", {"name": name})
        identifier = account["id"]
        roles = self.request("GET", "/api/v1/roles")
        viewer = next(r for r in roles if r["name"] == "signoz-viewer")
        assigned = self.request("GET", f"/api/v1/service_accounts/{identifier}/roles")
        if any(r["name"] != "signoz-viewer" for r in assigned):
            raise ValueError("Demo query account has unexpected elevated roles")
        if not assigned:
            self.request(
                "POST",
                "/api/v1/service_account_roles",
                {"serviceAccountId": identifier, "roleId": viewer["id"]},
            )
        created = self.request(
            "POST",
            f"/api/v1/service_accounts/{identifier}/keys",
            {"name": f"triage-{secrets.token_hex(6)}", "expiresAt": 0},
        )
        return str(created["key"])

    def alerts(self, webhook_url: str, username: str, password: str) -> None:
        """Create only this demo's named channel and error-span threshold rule."""
        name = self.namespace + "-webhook"
        if not any(c["name"] == name for c in self.request("GET", "/api/v1/channels")):
            self.request(
                "POST",
                "/api/v1/channels",
                {
                    "name": name,
                    "webhook_configs": [
                        {
                            "url": webhook_url,
                            "send_resolved": True,
                            "http_config": {
                                "basic_auth": {"username": username, "password": password}
                            },
                        }
                    ],
                },
            )
        rule = payment_rule(self.namespace, name)
        rules = self.request("GET", "/api/v1/rules")["rules"]
        if not any(r.get("alert") == rule["alert"] for r in rules):
            self.request("POST", "/api/v2/rules", rule)

    def remove_alerts(self) -> None:
        """Delete this demo's rule before its channel while the listener is still alive."""
        rule_name = self.namespace + "-payment-errors"
        for rule in self.request("GET", "/api/v1/rules")["rules"]:
            if rule.get("alert") == rule_name and rule.get("id"):
                self.request("DELETE", f"/api/v1/rules/{rule['id']}")
        channel_name = self.namespace + "-webhook"
        for channel in self.request("GET", "/api/v1/channels"):
            if channel.get("name") == channel_name and channel.get("id"):
                self.request("DELETE", f"/api/v1/channels/{channel['id']}")


def payment_rule(namespace: str, channel: str) -> dict[str, Any]:
    """Current v2 threshold schema with one trace-count builder query."""
    return {
        "alert": namespace + "-payment-errors",
        "alertType": "TRACES_BASED_ALERT",
        "ruleType": "threshold_rule",
        "version": "v5",
        "schemaVersion": "v2alpha1",
        "disabled": False,
        "source": "",
        "evaluation": {
            "kind": "rolling",
            "spec": {"evalWindow": "1m", "frequency": "5s"},
        },
        "notificationSettings": {
            "groupBy": [],
            "renotify": {"enabled": False, "interval": "30m", "alertStates": []},
            "usePolicy": False,
        },
        "condition": {
            "compositeQuery": {
                "queryType": "builder",
                "panelType": "graph",
                "queries": [
                    {
                        "type": "builder_query",
                        "spec": {
                            "name": "A",
                            "signal": "traces",
                            "source": "",
                            "disabled": False,
                            "aggregations": [{"expression": "count()"}],
                            "filter": {
                                "expression": "service.name = 'payment' AND hasError = true"
                            },
                            "groupBy": [],
                            "having": {"expression": ""},
                            "legend": "",
                        },
                    }
                ],
            },
            "selectedQueryName": "A",
            "thresholds": {
                "kind": "basic",
                "spec": [
                    {
                        "name": "warning",
                        "target": 0,
                        "targetUnit": "",
                        "recoveryTarget": None,
                        "matchType": "at_least_once",
                        "op": "above",
                        "channels": [channel],
                    }
                ],
            },
        },
        "labels": {"severity": "warning"},
        "annotations": {"summary": "Payment error spans observed"},
    }
