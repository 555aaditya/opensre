"""High-signal contracts for the bounded SigNoz demo."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Any

import httpx
import pytest

from integrations.signoz.triage_demo.compose import compose, isolate, owned
from integrations.signoz.triage_demo.webhook import DemoAlertInbox, build_demo_webhook_app
from integrations.signoz.triage_evidence import TriageEvidenceTools, TriageScope


def _alert(*, status: str = "firing", test: bool = False) -> dict[str, Any]:
    labels = {"alertname": "Test Alert (demo)" if test else "payment-errors"}
    annotations = (
        {
            "description": "Test alert fired from SigNoz",
            "summary": "Test alert fired from SigNoz",
        }
        if test
        else {"summary": "Payment errors observed"}
    )
    return {
        "status": status,
        "labels": labels,
        "annotations": annotations,
        "startsAt": "2026-10-13T10:00:00Z",
        "fingerprint": f"{status}-{test}",
    }


def test_demo_webhook_requires_auth_and_accepts_only_one_real_firing_alert() -> None:
    inbox = DemoAlertInbox()
    app = build_demo_webhook_app(username="demo", password="secret", inbox=inbox)
    payload = {"version": "4", "alerts": [_alert(test=True), _alert(status="resolved"), _alert()]}

    async def post() -> tuple[httpx.Response, httpx.Response]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            unauthorized = await client.post("/alerts/signoz", json=payload)
            accepted = await client.post("/alerts/signoz", json=payload, auth=("demo", "secret"))
            return unauthorized, accepted

    unauthorized, response = asyncio.run(post())

    assert unauthorized.status_code == HTTPStatus.UNAUTHORIZED
    assert response.status_code == HTTPStatus.ACCEPTED
    assert response.json() == {"accepted": 1}
    accepted = inbox.get(timeout=0.01)
    assert accepted is not None and accepted.labels["alertname"] == "payment-errors"


def test_evidence_scope_rejects_untrusted_authority_and_stops_at_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict[str, Any]] = []

    def post(url: str, **kwargs: Any) -> httpx.Response:
        assert url == "https://signoz.example/api/v5/query_range"
        requests.append(kwargs["json"])
        return httpx.Response(
            HTTPStatus.OK,
            request=httpx.Request("POST", url),
            json={"data": {"data": {"results": []}}},
        )

    monkeypatch.setattr("integrations.signoz.client.httpx.post", post)
    now = datetime.now(UTC)
    scope = TriageScope(
        query_url="https://signoz.example",
        api_key="never-in-model",
        services=("payment",),
        start=now - timedelta(minutes=30),
        end=now,
        deadline=time.monotonic() + 30,
        max_tool_calls=1,
    )
    tools = TriageEvidenceTools(scope)
    for payload in (
        {"service": "secret"},
        {"service": "payment", "url": "https://evil.example"},
        {"service": "payment", "start_time": "now"},
    ):
        with pytest.raises(PermissionError):
            tools.query("traces", payload)

    tools.query("traces", {"service": "payment", "error_only": True, "limit": 500})
    with pytest.raises(TimeoutError, match="budget"):
        tools.query("traces", {"service": "payment"})

    spec = requests[0]["compositeQuery"]["queries"][0]["spec"]
    assert spec["limit"] == 10
    assert "service.name = 'payment'" in spec["filter"]["expression"]
    assert "hasError = true" in spec["filter"]["expression"]
    assert "never-in-model" not in json.dumps(scope.evidence)


def test_owned_compose_rejects_foreign_cleanup(tmp_path: Path) -> None:
    namespace = "opensre-triage-abc"
    spec = {
        "services": {
            "ingester": {"image": "signoz/collector:1"},
            namespace + "-signoz-0": {"image": "signoz/signoz:1"},
        },
        "volumes": {"data": {}},
    }
    isolated = isolate(spec, namespace, web_service=namespace + "-signoz-0", web_port=12345)
    isolated["volumes"]["data"]["name"] = "production-database"
    path = tmp_path / "signoz.compose.json"
    path.write_text(json.dumps(isolated))

    with pytest.raises(ValueError, match="outside"):
        owned(isolated, namespace)
    with pytest.raises(ValueError, match="outside"):
        compose(tmp_path, namespace, path, "down", "--volumes")
