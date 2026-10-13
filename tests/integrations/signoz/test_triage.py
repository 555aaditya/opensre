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

from core.agent_harness.telemetry_investigation import (
    InvestigationBudget,
    TelemetryEvidenceTools,
)
from core.agent_harness.telemetry_investigation import runtime as triage_run_module
from core.domain.telemetry_investigation import (
    EvidenceCapability,
    TelemetryEvidenceQuery,
    TelemetryScope,
)
from core.llm.types import AgentLLMResponse
from integrations.signoz import SigNozConfig
from integrations.signoz.triage_demo import runtime as demo_runtime
from integrations.signoz.triage_demo.compose import compose, isolate, owned
from integrations.signoz.triage_demo.runtime import PaymentDemo
from integrations.signoz.triage_demo.webhook import DemoAlertInbox, build_demo_webhook_app
from integrations.signoz.triage_evidence import SigNozEvidenceBackend
from integrations.signoz.triage_run import run_signoz_triage


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
    config = SigNozConfig(url="https://signoz.example", api_key="never-in-model")
    scope = TelemetryScope(
        provider="signoz",
        services=("payment",),
        start=now - timedelta(minutes=30),
        end=now,
    )
    budget = InvestigationBudget(
        deadline=time.monotonic() + 30,
        max_tool_calls=1,
    )
    backend = SigNozEvidenceBackend(config)
    tools = TelemetryEvidenceTools(backend, scope, budget)
    for payload in (
        {"service": "secret"},
        {"service": "payment", "url": "https://evil.example"},
        {"service": "payment", "start_time": "now"},
    ):
        with pytest.raises(PermissionError):
            tools.query("traces", payload)
    with pytest.raises(PermissionError):
        backend.query(
            TelemetryEvidenceQuery(
                capability=EvidenceCapability.TRACES,
                service="payment",
                limit=10,
                timeout_seconds=1,
                parameters=(("start_time", "1970-01-01T00:00:00Z"),),
            ),
            scope=scope,
        )

    tools.query("traces", {"service": "payment", "error_only": True, "limit": 500})
    with pytest.raises(TimeoutError, match="budget"):
        tools.query("traces", {"service": "payment"})

    spec = requests[0]["compositeQuery"]["queries"][0]["spec"]
    assert spec["limit"] == 10
    assert "service.name = 'payment'" in spec["filter"]["expression"]
    assert "hasError = true" in spec["filter"]["expression"]
    assert "never-in-model" not in json.dumps(budget.evidence)


def test_evidence_tools_expose_only_backend_capabilities() -> None:
    class TraceOnlyBackend:
        provider = "trace-only"
        capabilities = frozenset({EvidenceCapability.TRACES})
        redactions: tuple[str, ...] = ()

        def query(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {"available": True}

    now = datetime.now(UTC)
    scope = TelemetryScope(
        provider="trace-only",
        services=("payment",),
        start=now - timedelta(minutes=5),
        end=now,
    )
    tools = TelemetryEvidenceTools(TraceOnlyBackend(), scope, InvestigationBudget.with_timeout(5))

    assert [tool.name for tool in tools.action_tools(confirm_fn=None, is_tty=False)] == [
        "query_telemetry_traces"
    ]


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


def test_cleanup_survives_an_interrupted_flag_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "opensre-triage-abc"
    application = root / "application"
    flag = application / "src" / "flagd" / "demo.flagd.json"
    flag.parent.mkdir(parents=True)
    flag.write_text("{")
    for filename in ("application.compose.json", "signoz.compose.json"):
        (root / filename).write_text("{}")
    calls: list[str] = []
    monkeypatch.setattr(
        demo_runtime,
        "compose",
        lambda _root, _identifier, path, *_args: calls.append(path.name),
    )
    demo = PaymentDemo.__new__(PaymentDemo)
    demo.id = root.name
    demo.root = root
    demo.data = {"application": str(application)}
    demo.progress = lambda _message: None

    result = demo.cleanup()

    assert result["cleaned"] is True
    assert calls == ["application.compose.json", "signoz.compose.json"]
    assert not root.exists()


class _ImmediateLLM:
    model_id = "fake"

    def tool_schemas(self, _tools: Any) -> list[dict[str, Any]]:
        return []

    def invoke(self, *_args: Any, **_kwargs: Any) -> AgentLLMResponse:
        return AgentLLMResponse(content="done")


def _budget(*, seconds: float, model_calls: int) -> InvestigationBudget:
    return InvestigationBudget(
        deadline=time.monotonic() + seconds,
        max_model_calls=model_calls,
    )


def test_model_budget_counts_every_provider_invocation() -> None:
    assert hasattr(triage_run_module, "BoundedAgentLLM")
    bounded = triage_run_module.BoundedAgentLLM(_ImmediateLLM(), _budget(seconds=10, model_calls=2))

    bounded.invoke([])
    bounded.invoke([])

    with pytest.raises(TimeoutError, match="model budget"):
        bounded.invoke([])


def test_provider_invocation_cannot_outlive_the_triage_deadline() -> None:
    class BlockingLLM(_ImmediateLLM):
        def invoke(self, *_args: Any, **_kwargs: Any) -> AgentLLMResponse:
            time.sleep(1)
            return AgentLLMResponse(content="late")

    assert hasattr(triage_run_module, "BoundedAgentLLM")
    bounded = triage_run_module.BoundedAgentLLM(BlockingLLM(), _budget(seconds=0.02, model_calls=1))
    started = time.monotonic()

    with pytest.raises(TimeoutError, match="deadline"):
        bounded.invoke([])

    assert time.monotonic() - started < 0.5


def test_restricted_triage_rejects_cli_backed_models(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(triage_run_module, "agent_llm_is_cli_backed", lambda: True, raising=False)

    with pytest.raises(ValueError, match="API-backed model"):
        run_signoz_triage(
            SigNozConfig(url="https://signoz.example", api_key="query-key"),
            service="payment",
        )
