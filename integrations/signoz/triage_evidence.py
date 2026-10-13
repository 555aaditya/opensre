"""Read-only evidence tools bound to one trusted in-memory SigNoz scope."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from config.constants.triage import TRIAGE_MODEL_ITERATIONS, TRIAGE_TEXT_LIMIT, TRIAGE_TOOL_CALLS
from core.agent_harness.ports import ConfirmFn, ToolEventObserver
from core.tool import AgentTool, AgentToolContext
from integrations.signoz import SigNozConfig
from integrations.signoz.client import SigNozClient


@dataclass
class TriageScope:
    """Trusted authority, fixed time window, and counters for one investigation."""

    query_url: str
    api_key: str
    services: tuple[str, ...]
    start: datetime
    end: datetime
    deadline: float
    max_tool_calls: int = TRIAGE_TOOL_CALLS
    max_model_calls: int = TRIAGE_MODEL_ITERATIONS
    tool_calls: int = 0
    model_calls: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def recent(
        cls,
        *,
        query_url: str,
        api_key: str,
        service: str,
        window_minutes: int,
        anchor: datetime | None = None,
        timeout_seconds: float,
    ) -> TriageScope:
        """Create a scope ending now, or centered around a provider alert time."""
        if not 1 <= window_minutes <= 60:
            raise ValueError("Evidence window must be between 1 and 60 minutes")
        service = service.strip()
        if not service:
            raise ValueError("Service is required")
        now = datetime.now(UTC)
        if anchor is not None:
            if anchor.tzinfo is None or anchor > now + timedelta(minutes=1):
                raise ValueError("Alert timestamp is invalid or lies in the future")
            end = min(now, anchor + timedelta(minutes=window_minutes / 2))
            start = end - timedelta(minutes=window_minutes)
        else:
            end = now
            start = end - timedelta(minutes=window_minutes)
        return cls(
            query_url=query_url.rstrip("/"),
            api_key=api_key,
            services=(service,),
            start=start,
            end=end,
            deadline=time.monotonic() + timeout_seconds,
        )

    def consume_tool(self) -> None:
        """Reserve one tool call before making a provider request."""
        if time.monotonic() >= self.deadline or self.tool_calls >= self.max_tool_calls:
            raise TimeoutError("Evidence budget exhausted")
        self.tool_calls += 1


class TriageEvidenceTools:
    """Expose only scoped SigNoz reads; URLs and time bounds never reach the model."""

    def __init__(self, scope: TriageScope) -> None:
        self.scope = scope
        self._tools = [self._tool(signal) for signal in ("logs", "metrics", "traces")]

    def _tool(self, signal: str) -> AgentTool:
        properties: dict[str, Any] = {
            "service": {"type": "string", "enum": list(self.scope.services)},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10},
        }
        required = ["service"]
        if signal == "logs":
            properties["severity"] = {"type": "string", "enum": ["ERROR", "WARN", "INFO", "FATAL"]}
        if signal == "traces":
            properties["error_only"] = {"type": "boolean"}
        if signal == "metrics":
            properties["metric_name"] = {"type": "string", "maxLength": 200}
            required.append("metric_name")

        def execute(payload: dict[str, Any], _context: AgentToolContext) -> dict[str, Any]:
            return self.query(signal, payload)

        return AgentTool(
            name=f"query_signoz_{signal}",
            description=f"Read scoped SigNoz {signal} in the fixed evidence window.",
            input_schema={
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
            execute=execute,
            source="signoz",
        )

    def query(self, signal: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Enforce scope and budget again at execution, beyond model schema checks."""
        if signal not in {"logs", "metrics", "traces"}:
            raise ValueError("Evidence signal is not permitted")
        allowed = {"service", "limit"} | {
            "logs": {"severity"},
            "metrics": {"metric_name"},
            "traces": {"error_only"},
        }[signal]
        if set(payload) - allowed or payload.get("service") not in self.scope.services:
            raise PermissionError("Query exceeds trusted source scope")
        self.scope.consume_tool()
        remaining = self.scope.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Evidence budget exhausted")
        client = SigNozClient(
            SigNozConfig(
                url=self.scope.query_url,
                api_key=self.scope.api_key,
                timeout_seconds=min(10, max(0.1, remaining)),
            ),
        )
        args = dict(payload)
        args["limit"] = max(1, min(int(args.get("limit", 10)), 10))
        args.update(start_time=self.scope.start.isoformat(), end_time=self.scope.end.isoformat())
        if signal == "logs":
            result = client.query_logs(**args)
        elif signal == "metrics":
            result = client.query_metrics(**args)
        else:
            result = client.query_traces(**args)
        # Keep provider text bounded and never allow a echoed credential into the model.
        encoded = (
            json.dumps(result, default=str).replace(self.scope.api_key, "[redacted]")
            if self.scope.api_key
            else json.dumps(result, default=str)
        )
        if len(encoded) > TRIAGE_TEXT_LIMIT:
            result = {
                "available": result.get("available", False),
                "partial": True,
                "preview": encoded[:TRIAGE_TEXT_LIMIT],
                "truncation_note": "Evidence clipped to the report budget",
            }
        else:
            result = cast(dict[str, Any], json.loads(encoded))
        record = {
            "signal": signal,
            "service": args["service"],
            "start": self.scope.start.isoformat(),
            "end": self.scope.end.isoformat(),
            "query": payload,
            "result": result,
        }
        self.scope.evidence.append(record)
        return result

    def action_tools(
        self,
        *,
        confirm_fn: ConfirmFn | None,
        is_tty: bool | None,
        resolved_integrations: dict[str, Any] | None = None,
        turn_user_message: str = "",
    ) -> list[Any]:
        """Supply a fixed allowlist; no shell, MCP, memory, or remediation tools."""
        _ = (confirm_fn, is_tty, resolved_integrations, turn_user_message)
        return list(self._tools)

    def tool_resources(self) -> dict[str, Any]:
        """No ambient integration or subprocess resources are exposed."""
        return {}

    def observer(self, *, message: str) -> ToolEventObserver:
        """Provider-call accounting is enforced by the host's LLM adapter."""
        _ = message

        def observe(_kind: str, _data: dict[str, Any]) -> None:
            return None

        return observe


__all__ = ["TriageEvidenceTools", "TriageScope"]
