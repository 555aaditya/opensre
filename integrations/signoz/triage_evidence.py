"""SigNoz adapter for provider-neutral bounded telemetry evidence queries."""

from __future__ import annotations

from typing import Any

from core.domain.telemetry_investigation import (
    EvidenceCapability,
    TelemetryEvidenceQuery,
    TelemetryScope,
)
from integrations.signoz.client import SigNozClient
from integrations.signoz.config import SigNozConfig


class SigNozEvidenceBackend:
    """Execute trusted-scope log, metric, and trace reads against SigNoz."""

    provider = "signoz"
    capabilities = frozenset(EvidenceCapability)

    def __init__(self, config: SigNozConfig) -> None:
        if not config.is_configured:
            raise ValueError("Connect SigNoz before running triage")
        self._config = config

    @property
    def redactions(self) -> tuple[str, ...]:
        """Return secrets that must be removed from model-visible provider output."""
        return (self._config.api_key,)

    def query(
        self,
        query: TelemetryEvidenceQuery,
        *,
        scope: TelemetryScope,
    ) -> dict[str, Any]:
        """Translate one provider-neutral query to the fixed SigNoz API surface."""
        if scope.provider != self.provider or query.capability not in self.capabilities:
            raise PermissionError("Query exceeds the SigNoz evidence contract")
        if query.service not in scope.services or not 1 <= query.limit <= 10:
            raise PermissionError("Query exceeds trusted service scope")
        parameters = query.parameters_by_name
        allowed = {
            EvidenceCapability.LOGS: {"severity"},
            EvidenceCapability.METRICS: {"metric_name"},
            EvidenceCapability.TRACES: {"error_only"},
        }[query.capability]
        if set(parameters) - allowed:
            raise PermissionError("Query parameters exceed the SigNoz evidence contract")
        client = SigNozClient(
            SigNozConfig(
                url=self._config.url,
                api_key=self._config.api_key,
                timeout_seconds=query.timeout_seconds,
            )
        )
        args = {
            **parameters,
            "service": query.service,
            "limit": query.limit,
            "start_time": scope.start.isoformat(),
            "end_time": scope.end.isoformat(),
        }
        if query.capability is EvidenceCapability.LOGS:
            return client.query_logs(**args)
        if query.capability is EvidenceCapability.METRICS:
            return client.query_metrics(**args)
        return client.query_traces(**args)


__all__ = ["SigNozEvidenceBackend"]
