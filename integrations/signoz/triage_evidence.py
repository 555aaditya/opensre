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


def _validated_parameters(query: TelemetryEvidenceQuery) -> dict[str, Any]:
    """Validate direct-call values that do not pass through the agent tool schema."""
    parameters = query.parameters_by_name
    if len(parameters) != len(query.parameters):
        raise PermissionError("Duplicate SigNoz query parameters are not permitted")
    if query.capability is EvidenceCapability.LOGS:
        severity = parameters.get("severity")
        if set(parameters) - {"severity"} or (
            "severity" in parameters and severity not in {"ERROR", "WARN", "INFO", "FATAL"}
        ):
            raise PermissionError("Invalid SigNoz log parameters")
    elif query.capability is EvidenceCapability.METRICS:
        metric_name = parameters.get("metric_name")
        if (
            set(parameters) != {"metric_name"}
            or type(metric_name) is not str
            or not metric_name.strip()
            or len(metric_name) > 200
        ):
            raise PermissionError("Invalid SigNoz metric parameters")
    else:
        error_only = parameters.get("error_only")
        if set(parameters) - {"error_only"} or (
            "error_only" in parameters and type(error_only) is not bool
        ):
            raise PermissionError("Invalid SigNoz trace parameters")
    return parameters


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
        if (
            query.service not in scope.services
            or type(query.limit) is not int
            or not 1 <= query.limit <= 10
            or type(query.timeout_seconds) not in {int, float}
            or not 0 < query.timeout_seconds <= 10
        ):
            raise PermissionError("Query exceeds trusted service scope")
        parameters = _validated_parameters(query)
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
