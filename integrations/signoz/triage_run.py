"""SigNoz entrypoint for the provider-neutral bounded telemetry investigator."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from config.constants.triage import TRIAGE_SECONDS
from core.agent_harness.telemetry_investigation import run_telemetry_investigation
from core.domain.telemetry_investigation import TelemetryScope, TelemetryTrigger
from integrations.signoz.config import SigNozConfig
from integrations.signoz.notifications import NativeAlert
from integrations.signoz.triage_evidence import SigNozEvidenceBackend


def _trigger_from_alert(alert: NativeAlert) -> TelemetryTrigger:
    """Normalize a native SigNoz alert without granting it query authority."""
    attributes = tuple(
        sorted(
            [(f"label.{key}", value) for key, value in alert.labels.items()]
            + [(f"annotation.{key}", value) for key, value in alert.annotations.items()]
        )
    )
    return TelemetryTrigger(
        provider="signoz",
        trigger_id=alert.fingerprint,
        kind=alert.labels.get("alertname", "alert"),
        status=alert.status,
        observed_at=datetime.fromisoformat(alert.startsAt.replace("Z", "+00:00")),
        title=alert.labels.get("alertname", ""),
        summary=alert.annotations.get("summary", ""),
        attributes=attributes,
    )


def run_signoz_triage(
    config: SigNozConfig,
    *,
    service: str,
    window_minutes: int = 30,
    symptom: str = "",
    alert: NativeAlert | None = None,
    timeout_seconds: float = TRIAGE_SECONDS,
) -> dict[str, Any]:
    """Run one SigNoz investigation through the shared telemetry contract."""
    backend = SigNozEvidenceBackend(config)
    trigger = _trigger_from_alert(alert) if alert is not None else None
    scope = TelemetryScope.recent(
        provider=backend.provider,
        service=service,
        window_minutes=window_minutes,
        anchor=trigger.observed_at if trigger is not None else None,
    )
    return run_telemetry_investigation(
        backend,
        scope=scope,
        symptom=symptom,
        trigger=trigger,
        timeout_seconds=timeout_seconds,
    )


__all__ = ["run_signoz_triage"]
