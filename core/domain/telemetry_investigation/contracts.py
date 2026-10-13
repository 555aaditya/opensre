"""Provider-neutral authority and evidence contracts for telemetry investigations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol


class EvidenceCapability(StrEnum):
    """Telemetry signal a provider can query within a trusted scope."""

    LOGS = "logs"
    METRICS = "metrics"
    TRACES = "traces"


@dataclass(frozen=True, slots=True)
class TelemetryTrigger:
    """Bounded, untrusted event that asks OpenSRE to investigate telemetry."""

    provider: str
    trigger_id: str
    kind: str
    status: str
    observed_at: datetime | None = None
    title: str = ""
    summary: str = ""
    attributes: tuple[tuple[str, str], ...] = ()

    def as_context(self) -> dict[str, Any]:
        """Return the model-visible trigger fields without granting query authority."""
        return {
            "provider": self.provider,
            "trigger_id": self.trigger_id,
            "kind": self.kind,
            "status": self.status,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "title": self.title,
            "summary": self.summary,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class TelemetryScope:
    """Trusted provider, service allowlist, and immutable evidence window."""

    provider: str
    services: tuple[str, ...]
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        """Reject malformed authority before any provider request is possible."""
        if (
            not self.provider.strip()
            or not self.services
            or any(not service.strip() for service in self.services)
        ):
            raise ValueError("Telemetry provider and services are required")
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("Telemetry scope timestamps must be timezone-aware")
        if self.end <= self.start or self.end - self.start > timedelta(minutes=60):
            raise ValueError("Telemetry scope must be a positive window of at most 60 minutes")

    @classmethod
    def recent(
        cls,
        *,
        provider: str,
        service: str,
        window_minutes: int,
        anchor: datetime | None = None,
    ) -> TelemetryScope:
        """Create a bounded window ending now or centered around a trigger time."""
        if not 1 <= window_minutes <= 60:
            raise ValueError("Evidence window must be between 1 and 60 minutes")
        provider = provider.strip()
        service = service.strip()
        if not provider:
            raise ValueError("Telemetry provider is required")
        if not service:
            raise ValueError("Service is required")
        now = datetime.now(UTC)
        if anchor is not None:
            if anchor.tzinfo is None or anchor > now + timedelta(minutes=1):
                raise ValueError("Trigger timestamp is invalid or lies in the future")
            end = min(now, anchor + timedelta(minutes=window_minutes / 2))
        else:
            end = now
        return cls(
            provider=provider,
            services=(service,),
            start=end - timedelta(minutes=window_minutes),
            end=end,
        )


@dataclass(frozen=True, slots=True)
class TelemetryEvidenceQuery:
    """One provider-neutral telemetry request already constrained by a trusted scope."""

    capability: EvidenceCapability
    service: str
    limit: int
    timeout_seconds: float
    parameters: tuple[tuple[str, Any], ...] = ()

    @property
    def parameters_by_name(self) -> dict[str, Any]:
        """Return optional signal controls as a lookup map."""
        return dict(self.parameters)


class TelemetryEvidenceBackend(Protocol):
    """Provider adapter that executes bounded telemetry reads."""

    provider: str
    capabilities: frozenset[EvidenceCapability]

    @property
    def redactions(self) -> tuple[str, ...]:
        """Return values that must be removed from model-visible output."""

    def query(
        self,
        query: TelemetryEvidenceQuery,
        *,
        scope: TelemetryScope,
    ) -> dict[str, Any]:
        """Execute one validated query without widening ``scope``."""


__all__ = [
    "EvidenceCapability",
    "TelemetryEvidenceBackend",
    "TelemetryEvidenceQuery",
    "TelemetryScope",
    "TelemetryTrigger",
]
