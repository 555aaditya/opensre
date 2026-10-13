"""Bounded parsing for native SigNoz Alertmanager v4 notifications."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from config.constants.triage import TRIAGE_TEXT_LIMIT


class NativeAlert(BaseModel):
    """One firing or resolved alert from a grouped notification."""

    status: Literal["firing", "resolved"]
    labels: dict[str, str]
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str
    fingerprint: str = Field(min_length=1, max_length=256)

    @field_validator("startsAt")
    @classmethod
    def validate_start(cls, value: str) -> str:
        """Require an absolute timestamp without changing provider precision."""
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.year < 1970:
            raise ValueError("startsAt must be a timezone-aware timestamp")
        return value

    @field_validator("labels", "annotations")
    @classmethod
    def bound_text(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject notification text that exceeds the investigation prompt budget."""
        if len(value) > 100 or sum(len(key) + len(text) for key, text in value.items()) > (
            TRIAGE_TEXT_LIMIT
        ):
            raise ValueError("Alert text exceeds its bounded contract")
        return value

    @property
    def is_delivery_test(self) -> bool:
        """Return whether SigNoz generated its documented channel test alert."""
        return (
            self.labels.get("alertname", "").startswith("Test Alert (")
            and self.annotations.get("description") == "Test alert fired from SigNoz"
            and self.annotations.get("summary") == "Test alert fired from SigNoz"
        )


class NativeNotification(BaseModel):
    """A bounded native notification containing independently-scoped alerts."""

    version: Literal["4"] = "4"
    alerts: list[NativeAlert] = Field(min_length=1, max_length=1000)


def parse_notification(payload: Any) -> list[NativeAlert]:
    """Validate a native payload without trusting receiver or external URL fields."""
    return NativeNotification.model_validate(payload).alerts


__all__ = ["NativeAlert", "parse_notification"]
