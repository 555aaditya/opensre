"""The verified analytics connection as tools receive it from integration sources."""

from __future__ import annotations

from typing import Any

from integrations.opensre_analytics.config import (
    SERVICE,
    OpenSREAnalyticsConfig,
    build_opensre_analytics_config,
)

#: Connection values injected from the verified integration and hidden from the model,
#: so a guessed URL or token can never override the configured one.
INJECTED_PARAMS = ("analytics_url", "analytics_token")


def analytics_available(sources: dict[str, Any]) -> bool:
    entry = sources.get(SERVICE)
    return isinstance(entry, dict) and bool(entry.get("connection_verified"))


def analytics_params(sources: dict[str, Any]) -> dict[str, Any]:
    entry = sources.get(SERVICE)
    if not isinstance(entry, dict):
        return {}
    return {
        "analytics_url": str(entry.get("url") or ""),
        "analytics_token": str(entry.get("auth_token") or ""),
    }


def config_from_params(
    analytics_url: str | None, analytics_token: str | None
) -> OpenSREAnalyticsConfig:
    return build_opensre_analytics_config(
        {"url": analytics_url or "", "auth_token": analytics_token or ""}
    )
