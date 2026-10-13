"""Lightweight public entrypoints for foreground SigNoz triage flows."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from integrations.signoz.config import SigNozConfig

if TYPE_CHECKING:
    from integrations.signoz.notifications import NativeAlert


def run_signoz_triage(
    config: SigNozConfig,
    *,
    service: str,
    window_minutes: int = 30,
    symptom: str = "",
    alert: NativeAlert | None = None,
    timeout_seconds: float = 180,
) -> dict[str, Any]:
    """Run one bounded foreground investigation without loading its harness at import time."""
    from integrations.signoz.triage_run import run_signoz_triage as run

    return run(
        config,
        service=service,
        window_minutes=window_minutes,
        symptom=symptom,
        alert=alert,
        timeout_seconds=timeout_seconds,
    )


def run_payment_demo(*, progress: Callable[[str], None]) -> dict[str, Any]:
    """Provision and run one disposable native-alert demo, cleaning up failures."""
    from integrations.signoz.triage_demo.runtime import PaymentDemo

    demo = PaymentDemo(progress=progress)
    progress(
        f"Demo {demo.id}. OpenSRE will provision pinned Foundry and OpenTelemetry Demo assets."
    )
    try:
        return demo.start()
    except Exception as exc:
        cleanup_error = ""
        try:
            demo.cleanup()
        except Exception as cleanup_exc:
            cleanup_error = (
                f" Cleanup was incomplete ({type(cleanup_exc).__name__}); run "
                f"`uv run opensre triage demo cleanup {demo.id}`."
            )
        safe = (
            str(exc)
            if isinstance(exc, (RuntimeError, TimeoutError, ValueError))
            else type(exc).__name__
        )
        raise RuntimeError(safe + cleanup_error) from None


def cleanup_payment_demo(identifier: str, *, progress: Callable[[str], None]) -> dict[str, Any]:
    """Remove only resources owned by one disposable demo identifier."""
    from integrations.signoz.triage_demo.runtime import PaymentDemo

    return PaymentDemo(identifier, progress=progress).cleanup()


__all__ = ["cleanup_payment_demo", "run_payment_demo", "run_signoz_triage"]
