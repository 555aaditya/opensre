"""CLI commands for bounded SigNoz investigations and the disposable demo."""

from __future__ import annotations

import json
from typing import Any

import click
from rich.console import Console
from rich.text import Text

from infrastructure.process.runtime_flags import is_json_output
from integrations.catalog import resolve_effective_integrations
from integrations.signoz import (
    build_signoz_config,
    cleanup_payment_demo,
    run_payment_demo,
    run_signoz_triage,
)


@click.group(name="triage", invoke_without_command=True)
@click.pass_context
def triage_command(ctx: click.Context) -> None:
    """Run bounded SigNoz investigations."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


def _emit(value: Any) -> None:
    rendered = json.dumps(value, indent=None if is_json_output() else 2, default=str)
    if is_json_output():
        click.echo(rendered)
    else:
        Console().print(Text(rendered))


@triage_command.command(name="connect")
@click.pass_context
def triage_connect(ctx: click.Context) -> None:
    """Configure or replace the existing SigNoz integration."""
    from surfaces.cli.commands.integrations import setup_integration

    ctx.invoke(setup_integration, service="signoz")


@triage_command.command(name="run")
@click.option("--service", required=True, help="Required exact SigNoz service name.")
@click.option(
    "--window-minutes",
    type=click.IntRange(1, 60),
    default=30,
    show_default=True,
    help="Evidence window ending now.",
)
@click.option("--symptom", default="", help="Optional incident symptom or question.")
def triage_run(service: str, window_minutes: int, symptom: str) -> None:
    """Run one on-demand investigation against the connected SigNoz instance."""
    configured = resolve_effective_integrations().get("signoz") or {}
    try:
        config = build_signoz_config(configured.get("config") or {})
        if not config.is_configured:
            raise click.ClickException(
                "SigNoz is not connected. Run `uv run opensre triage connect` first."
            )
        _emit(
            run_signoz_triage(
                config,
                service=service,
                window_minutes=window_minutes,
                symptom=symptom,
            )
        )
    except (RuntimeError, TimeoutError, ValueError) as exc:
        raise click.ClickException(str(exc)) from None


@triage_command.group(name="demo", invoke_without_command=True)
@click.pass_context
def triage_demo(ctx: click.Context) -> None:
    """Provision SigNoz and run the native payment-alert demo."""
    if ctx.invoked_subcommand is not None:
        return
    from config.llm_settings import has_credentials_for_active_llm_provider

    if not has_credentials_for_active_llm_provider():
        raise click.ClickException(
            "Configure an OpenSRE model before starting the demo; model calls may incur cost."
        )
    try:
        _emit(run_payment_demo(progress=click.echo))
    except (RuntimeError, TimeoutError, ValueError) as exc:
        raise click.ClickException(str(exc)) from None


@triage_demo.command(name="cleanup")
@click.argument("demo_id")
def triage_demo_cleanup(demo_id: str) -> None:
    """Remove only resources owned by the selected disposable demo."""
    try:
        _emit(cleanup_payment_demo(demo_id, progress=click.echo))
    except (RuntimeError, TimeoutError, ValueError) as exc:
        raise click.ClickException(str(exc)) from None
