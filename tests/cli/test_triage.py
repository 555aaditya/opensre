"""Regression coverage for the connected SigNoz triage command."""

from __future__ import annotations

from typing import Any

import pytest
from click.testing import CliRunner

from surfaces.cli.commands import triage as triage_module
from surfaces.cli.commands.triage import triage_command


def test_run_uses_the_connected_signoz_config(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        triage_module,
        "resolve_effective_integrations",
        lambda: {
            "signoz": {
                "source": "local store",
                "config": {"url": "https://signoz.example", "api_key": "query-key"},
            }
        },
    )

    def run(config: Any, **kwargs: Any) -> dict[str, Any]:
        captured.update(config=config, kwargs=kwargs)
        return {"observed": "bounded"}

    monkeypatch.setattr(triage_module, "run_signoz_triage", run)

    result = CliRunner().invoke(triage_command, ["run", "--service", "payment"])

    assert result.exit_code == 0, result.output
    assert captured["config"].url == "https://signoz.example"
    assert captured["config"].api_key == "query-key"
    assert captured["kwargs"]["service"] == "payment"
