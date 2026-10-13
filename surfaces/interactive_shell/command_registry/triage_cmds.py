"""Interactive-shell parity for the bounded SigNoz triage CLI."""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console

from config.cli_command_choices import CLI_COMMAND_CHOICES
from core.agent_harness.spi.session_state import session_terminal
from surfaces.interactive_shell.session import Session
from surfaces.shared.terminal.components.choice_menu import repl_tty_interactive
from surfaces.shared.terminal.components.subcommand_menu import repl_choose_subcommand


def cmd_triage(
    session: Session, console: Console, args: list[str], *, run_cli: Callable[..., bool]
) -> bool:
    """Run the same foreground connect, investigation, and demo flows from the shell."""
    terminal = session_terminal(session)
    if not args:
        if terminal is not None and repl_tty_interactive():
            choice = repl_choose_subcommand(
                parent="/triage", options=CLI_COMMAND_CHOICES[("/triage",)]
            )
            if choice is None:
                return True
            args = [choice]
        else:
            args = ["--help"]
    if terminal is None and args[0] in {"connect", "demo"}:
        command = " ".join(["uv run opensre triage", *args])
        console.print(f"Run this foreground command on the OpenSRE host:\n  {command}")
        return True
    return run_cli(
        console,
        ["triage", *args],
        session=session,
        capture_output=args[0] not in {"connect", "demo"},
    )
