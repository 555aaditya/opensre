"""Linear self-contained paymentFailure demo with explicit owned cleanup."""

from __future__ import annotations

import json
import secrets
import shutil
import socket
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

import httpx

from config.constants.paths import opensre_home
from config.constants.triage_demo import DEMO_DISK_BYTES, DEMO_PREFIX, DEMO_RAM_BYTES
from infrastructure.asgi_server import serve_asgi_in_thread
from integrations.signoz import SigNozConfig
from integrations.signoz.triage_demo.artifacts import prepare, run
from integrations.signoz.triage_demo.compose import compose, generate, write_compose
from integrations.signoz.triage_demo.provision import DemoAdmin
from integrations.signoz.triage_demo.webhook import DemoAlertInbox, build_demo_webhook_app
from integrations.signoz.triage_run import run_signoz_triage


def free_port() -> int:
    """Choose a currently available loopback port, rechecked by Docker on bind."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def demo_root(identifier: str) -> Path:
    """Resolve a demo name without accepting a caller-controlled filesystem path."""
    suffix = identifier.removeprefix(DEMO_PREFIX)
    if not identifier.startswith(DEMO_PREFIX) or not suffix.isalnum():
        raise ValueError("Invalid demo ID")
    return opensre_home() / "alerts" / "demos" / identifier


def preflight(root: Path) -> None:
    """Check Docker Compose, daemon memory, and disk without installing software."""
    run(["docker", "compose", "version"], root, timeout=15)
    info = json.loads(run(["docker", "info", "--format", "{{json .}}"], root, timeout=15))
    if int(info.get("MemTotal", 0)) < DEMO_RAM_BYTES:
        gib = DEMO_RAM_BYTES // 1024**3
        raise ValueError(f"Docker needs at least {gib} GiB RAM for this demo")
    if shutil.disk_usage(root).free < DEMO_DISK_BYTES:
        gib = DEMO_DISK_BYTES // 1024**3
        raise ValueError(f"Demo needs at least {gib} GiB free disk space")


def wait_for(
    check: Callable[[], Any], *, seconds: float, message: str, progress: Callable[[str], None]
) -> Any:
    """Bound readiness waits while keeping long-running CLI progress visible."""
    deadline = time.monotonic() + seconds
    next_notice = 0.0
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (httpx.HTTPError, RuntimeError):
            pass
        if time.monotonic() >= next_notice:
            progress(message)
            next_notice = time.monotonic() + 20
        time.sleep(2)
    raise TimeoutError(message + "; timed out")


class PaymentDemo:
    """Provision one owned stack, run one alert investigation, and leave it for inspection."""

    def __init__(
        self, identifier: str | None = None, *, progress: Callable[[str], None] = print
    ) -> None:
        self.id = identifier or DEMO_PREFIX + secrets.token_hex(6)
        self.root = demo_root(self.id)
        self.path = self.root / "manifest.json"
        self.progress = progress
        if identifier is not None and not self.path.exists():
            raise ValueError("Demo not found")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
            if self.data.get("id") != self.id or self.data.get("schema") != 2:
                raise ValueError("Demo manifest identity/schema mismatch")
        else:
            self.data = {
                "id": self.id,
                "schema": 2,
                "signoz_port": free_port(),
                "app_port": free_port(),
                "created_at": time.time(),
            }
            self.save()

    def save(self) -> None:
        """Atomically persist only cleanup metadata, never runtime credentials."""
        self.data["updated_at"] = time.time()
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.data, indent=2))
        temporary.chmod(0o600)
        temporary.replace(self.path)

    @property
    def signoz_url(self) -> str:
        return f"http://127.0.0.1:{self.data['signoz_port']}"

    @property
    def app_url(self) -> str:
        return f"http://127.0.0.1:{self.data['app_port']}"

    def flag(self, enabled: bool) -> None:
        """Toggle only paymentFailure while ensuring raw PII remains disabled."""
        application = Path(self.data["application"])
        if not application.resolve().is_relative_to(self.root.resolve()):
            raise ValueError("Application path is outside this demo")
        path = application / "src" / "flagd" / "demo.flagd.json"
        flags = json.loads(path.read_text())
        flags["flags"]["paymentFailure"]["defaultVariant"] = "100%" if enabled else "off"
        flags["flags"]["emitRawPii"]["defaultVariant"] = "off"
        # Docker Desktop may retain the old inode for bind-mounted files when a
        # host-side atomic rename replaces them, so update this demo-owned file
        # in place and let flagd's file watcher observe the write.
        path.write_text(json.dumps(flags, indent=2))

    def checkout(self) -> bool:
        """Exercise checkout using upstream's synthetic person fixture."""
        user = "opensre-triage-demo-" + secrets.token_hex(4)
        fixture = Path(self.data["application"]) / "src" / "load-generator" / "people.json"
        person = json.loads(fixture.read_text())[0]
        person["email"] = "synthetic-demo@example.invalid"
        with httpx.Client(base_url=self.app_url, timeout=15) as client:
            added = client.post(
                "/api/cart",
                json={"userId": user, "item": {"productId": "0PUK6V6EV0", "quantity": 1}},
            )
            added.raise_for_status()
            response = client.post("/api/checkout", json={**person, "userId": user})
            return response.is_success and bool(response.json().get("orderId"))

    def _prepare_compose(self) -> None:
        binary, application = prepare(self.root)
        paths, pins = generate(
            self.root,
            binary,
            application,
            self.id,
            self.data["signoz_port"],
            self.data["app_port"],
        )
        signoz = json.loads(paths[0].read_text())
        service = signoz["services"][f"{self.id}-signoz-0"]
        service["extra_hosts"] = ["host.docker.internal:host-gateway"]
        service.setdefault("environment", {})["SIGNOZ_RULER_EVAL__DELAY"] = "0s"
        write_compose(paths[0], signoz)
        self.data.update(application=str(application), image_digests=pins)
        self.save()
        self.flag(False)

    def _start_compose(self) -> None:
        for filename in ("signoz.compose.json", "application.compose.json"):
            compose(self.root, self.id, self.root / filename, "up", "-d")
        wait_for(
            lambda: httpx.get(self.signoz_url + "/api/v1/health", timeout=5).is_success,
            seconds=600,
            message="Waiting for SigNoz readiness",
            progress=self.progress,
        )

    def _wait_for_alert(self, inbox: DemoAlertInbox) -> Any:
        deadline = time.monotonic() + 600
        next_notice = 0.0
        while time.monotonic() < deadline:
            with suppress(httpx.HTTPError):
                self.checkout()
            alert = inbox.get(timeout=min(5, max(0.1, deadline - time.monotonic())))
            if alert is not None:
                return alert
            if time.monotonic() >= next_notice:
                self.progress("Waiting for SigNoz to deliver the native payment alert")
                next_notice = time.monotonic() + 20
        raise TimeoutError("Waiting for SigNoz native payment alert; timed out")

    def start(self) -> dict[str, Any]:
        """Run setup, native alert delivery, and one bounded foreground investigation."""
        preflight(self.root)
        self.progress(f"{self.id}: downloading pinned Foundry and OpenTelemetry Demo artifacts")
        self._prepare_compose()
        self.progress(f"{self.id}: starting isolated Docker Compose stacks")
        self._start_compose()

        inbox = DemoAlertInbox()
        username, password = self.id, secrets.token_urlsafe(32)
        app = build_demo_webhook_app(username=username, password=password, inbox=inbox)
        listener = serve_asgi_in_thread(app, host="0.0.0.0", port=0)
        admin = DemoAdmin(self.signoz_url, self.id, self.root)
        alerts_configured = False
        report: dict[str, Any] | None = None
        try:

            def admin_ready() -> bool:
                admin.login()
                return True

            wait_for(
                admin_ready,
                seconds=120,
                message="Waiting for SigNoz registration readiness",
                progress=self.progress,
            )
            query_key = admin.query_key()
            webhook_url = f"http://host.docker.internal:{listener.bound_port}/alerts/signoz"
            admin.alerts(webhook_url, username, password)
            alerts_configured = True
            wait_for(
                self.checkout,
                seconds=300,
                message="Waiting for a healthy synthetic checkout",
                progress=self.progress,
            )
            self.flag(True)
            self.progress(f"{self.id}: paymentFailure enabled; waiting for the real alert")
            alert = self._wait_for_alert(inbox)
            self.progress(f"{self.id}: alert received; running bounded OpenSRE triage")
            report = run_signoz_triage(
                SigNozConfig(url=self.signoz_url, api_key=query_key),
                service="payment",
                window_minutes=30,
                symptom="SigNoz reported payment error spans",
                alert=alert,
            )
        finally:
            try:
                self.flag(False)
                if alerts_configured:
                    admin.remove_alerts()
            finally:
                listener.stop()

        return {
            "demo_id": self.id,
            "signoz_url": self.signoz_url,
            "application_url": self.app_url,
            "admin_email": f"{self.id}@example.invalid",
            "admin_password_file": str(admin.password_path),
            "cleanup_command": f"uv run opensre triage demo cleanup {self.id}",
            "report": report,
        }

    def cleanup(self) -> dict[str, Any]:
        """Remove only ownership-validated Compose resources and then the demo directory."""
        if "application" in self.data:
            self.flag(False)
        for filename in ("application.compose.json", "signoz.compose.json"):
            path = self.root / filename
            if path.exists():
                compose(self.root, self.id, path, "down", "--volumes")
        root = str(self.root)
        shutil.rmtree(self.root)
        return {"demo_id": self.id, "cleaned": True, "removed": root}
