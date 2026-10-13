"""Temporary authenticated webhook used only while the demo command is running."""

from __future__ import annotations

import base64
import hmac
import json
import queue
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import ValidationError

from infrastructure.request_body_limit import RequestBodyLimitMiddleware
from integrations.signoz.notifications import NativeAlert, parse_notification


class DemoAlertInbox:
    """Keep at most the first real firing alert delivered to this demo run."""

    def __init__(self) -> None:
        self._queue: queue.Queue[NativeAlert] = queue.Queue(maxsize=1)

    def put(self, alert: NativeAlert) -> bool:
        """Accept the first firing alert and ignore tests, resolutions, and duplicates."""
        if alert.status != "firing" or alert.is_delivery_test:
            return False
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            return False
        return True

    def get(self, *, timeout: float) -> NativeAlert | None:
        """Wait for a firing alert without exposing queue mechanics to orchestration."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None


def build_demo_webhook_app(*, username: str, password: str, inbox: DemoAlertInbox) -> FastAPI:
    """Build a body-bounded Basic-auth listener for one foreground demo."""
    app = FastAPI()
    app.add_middleware(RequestBodyLimitMiddleware)

    @app.post("/alerts/signoz")
    async def receive(request: Request) -> JSONResponse:
        body = await request.body()
        scheme, token = get_authorization_scheme_param(request.headers.get("authorization"))
        expected = base64.b64encode(f"{username}:{password}".encode()).decode()
        if scheme.lower() != "basic" or not hmac.compare_digest(token, expected):
            return JSONResponse(
                {"error": "unauthorized"},
                status_code=HTTPStatus.UNAUTHORIZED,
                headers={"WWW-Authenticate": "Basic"},
            )
        try:
            alerts = parse_notification(json.loads(body))
        except (ValueError, ValidationError):
            return JSONResponse(
                {"error": "invalid SigNoz notification"}, status_code=HTTPStatus.BAD_REQUEST
            )
        accepted = sum(inbox.put(alert) for alert in alerts)
        return JSONResponse({"accepted": accepted}, status_code=HTTPStatus.ACCEPTED)

    return app


__all__ = ["DemoAlertInbox", "build_demo_webhook_app"]
