"""FastAPI 应用：webhook 接收端点 + 管理 API + 监控页面。"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from .core import WebhookService
from .demo import run_scenario
from .store import Store

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    db_path: str | None = None,
    initial_secret: str | None = None,
    tolerance_seconds: int | None = None,
    rotation_grace_seconds: int | None = None,
) -> FastAPI:
    service = WebhookService(
        Store(db_path or os.environ.get("WEBHOOK_DB", "webhook.db")),
        tolerance_seconds=tolerance_seconds
            if tolerance_seconds is not None
            else int(os.environ.get("WEBHOOK_TOLERANCE_SECONDS", "300")),
        rotation_grace_seconds=rotation_grace_seconds
            if rotation_grace_seconds is not None
            else int(os.environ.get("WEBHOOK_ROTATION_GRACE_SECONDS", "3600")),
        initial_secret=initial_secret
            or os.environ.get("WEBHOOK_INITIAL_SECRET", "whsec_dev_initial"),
    )

    app = FastAPI(title="Webhook 接收服务", version="0.1.0")
    app.state.service = service

    # ---------- 接收端点 ----------

    @app.post("/webhook")
    async def webhook(request: Request) -> JSONResponse:
        body = await request.body()
        result = service.ingest(
            body,
            request.headers.get("x-webhook-signature"),
            request.headers.get("x-webhook-delivery"),
        )
        status = result.pop("http_status")
        return JSONResponse(result, status_code=status)

    # ---------- 状态与页面 ----------

    @app.get("/api/state")
    async def get_state() -> dict:
        return service.state()

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    # ---------- 管理操作 ----------

    @app.post("/admin/keys/rotate")
    async def rotate_key() -> dict:
        return service.rotate_key()

    @app.post("/admin/keys/expire-previous")
    async def expire_previous() -> dict:
        return service.expire_previous_key()

    @app.post("/admin/events/{event_id}/{version}/retry")
    async def retry_event(event_id: str, version: int, request: Request) -> dict:
        patch = None
        if request.headers.get("content-type", "").startswith("application/json"):
            body = await request.json()
            patch = body.get("patch") if isinstance(body, dict) else None
        return service.retry_event(event_id, version, patch)

    @app.post("/admin/demo/{scenario}")
    async def demo(scenario: str) -> dict:
        return run_scenario(service, scenario)

    @app.post("/admin/reset")
    async def reset() -> dict:
        service.reset()
        return {"ok": True}

    return app


app = create_app()
