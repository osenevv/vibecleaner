"""Harbor & Pine matter review service."""

from __future__ import annotations

from fastapi import FastAPI

from counsel.review import router as review_router

SERVICE_NAME = "matter-review"
API_VERSION = "2026.11"


def build_app() -> FastAPI:
    application = FastAPI(title=SERVICE_NAME, version=API_VERSION)
    application.include_router(review_router)
    return application


app = build_app()
