"""Willow Athletic dues service."""

from __future__ import annotations

from fastapi import FastAPI

from club.dues import router as dues_router

SERVICE_NAME = "willow-dues"
API_VERSION = "2026.11"


def build_app() -> FastAPI:
    application = FastAPI(title=SERVICE_NAME, version=API_VERSION)
    application.include_router(dues_router)
    return application


app = build_app()
