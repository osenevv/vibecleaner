"""Northwind hire-desk API."""

from __future__ import annotations

from fastapi import FastAPI

from onboarding.equipment import router as equipment_router

SERVICE_NAME = "hire-desk"
API_VERSION = "2026.11"


def build_app() -> FastAPI:
    application = FastAPI(title=SERVICE_NAME, version=API_VERSION)
    application.include_router(equipment_router)
    return application


app = build_app()
