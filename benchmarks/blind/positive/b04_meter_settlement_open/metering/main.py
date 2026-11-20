"""Co-op metering API.

Feeder reads are mounted with ensure_staff. Settlement is a separate
router so window submission is its own mount.
"""

from __future__ import annotations

from fastapi import FastAPI

from metering.routers import feeders, settlement

SERVICE_NAME = "feeder-metering"
API_VERSION = "2026.11"


def build_app() -> FastAPI:
    application = FastAPI(title=SERVICE_NAME, version=API_VERSION)
    application.include_router(feeders.router)
    application.include_router(settlement.router)
    return application


app = build_app()
