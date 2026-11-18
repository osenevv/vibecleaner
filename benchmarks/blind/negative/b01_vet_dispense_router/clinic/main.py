"""North Barn chart API. Credentials are allowed only for the clinic origin."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from clinic.charts import router as chart_router

ALLOWED_ORIGINS = ["https://charts.northbarn.vet"]

app = FastAPI(title="North Barn charts")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)
app.include_router(chart_router)
