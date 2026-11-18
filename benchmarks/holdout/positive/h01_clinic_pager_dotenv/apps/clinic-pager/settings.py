import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ClinicPagerSettings:
    app_env: str
    database_url: str
    supabase_url: str
    timezone: str
    reminder_lead_minutes: int
    openai_api_key: str
    supabase_service_role_key: str
    pager_secret: str


def _required(name: str) -> str:
    value = os.environ[name]
    if not value.strip():
        raise RuntimeError(f"environment variable {name} is empty")
    return value


def load_settings() -> ClinicPagerSettings:
    return ClinicPagerSettings(
        app_env=_required("APP_ENV"),
        database_url=_required("DATABASE_URL"),
        supabase_url=_required("SUPABASE_URL"),
        timezone=_required("TIMEZONE"),
        reminder_lead_minutes=int(_required("REMINDER_LEAD_MINUTES")),
        openai_api_key=_required("OPENAI_API_KEY"),
        supabase_service_role_key=_required("SUPABASE_SERVICE_ROLE_KEY"),
        pager_secret=_required("CLINIC_PAGER_SECRET"),
    )


def redacted(settings: ClinicPagerSettings) -> dict[str, str]:
    return {
        "app_env": settings.app_env,
        "timezone": settings.timezone,
        "supabase_url": settings.supabase_url,
        "reminder_lead_minutes": str(settings.reminder_lead_minutes),
        "openai_api_key": "set",
        "supabase_service_role_key": "set",
        "pager_secret": "set",
    }
