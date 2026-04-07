import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from apscheduler.schedulers.background import BackgroundScheduler
from app.core.auth import hash_password
from app.core.config import settings
from app.core.database import engine, SessionLocal
from app.models.models import Base, User
from app.routers import auth, analysis, trust, community, scanner, notifications
from app.routers import intelligence, media, admin, public_api
from app.core.billing import seed_plans
from app.services.threat_intel import collect_all_intel

logger = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Trustive AI Security Platform",
    version="2.0.0",
    docs_url="/api/docs",
    description="AI-powered conversation hijack detection, threat intelligence, URL/IP/File scanning, and multi-channel security analysis"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_origin_regex=settings.CORS_ALLOW_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(trust.router, prefix="/api/trust", tags=["Trust"])
app.include_router(community.router, prefix="/api/community", tags=["Community"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["Scanner"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["Notifications"])
app.include_router(intelligence.router, prefix="/api/intelligence", tags=["Threat Intelligence"])
app.include_router(media.router, prefix="/api/media", tags=["Media Analysis"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin"])
app.include_router(public_api.router, prefix="/api/public", tags=["Public API"])


def ensure_system_user():
    db = SessionLocal()
    try:
        system_user = db.query(User).filter(User.id == 1).first()
        if system_user:
            return system_user

        system_user = User(
            id=1,
            email="system@trustive.ai",
            username="system",
            hashed_password=hash_password("system-disabled-login"),
            is_active=False,
        )
        db.add(system_user)
        db.commit()
        db.refresh(system_user)
        logger.info("Created system user with id=1")
        return system_user
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to ensure system user exists: %s", exc)
        raise
    finally:
        db.close()


@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        seed_plans(db)
    finally:
        db.close()

    ensure_system_user()

    if not hasattr(app.state, "scheduler"):
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            collect_all_intel,
            "interval",
            hours=6,
            id="collect-threat-intel",
            replace_existing=True,
        )
        scheduler.start()
        app.state.scheduler = scheduler
        logger.info("Threat intelligence scheduler started")


@app.on_event("shutdown")
def shutdown_event():
    scheduler = getattr(app.state, "scheduler", None)
    if scheduler:
        scheduler.shutdown(wait=False)
        logger.info("Threat intelligence scheduler stopped")


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Trustive AI Security Platform API",
        version="2.1.0",
        description=(
            "Trustive AI provides AI-assisted threat analysis, geographic threat intelligence, "
            "community sharing, media deepfake detection, and administration endpoints."
        ),
        routes=app.routes,
    )
    openapi_schema["info"]["contact"] = {
        "name": "Trustive AI",
        "url": "https://trustive.ai",
        "email": "support@trustive.ai",
    }
    openapi_schema["info"]["x-feature-highlights"] = [
        "Threat analysis with transformer-backed classification",
        "Geographic threat map with IP geolocation markers",
        "Media analysis for OCR, object insights, and deepfake heuristics",
        "Community feed sharing and admin moderation",
    ]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

@app.get("/")
async def root():
    return {
        "success": True,
        "message": "Trustive AI Security Platform",
        "version": "2.0.0",
        "features": [
            "AI Threat Detection",
            "Conversation Hijack Detection",
            "Homograph Domain Detection",
            "Writing Style Analysis",
            "Community Threat Intelligence",
            "URL Scanner",
            "IP Reputation Check",
            "File Scanner",
            "API Key Management"
        ]
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "features": [
            "hijack_detection_active",
            "multi_channel_active",
            "url_scanner_active",
            "ip_reputation_active",
            "file_scanner_active",
            "api_keys_active"
        ]
    }
