from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import engine
from app.models.models import Base
from app.routers import auth, analysis, trust, community, scanner, notifications
from app.core.billing import seed_plans

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Trustive AI Security Platform",
    version="2.0.0",
    docs_url="/api/docs",
    description="AI-powered conversation hijack detection, threat intelligence, URL/IP/File scanning, and multi-channel security analysis"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://truestiv-frontend.vercel.app",
        "http://localhost:5000",
        "http://localhost:5173",
        "https://truestiv-frontend-5i26o56kp-true-t.vercel.app"
    ],
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
