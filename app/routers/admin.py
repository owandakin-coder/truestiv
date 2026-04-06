from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.models import CommunityThreat, MediaAnalysis, Notification, User, UserAPIKey

router = APIRouter()


def _ensure_admin(current_user: User):
    allowed_emails = {
        email.strip().lower()
        for email in getattr(settings, "ADMIN_EMAILS", "system@trustive.ai").split(",")
        if email.strip()
    }
    if current_user.id == 1 or current_user.email.lower() in allowed_emails:
        return
    raise HTTPException(status_code=403, detail="Admin access required")


@router.get("/overview")
def admin_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    return {
        "success": True,
        "metrics": {
            "users": db.query(User).count(),
            "community_threats": db.query(CommunityThreat).count(),
            "unmoderated_threats": db.query(CommunityThreat).filter(CommunityThreat.is_moderated == False).count(),
            "media_analyses": db.query(MediaAnalysis).count(),
            "stored_api_keys": db.query(UserAPIKey).count(),
            "notifications": db.query(Notification).count(),
        },
    }


@router.get("/users")
def admin_users(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    users = db.query(User).order_by(User.created_at.desc()).limit(limit).all()
    return {
        "success": True,
        "items": [
            {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat() if user.created_at else None,
            }
            for user in users
        ],
    }


@router.get("/threats")
def admin_threats(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    threats = db.query(CommunityThreat).order_by(CommunityThreat.published_at.desc()).limit(limit).all()
    return {
        "success": True,
        "items": [
            {
                "id": threat.id,
                "indicator": threat.indicator,
                "threat_type": threat.threat_type,
                "risk_score": threat.risk_score,
                "threat_level": threat.threat_level,
                "is_moderated": threat.is_moderated,
                "title": threat.title,
                "description": threat.description,
                "published_at": threat.published_at.isoformat() if threat.published_at else None,
            }
            for threat in threats
        ],
    }


@router.post("/threats/{threat_id}/moderate")
def moderate_threat(
    threat_id: int,
    approved: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    threat = db.query(CommunityThreat).filter(CommunityThreat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat.is_moderated = approved
    db.commit()
    return {"success": True, "id": threat.id, "is_moderated": threat.is_moderated}


@router.get("/api-keys")
def admin_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    items = db.query(UserAPIKey).order_by(UserAPIKey.created_at.desc()).limit(100).all()
    return {
        "success": True,
        "items": [
            {
                "id": item.id,
                "user_id": item.user_id,
                "provider": item.provider,
                "label": item.label,
                "masked_value": item.masked_value,
                "is_active": item.is_active,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in items
        ],
    }
