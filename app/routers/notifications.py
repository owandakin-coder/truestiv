from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, CommunityThreat, EmailAnalysis

router = APIRouter()

@router.get("/api/notifications")
def get_notifications(db: Session = Depends(get_db), current_user: User = Depends(get_current_user), limit: int = 20):
    # שלב איומים אחרונים מהקהילה
    threats = db.query(CommunityThreat).filter(
        CommunityThreat.published_by != current_user.id
    ).order_by(CommunityThreat.published_at.desc()).limit(10).all()
    
    # שלב ניתוחים אחרונים
    analyses = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.threat_level.in_(["threat", "suspicious"])
    ).order_by(EmailAnalysis.created_at.desc()).limit(10).all()
    
    notifications = []
    for t in threats:
        notifications.append({
            "id": t.id,
            "type": "community",
            "title": "Community Threat",
            "message": f"New {t.threat_type} reported: {t.indicator}",
            "time": t.published_at.isoformat(),
            "read": False,
            "color": "#3b82f6"
        })
    for a in analyses:
        notifications.append({
            "id": a.id,
            "type": "threat",
            "title": "Threat Detected",
            "message": a.summary[:100],
            "time": a.created_at.isoformat(),
            "read": False,
            "color": "#ff3b3b"
        })
    
    # מיון לפי זמן
    notifications.sort(key=lambda x: x["time"], reverse=True)
    return notifications[:limit]