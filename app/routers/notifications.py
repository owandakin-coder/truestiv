from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, CommunityThreat, EmailAnalysis

router = APIRouter()

@router.get("/")
def get_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 30
):
    # 
    community_threats = db.query(CommunityThreat).filter(
        CommunityThreat.published_by != current_user.id
    ).order_by(desc(CommunityThreat.published_at)).limit(limit // 2).all()
    
    # 
    own_analyses = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.threat_level.in_(["threat", "suspicious"])
    ).order_by(desc(EmailAnalysis.created_at)).limit(limit // 2).all()
    
    notifications = []
    
    for ct in community_threats:
        notifications.append({
            "id": f"comm_{ct.id}",
            "type": "community",
            "title": "Community Threat",
            "message": f"{ct.threat_type.upper()}: {ct.indicator[:50]}",
            "time": ct.published_at.isoformat(),
            "read": False,
            "color": "#3b82f6",
            "icon": "globe"
        })
    
    for an in own_analyses:
        notifications.append({
            "id": f"analysis_{an.id}",
            "type": "threat",
            "title": "Threat Detected",
            "message": an.summary[:100] if an.summary else f"{an.threat_type} from {an.sender or an.phone_number}",
            "time": an.created_at.isoformat(),
            "read": False,
            "color": "#ff3b3b",
            "icon": "alert"
        })
    
    #   
    notifications.sort(key=lambda x: x["time"], reverse=True)
    return notifications[:limit]
