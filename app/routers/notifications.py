from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, CommunityThreat, EmailAnalysis
from typing import List, Dict, Any

router = APIRouter(tags=["Notifications"])


@router.get("/")
def get_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 30
) -> Dict[str, Any]:
    """
    Get combined notifications from community threats and user's own threat analyses.
    """
    # Community threats published by others
    community_threats = db.query(CommunityThreat).filter(
        CommunityThreat.published_by != current_user.id,
        CommunityThreat.is_moderated == False
    ).order_by(desc(CommunityThreat.published_at)).limit(limit // 2).all()

    # User's own threat analyses
    own_analyses = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.threat_level.in_(["threat", "suspicious"])
    ).order_by(desc(EmailAnalysis.created_at)).limit(limit // 2).all()

    notifications = []

    for ct in community_threats:
        notifications.append({
            "id": f"comm_{ct.id}",
            "type": "community",
            "title": f"Community {ct.threat_type.upper()} Threat",
            "message": ct.indicator[:100] if ct.indicator else "New threat reported",
            "time": ct.published_at.isoformat(),
            "read": False,  # TODO: store read status per user in separate table
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

    # Sort by most recent first
    notifications.sort(key=lambda x: x["time"], reverse=True)
    return {"total": len(notifications), "items": notifications[:limit]}


@router.post("/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Mark a specific notification as read.
    Since we don't have a persistent read status table yet, we just return success.
    For production, you'd store read status in a UserNotificationRead table.
    """
    # TODO: Implement persistent read status (e.g., UserNotificationRead model)
    # For now, always return success (frontend will manage read state locally)
    return {"success": True, "message": f"Notification {notification_id} marked as read (locally)"}
