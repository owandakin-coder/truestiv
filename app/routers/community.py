from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, ThreatReport
from typing import List
from datetime import datetime
from app.models.models import CommunityThreat
from app.services.threat_intel import aggregate_ip_intel, aggregate_url_intel
from app.schemas.schemas import ThreatPublishRequest

router = APIRouter()

@router.get("/feed", response_model=List[dict])
def get_threat_feed(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    reports = db.query(ThreatReport).order_by(ThreatReport.created_at.desc()).limit(50).all()
    return [{
        "id": r.id,
        "title": r.title,
        "description": r.description,
        "threat_type": r.threat_type,
        "severity": r.severity,
        "is_verified": r.is_verified,
        "reported_by": r.user_id,
        "created_at": str(r.created_at)
    } for r in reports]

@router.post("/reports", response_model=dict)
def create_report(report_data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not report_data.get("title") or not report_data.get("threat_type"):
        raise HTTPException(status_code=400, detail="Title and threat_type are required")

    report = ThreatReport(
        user_id=current_user.id,
        title=report_data["title"],
        description=report_data.get("description", ""),
        threat_type=report_data["threat_type"],
        severity=report_data.get("severity", "medium"),
        is_verified=False
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {
        "success": True,
        "id": report.id,
        "title": report.title,
        "threat_type": report.threat_type,
        "severity": report.severity,
        "created_at": str(report.created_at)
    }

@router.post("/reports/{report_id}/verify", response_model=dict)
def verify_report(report_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot verify your own report")
    report.is_verified = True
    db.commit()
    return {"success": True, "message": "Report verified"}

@router.get("/stats", response_model=dict)
def community_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total = db.query(ThreatReport).count()
    verified = db.query(ThreatReport).filter(ThreatReport.is_verified == True).count()
    by_type = {}
    for report in db.query(ThreatReport).all():
        by_type[report.threat_type] = by_type.get(report.threat_type, 0) + 1
    return {
        "total_reports": total,
        "verified_reports": verified,
        "by_type": by_type
    }
