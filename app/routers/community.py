from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, ThreatReport, CommunityThreat
from typing import List
from datetime import datetime
from app.schemas.schemas import ThreatPublishRequest

router = APIRouter()

@router.get("/feed")
def get_threat_feed(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    reports = db.query(ThreatReport).order_by(ThreatReport.created_at.desc()).limit(50).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "description": r.description,
            "threat_type": r.threat_type,
            "severity": r.severity,
            "is_verified": r.is_verified,
            "reported_by": r.user_id,
            "created_at": r.created_at.isoformat()
        }
        for r in reports
    ]


@router.post("/reports")
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
        "created_at": report.created_at.isoformat()
    }


@router.post("/reports/{report_id}/verify")
def verify_report(report_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot verify your own report")

    report.is_verified = True
    db.commit()

    return {"success": True, "message": "Report verified"}


@router.get("/stats")
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


# -----------------------------
# Community Threat Intelligence
# -----------------------------

@router.post("/publish-threat")
def publish_threat(
    data: ThreatPublishRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    threat = CommunityThreat(
        threat_type=data.threat_type,
        indicator=data.indicator,
        risk_score=data.risk_score,
        threat_level=data.threat_level,
        source_analysis_id=data.analysis_id,
        published_by=current_user.id,
        raw_intel=[]
    )

    db.add(threat)
    db.commit()
    db.refresh(threat)

    return {
        "success": True,
        "id": threat.id,
        "threat_type": threat.threat_type,
        "indicator": threat.indicator,
        "risk_score": threat.risk_score,
        "threat_level": threat.threat_level,
        "published_at": threat.published_at.isoformat()
    }


@router.get("/threats")
def get_community_threats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    threats = db.query(CommunityThreat).order_by(CommunityThreat.published_at.desc()).limit(50).all()

    return [
        {
            "id": t.id,
            "threat_type": t.threat_type,
            "indicator": t.indicator,
            "risk_score": t.risk_score,
            "threat_level": t.threat_level,
            "source_analysis_id": t.source_analysis_id,
            "published_by": t.published_by,
            "published_at": t.published_at.isoformat()
        }
        for t in threats
    ]
