from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, ThreatReport, CommunityThreat, CommunityLike
from typing import List
from datetime import datetime
from app.schemas.schemas import ThreatPublishRequest

router = APIRouter()


def normalize_indicator(threat_type: str, indicator: str) -> str:
    normalized = (indicator or "").strip()
    if threat_type in {"url", "ip", "hash", "email", "domain", "phone"}:
        return normalized.lower()
    return normalized

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
    normalized_type = (data.threat_type or "").strip().lower()
    normalized_indicator = normalize_indicator(normalized_type, data.indicator)
    if not normalized_indicator:
        raise HTTPException(status_code=400, detail="Indicator is required")

    existing_query = db.query(CommunityThreat).filter(CommunityThreat.threat_type == normalized_type)
    if normalized_type in {"url", "ip", "hash", "email", "domain", "phone"}:
        existing_query = existing_query.filter(func.lower(CommunityThreat.indicator) == normalized_indicator)
    else:
        existing_query = existing_query.filter(CommunityThreat.indicator == normalized_indicator)
    existing = existing_query.order_by(CommunityThreat.published_at.desc()).first()

    if existing:
        return {
            "success": True,
            "duplicate": True,
            "id": existing.id,
            "threat_type": existing.threat_type,
            "indicator": existing.indicator,
            "risk_score": existing.risk_score,
            "threat_level": existing.threat_level,
            "published_at": existing.published_at.isoformat() if existing.published_at else None,
        }

    threat = CommunityThreat(
        threat_type=normalized_type,
        indicator=normalized_indicator,
        risk_score=data.risk_score,
        threat_level=(data.threat_level or "suspicious").lower(),
        source_analysis_id=data.analysis_id,
        published_by=current_user.id,
        raw_intel={"source": "community", "published_via": "public_workspace"},
        is_moderated=True,
    )

    db.add(threat)
    db.commit()
    db.refresh(threat)

    return {
        "success": True,
        "duplicate": False,
        "id": threat.id,
        "threat_type": threat.threat_type,
        "indicator": threat.indicator,
        "risk_score": threat.risk_score,
        "threat_level": threat.threat_level,
        "published_at": threat.published_at.isoformat()
    }


@router.get("/threats")
def get_community_threats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    threats = (
        db.query(CommunityThreat)
        .filter(
            CommunityThreat.is_moderated == True,
            CommunityThreat.threat_level.in_(["suspicious", "threat", "dangerous"]),
        )
        .order_by(CommunityThreat.published_at.desc())
        .limit(50)
        .all()
    )

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

@router.post("/{threat_id}/like", status_code=200)
def like_threat(threat_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    # upsert like
    existing = db.query(CommunityLike).filter_by(threat_id=threat_id, user_id=user.id).first()
    if existing:
        db.delete(existing)
        db.query(CommunityThreat).filter_by(id=threat_id).update({"likes_count": CommunityThreat.likes_count - 1})
        db.commit()
        return {"liked": False}
    db.add(CommunityLike(threat_id=threat_id, user_id=user.id))
    db.query(CommunityThreat).filter_by(id=threat_id).update({"likes_count": CommunityThreat.likes_count + 1})
    db.commit()
    return {"liked": True}
