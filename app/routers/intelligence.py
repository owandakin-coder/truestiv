import re
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import quote

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.models import CommunityThreat, EmailAnalysis, User
from app.services.threat_intel import (
    collect_all_intel,
    get_ip_geo,
)

router = APIRouter()
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _extract_ip_candidates(db: Session, limit: int = 200) -> List[str]:
    threat_ips = [
        row[0]
        for row in db.query(CommunityThreat.indicator)
        .filter(CommunityThreat.threat_type == "ip")
        .order_by(CommunityThreat.published_at.desc())
        .limit(limit)
        .all()
    ]
    sender_ips = [
        row[0]
        for row in db.query(EmailAnalysis.sender)
        .filter(EmailAnalysis.sender.isnot(None))
        .order_by(EmailAnalysis.created_at.desc())
        .limit(limit)
        .all()
        if row[0] and IP_PATTERN.match(row[0])
    ]
    ordered = []
    seen = set()
    for ip in threat_ips + sender_ips:
        if ip and ip not in seen:
            ordered.append(ip)
            seen.add(ip)
    return ordered


@router.get("/geo-map")
def geo_map(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    markers = []
    for ip in _extract_ip_candidates(db):
        geo = get_ip_geo(ip)
        if geo.get("lat") is None or geo.get("lon") is None:
            continue
        matching_threat = (
            db.query(CommunityThreat)
            .filter(CommunityThreat.indicator == ip)
            .order_by(CommunityThreat.published_at.desc())
            .first()
        )
        markers.append(
            {
                "indicator": ip,
                "latitude": geo.get("lat"),
                "longitude": geo.get("lon"),
                "country": geo.get("country"),
                "city": geo.get("city"),
                "organization": geo.get("org"),
                "isp": geo.get("isp"),
                "risk_score": matching_threat.risk_score if matching_threat else 25,
                "threat_level": matching_threat.threat_level if matching_threat else "suspicious",
                "published_at": (
                    matching_threat.published_at.isoformat()
                    if matching_threat and matching_threat.published_at
                    else datetime.utcnow().isoformat()
                ),
            }
        )

    return {
        "success": True,
        "count": len(markers),
        "markers": markers,
    }


@router.get("/share-preview")
def share_preview(
    threat_id: int | None = None,
    analysis_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    title = "Trustive AI threat alert"
    summary = "Threat intelligence item ready for social sharing."
    path = "/community"

    if threat_id:
        threat = db.query(CommunityThreat).filter(CommunityThreat.id == threat_id).first()
        if threat:
            title = threat.title or f"{threat.threat_type.upper()} threat detected"
            summary = threat.description or f"Indicator {threat.indicator} scored {threat.risk_score}."
            path = f"/community?threat={threat.id}"
    elif analysis_id:
        analysis = (
            db.query(EmailAnalysis)
            .filter(EmailAnalysis.id == analysis_id, EmailAnalysis.user_id == current_user.id)
            .first()
        )
        if analysis:
            title = analysis.subject or f"{analysis.channel.upper()} analysis result"
            summary = analysis.summary or "Trustive AI analysis result ready for sharing."
            path = f"/analysis?result={analysis.id}"

    share_url = f"{getattr(settings, 'BASE_URL', 'http://localhost:8000').rstrip('/')}{path}"
    hashtags = getattr(settings, "DEFAULT_SHARE_HASHTAGS", "TrustiveAI,CyberSecurity,ThreatIntel")
    share_text = f"{title}: {summary}"

    return {
        "success": True,
        "title": title,
        "summary": summary,
        "share_text": share_text[:240],
        "share_url": share_url,
        "twitter_url": f"https://twitter.com/intent/tweet?text={quote(share_text[:200])}&url={quote(share_url)}&hashtags={quote(hashtags)}",
        "linkedin_url": f"https://www.linkedin.com/sharing/share-offsite/?url={quote(share_url)}",
        "hashtags": hashtags.split(","),
    }


@router.get("/sources-status")
def sources_status(current_user: User = Depends(get_current_user)):
    return {
        "success": True,
        "sources": [
            {"name": "AlienVault OTX", "type": "ip/url"},
            {"name": "URLhaus", "type": "url"},
            {"name": "AbuseIPDB", "type": "ip"},
            {"name": "PhishTank", "type": "url"},
            {"name": "IBM X-Force", "type": "ip/url"},
            {"name": "CISA KEV", "type": "cve"},
        ],
    }


@router.post("/collect-now")
def collect_now(current_user: User = Depends(get_current_user)):
    return {
        "success": True,
        "result": collect_all_intel(),
    }
