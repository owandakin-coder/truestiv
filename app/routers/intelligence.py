import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.models import (
    CommunityThreat,
    EmailAnalysis,
    IPScanObservation,
    MediaAnalysis,
    ScanHistory,
    User,
)
from app.services.threat_intel import collect_all_intel, get_ip_geo

router = APIRouter()
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalize_level(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    if normalized == "dangerous":
        return "threat"
    return normalized or "unknown"


def _is_actionable_level(value: str | None) -> bool:
    return _normalize_level(value) in {"suspicious", "threat"}


def _normalize_indicator(ioc_type: str, indicator: str) -> str:
    value = (indicator or "").strip()
    if ioc_type in {"url", "ip", "hash", "domain", "email", "phone"}:
        return value.lower()
    return value


def _iso(value) -> str | None:
    if not value:
        return None
    if isinstance(value, str):
        return value
    return value.isoformat()


def _parse_time_range(value: str | None) -> datetime | None:
    normalized = (value or "30d").strip().lower()
    if normalized in {"", "all", "any"}:
        return None
    now = datetime.now(timezone.utc)
    mapping = {
        "24h": timedelta(hours=24),
        "48h": timedelta(hours=48),
        "7d": timedelta(days=7),
        "14d": timedelta(days=14),
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
    }
    delta = mapping.get(normalized)
    return now - delta if delta else now - timedelta(days=30)


def _in_range(value, cutoff: datetime | None) -> bool:
    if not cutoff:
        return True
    if not value:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value >= cutoff


def _build_ioc_href(ioc_type: str, indicator: str) -> str:
    return f"/ioc/{ioc_type}/{quote(indicator, safe='')}"


def _collect_geo_markers(db: Session) -> list[dict]:
    markers = []
    seen = set()

    recent_observations = (
        db.query(IPScanObservation)
        .order_by(IPScanObservation.created_at.desc())
        .limit(180)
        .all()
    )

    for observation in recent_observations:
        if not observation.ip or observation.ip in seen:
            continue
        if observation.latitude is None or observation.longitude is None:
            continue
        if not _is_actionable_level(observation.threat_level):
            continue
        seen.add(observation.ip)
        markers.append(
            {
                "indicator": observation.ip,
                "ioc_type": "ip",
                "latitude": observation.latitude,
                "longitude": observation.longitude,
                "country": observation.country or "Unknown",
                "city": observation.city or "",
                "region": observation.region or "",
                "organization": observation.organization or "",
                "isp": observation.isp or "",
                "risk_score": observation.risk_score or 0,
                "threat_level": _normalize_level(observation.threat_level),
                "published_at": _iso(observation.created_at) or datetime.utcnow().isoformat(),
                "location_name": ", ".join(part for part in [observation.city, observation.country] if part) or "Unknown location",
                "source": observation.source or "scanner",
                "details_path": _build_ioc_href("ip", observation.ip),
            }
        )

    threat_ips = (
        db.query(CommunityThreat)
        .order_by(CommunityThreat.published_at.desc())
        .limit(180)
        .all()
    )

    for threat in threat_ips:
        ip = (threat.indicator or "").strip()
        if not ip or ip in seen or not IP_PATTERN.match(ip):
            continue
        if not _is_actionable_level(threat.threat_level):
            continue
        geo = get_ip_geo(ip)
        if geo.get("lat") is None or geo.get("lon") is None:
            continue
        seen.add(ip)
        intel_source = None
        if isinstance(threat.raw_intel, dict):
            intel_source = threat.raw_intel.get("source")
        markers.append(
            {
                "indicator": ip,
                "ioc_type": "ip",
                "latitude": geo.get("lat"),
                "longitude": geo.get("lon"),
                "country": geo.get("country") or "Unknown",
                "city": geo.get("city") or "",
                "region": geo.get("region") or "",
                "organization": geo.get("org") or "",
                "isp": geo.get("isp") or "",
                "risk_score": threat.risk_score or 25,
                "threat_level": _normalize_level(threat.threat_level),
                "published_at": _iso(threat.published_at) or datetime.utcnow().isoformat(),
                "location_name": ", ".join(part for part in [geo.get("city"), geo.get("country")] if part) or "Unknown location",
                "source": intel_source or "community",
                "details_path": _build_ioc_href("ip", ip),
            }
        )

    return markers


def _build_scan_item(item: ScanHistory) -> dict:
    return {
        "id": item.id,
        "scan_type": item.scan_type,
        "indicator": item.indicator,
        "threat_level": _normalize_level(item.threat_level),
        "risk_score": item.risk_score or 0,
        "confidence": item.confidence or 0,
        "country": item.country,
        "source": item.source or "scanner",
        "summary": item.summary or "",
        "created_at": _iso(item.created_at),
        "details_path": _build_ioc_href(item.scan_type, item.indicator),
    }


def _build_scan_event(item: ScanHistory) -> dict:
    return {
        "id": f"scan-{item.id}",
        "event_type": "scan",
        "source": item.source or "scanner",
        "ioc_type": item.scan_type,
        "indicator": item.indicator,
        "title": f"{item.scan_type.upper()} scan recorded",
        "summary": item.summary or "A new scanner result was recorded.",
        "threat_level": _normalize_level(item.threat_level),
        "risk_score": item.risk_score or 0,
        "country": item.country,
        "created_at": _iso(item.created_at),
        "details_path": _build_ioc_href(item.scan_type, item.indicator),
    }


def _build_community_event(item: CommunityThreat) -> dict:
    return {
        "id": f"community-{item.id}",
        "event_type": "community",
        "source": "community",
        "ioc_type": item.threat_type,
        "indicator": item.indicator,
        "title": item.title or f"{str(item.threat_type or 'indicator').upper()} promoted to community",
        "summary": item.description or "A community-visible threat indicator was published.",
        "threat_level": _normalize_level(item.threat_level),
        "risk_score": item.risk_score or 0,
        "created_at": _iso(item.published_at),
        "details_path": _build_ioc_href(item.threat_type, item.indicator),
    }


def _build_analysis_event(item: EmailAnalysis) -> dict:
    indicator = item.sender or item.phone_number or item.subject or f"{item.channel} analysis"
    ioc_type = "email" if item.channel == "email" else "phone"
    confidence = float(item.confidence or 0)
    risk_score = max(0, min(100, int(confidence * 100) if confidence <= 1 else int(confidence)))
    return {
        "id": f"analysis-{item.id}",
        "event_type": "analysis",
        "source": "analysis",
        "ioc_type": ioc_type,
        "indicator": indicator,
        "title": item.subject or f"{str(item.channel or 'message').upper()} analysis",
        "summary": item.summary or "A message was analyzed by Trustive AI.",
        "threat_level": _normalize_level(item.threat_level),
        "risk_score": risk_score,
        "created_at": _iso(item.created_at),
    }


def _build_media_event(item: MediaAnalysis) -> dict:
    return {
        "id": f"media-{item.id}",
        "event_type": "media",
        "source": "media",
        "ioc_type": item.media_type or "media",
        "indicator": item.filename or f"media-{item.id}",
        "title": f"{str(item.media_type or 'media').title()} analysis",
        "summary": item.summary or "A media artifact was analyzed.",
        "threat_level": _normalize_level(item.threat_level),
        "risk_score": item.risk_score or 0,
        "created_at": _iso(item.created_at),
    }


def _dedupe_events(events: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    for event in sorted(events, key=lambda item: item.get("created_at") or "", reverse=True):
        key = (
            event.get("event_type"),
            event.get("ioc_type"),
            _normalize_indicator(event.get("ioc_type") or "", event.get("indicator") or event.get("title") or ""),
            _normalize_level(event.get("threat_level")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


@router.get("/geo-map")
def geo_map(
    source: str | None = None,
    country: str | None = None,
    threat_level: str | None = None,
    time_range: str = "30d",
    limit: int = Query(default=200, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = _parse_time_range(time_range)
    all_markers = _collect_geo_markers(db)

    available_sources = sorted({marker["source"] for marker in all_markers if marker.get("source")})
    available_countries = sorted({marker["country"] for marker in all_markers if marker.get("country") and marker.get("country") != "Unknown"})
    available_levels = sorted({marker["threat_level"] for marker in all_markers if marker.get("threat_level") and marker.get("threat_level") != "unknown"})

    normalized_source = (source or "").strip().lower()
    normalized_country = (country or "").strip().lower()
    normalized_level = _normalize_level(threat_level)

    markers = []
    for marker in all_markers:
        published_at = datetime.fromisoformat(marker["published_at"]) if marker.get("published_at") else None
        if normalized_source and normalized_source not in {"all", marker.get("source", "").lower()}:
            continue
        if normalized_country and marker.get("country", "").lower() != normalized_country:
            continue
        if normalized_level not in {"", "all", "unknown"} and marker.get("threat_level") != normalized_level:
            continue
        if not _in_range(published_at, cutoff):
            continue
        markers.append(marker)

    markers = markers[:limit]
    return {
        "success": True,
        "count": len(markers),
        "markers": markers,
        "filters": {
            "source": source or "all",
            "country": country or "all",
            "threat_level": threat_level or "all",
            "time_range": time_range,
        },
        "facets": {
            "sources": available_sources,
            "countries": available_countries,
            "threat_levels": available_levels,
        },
    }


@router.get("/scan-history")
def scan_history(
    scan_type: str | None = None,
    threat_level: str | None = None,
    time_range: str = "30d",
    limit: int = Query(default=40, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = _parse_time_range(time_range)
    query = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .filter(ScanHistory.threat_level.in_(["suspicious", "threat", "dangerous"]))
        .order_by(ScanHistory.created_at.desc())
    )
    if scan_type and scan_type.lower() != "all":
        query = query.filter(ScanHistory.scan_type == scan_type.lower())
    items = query.limit(limit * 4).all()

    normalized_level = _normalize_level(threat_level)
    filtered = []
    for item in items:
        if normalized_level not in {"", "all", "unknown"} and _normalize_level(item.threat_level) != normalized_level:
            continue
        if not _in_range(item.created_at, cutoff):
            continue
        filtered.append(_build_scan_item(item))
        if len(filtered) >= limit:
            break

    return {
        "success": True,
        "items": filtered,
    }


@router.get("/timeline")
def timeline(
    source: str | None = None,
    threat_level: str | None = None,
    time_range: str = "30d",
    limit: int = Query(default=60, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = _parse_time_range(time_range)
    normalized_source = (source or "").strip().lower()
    normalized_level = _normalize_level(threat_level)

    events = []

    for item in (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .filter(ScanHistory.threat_level.in_(["suspicious", "threat", "dangerous"]))
        .order_by(ScanHistory.created_at.desc())
        .limit(limit)
        .all()
    ):
        events.append(_build_scan_event(item))

    for item in (
        db.query(CommunityThreat)
        .filter(CommunityThreat.threat_level.in_(["suspicious", "threat", "dangerous"]))
        .order_by(CommunityThreat.published_at.desc())
        .limit(limit)
        .all()
    ):
        events.append(_build_community_event(item))

    for item in (
        db.query(EmailAnalysis)
        .filter(EmailAnalysis.user_id == current_user.id)
        .filter(EmailAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]))
        .order_by(EmailAnalysis.created_at.desc())
        .limit(limit)
        .all()
    ):
        events.append(_build_analysis_event(item))

    for item in (
        db.query(MediaAnalysis)
        .filter(MediaAnalysis.user_id == current_user.id)
        .filter(MediaAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]))
        .order_by(MediaAnalysis.created_at.desc())
        .limit(limit)
        .all()
    ):
        events.append(_build_media_event(item))

    filtered = []
    for event in events:
        created_at = datetime.fromisoformat(event["created_at"]) if event.get("created_at") else None
        if normalized_source and normalized_source != "all" and event.get("event_type") != normalized_source:
            continue
        if normalized_level not in {"", "all", "unknown"} and _normalize_level(event.get("threat_level")) != normalized_level:
            continue
        if not _in_range(created_at, cutoff):
            continue
        filtered.append(event)

    filtered = _dedupe_events(filtered)[:limit]

    return {
        "success": True,
        "items": filtered,
        "stats": {
            "total": len(filtered),
            "high_attention": len(
                [
                    item
                    for item in filtered
                    if _normalize_level(item.get("threat_level")) in {"suspicious", "threat"}
                ]
            ),
            "sources": sorted({item["event_type"] for item in filtered}),
        },
    }


@router.get("/ioc/{ioc_type}/{indicator:path}")
def ioc_details(
    ioc_type: str,
    indicator: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    normalized_type = (ioc_type or "").strip().lower()
    normalized_indicator = _normalize_indicator(normalized_type, indicator)

    scan_matches = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.normalized_indicator == normalized_indicator,
        )
        .order_by(ScanHistory.created_at.desc())
        .limit(20)
        .all()
    )

    community_matches = [
        item
        for item in db.query(CommunityThreat).order_by(CommunityThreat.published_at.desc()).limit(200).all()
        if _normalize_indicator(item.threat_type, item.indicator) == normalized_indicator
        and _is_actionable_level(item.threat_level)
    ][:20]

    analysis_matches = (
        db.query(EmailAnalysis)
        .filter(
            EmailAnalysis.user_id == current_user.id,
            EmailAnalysis.content.ilike(f"%{indicator}%"),
            EmailAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
        )
        .order_by(EmailAnalysis.created_at.desc())
        .limit(12)
        .all()
    )

    media_matches = (
        db.query(MediaAnalysis)
        .filter(
            MediaAnalysis.user_id == current_user.id,
            MediaAnalysis.ocr_text.ilike(f"%{indicator}%"),
            MediaAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
        )
        .order_by(MediaAnalysis.created_at.desc())
        .limit(12)
        .all()
    )

    observation_matches = []
    geo = None
    if normalized_type == "ip":
        observation_matches = (
            db.query(IPScanObservation)
            .filter(
                IPScanObservation.ip == indicator,
                IPScanObservation.threat_level.in_(["suspicious", "threat", "dangerous"]),
            )
            .order_by(IPScanObservation.created_at.desc())
            .limit(12)
            .all()
        )
        latest_observation = observation_matches[0] if observation_matches else None
        if latest_observation and latest_observation.latitude is not None and latest_observation.longitude is not None:
            geo = {
                "country": latest_observation.country or "Unknown",
                "city": latest_observation.city or "",
                "region": latest_observation.region or "",
                "isp": latest_observation.isp or "",
                "organization": latest_observation.organization or "",
                "latitude": latest_observation.latitude,
                "longitude": latest_observation.longitude,
                "location_name": ", ".join(part for part in [latest_observation.city, latest_observation.country] if part) or "Unknown location",
            }
        else:
            resolved_geo = get_ip_geo(indicator)
            if resolved_geo.get("lat") is not None and resolved_geo.get("lon") is not None:
                geo = {
                    "country": resolved_geo.get("country") or "Unknown",
                    "city": resolved_geo.get("city") or "",
                    "region": resolved_geo.get("region") or "",
                    "isp": resolved_geo.get("isp") or "",
                    "organization": resolved_geo.get("org") or "",
                    "latitude": resolved_geo.get("lat"),
                    "longitude": resolved_geo.get("lon"),
                    "location_name": ", ".join(part for part in [resolved_geo.get("city"), resolved_geo.get("country")] if part) or "Unknown location",
                }

    risk_values = [
        *(item.risk_score or 0 for item in scan_matches),
        *(item.risk_score or 0 for item in community_matches),
        *(item.risk_score or 0 for item in media_matches),
        *(item.risk_score or 0 for item in observation_matches),
    ]
    latest_level = "unknown"
    latest_candidates = []
    if scan_matches:
        latest_candidates.append((scan_matches[0].created_at, _normalize_level(scan_matches[0].threat_level)))
    if community_matches:
        latest_candidates.append((community_matches[0].published_at, _normalize_level(community_matches[0].threat_level)))
    if media_matches:
        latest_candidates.append((media_matches[0].created_at, _normalize_level(media_matches[0].threat_level)))
    if analysis_matches:
        latest_candidates.append((analysis_matches[0].created_at, _normalize_level(analysis_matches[0].threat_level)))
    if observation_matches:
        latest_candidates.append((observation_matches[0].created_at, _normalize_level(observation_matches[0].threat_level)))
    if latest_candidates:
        latest_level = sorted(latest_candidates, key=lambda item: item[0] or datetime.min, reverse=True)[0][1]

    source_breakdown = {
        "scan_history": len(scan_matches),
        "community": len(community_matches),
        "analyses": len(analysis_matches),
        "media": len(media_matches),
        "observations": len(observation_matches),
    }

    return {
        "success": True,
        "ioc": {
            "type": normalized_type,
            "indicator": indicator,
            "normalized_indicator": normalized_indicator,
            "latest_threat_level": latest_level,
            "average_risk_score": round(sum(risk_values) / len(risk_values), 1) if risk_values else 0,
            "source_breakdown": source_breakdown,
            "geo": geo,
        },
        "scan_history": [_build_scan_item(item) for item in scan_matches],
        "community": [
            {
                "id": item.id,
                "threat_type": item.threat_type,
                "indicator": item.indicator,
                "risk_score": item.risk_score or 0,
                "threat_level": _normalize_level(item.threat_level),
                "summary": item.description or item.title or "Published in the community feed.",
                "published_at": _iso(item.published_at),
            }
            for item in community_matches
        ],
        "analyses": [
            {
                "id": item.id,
                "channel": item.channel,
                "subject": item.subject,
                "sender": item.sender or item.phone_number,
                "summary": item.summary or "",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
            }
            for item in analysis_matches
        ],
        "media": [
            {
                "id": item.id,
                "filename": item.filename,
                "media_type": item.media_type,
                "summary": item.summary or "",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
            }
            for item in media_matches
        ],
        "observations": [
            {
                "id": item.id,
                "ip": item.ip,
                "country": item.country,
                "city": item.city,
                "source": item.source,
                "risk_score": item.risk_score or 0,
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
            }
            for item in observation_matches
        ],
    }


@router.get("/search")
def search_intelligence(
    q: str = Query(default="", min_length=2),
    limit: int = Query(default=8, ge=1, le=25),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query_text = q.strip()
    pattern = f"%{query_text}%"

    scans = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.threat_level.in_(["suspicious", "threat", "dangerous"]),
            (
                ScanHistory.indicator.ilike(pattern)
                | ScanHistory.summary.ilike(pattern)
                | ScanHistory.scan_type.ilike(pattern)
            ),
        )
        .order_by(ScanHistory.created_at.desc())
        .limit(limit)
        .all()
    )

    community = (
        db.query(CommunityThreat)
        .filter(
            CommunityThreat.threat_level.in_(["suspicious", "threat", "dangerous"]),
            (
                CommunityThreat.indicator.ilike(pattern)
                | CommunityThreat.title.ilike(pattern)
                | CommunityThreat.description.ilike(pattern)
                | CommunityThreat.threat_type.ilike(pattern)
            ),
        )
        .order_by(CommunityThreat.published_at.desc())
        .limit(limit)
        .all()
    )

    analyses = (
        db.query(EmailAnalysis)
        .filter(
            EmailAnalysis.user_id == current_user.id,
            EmailAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
            (
                EmailAnalysis.sender.ilike(pattern)
                | EmailAnalysis.subject.ilike(pattern)
                | EmailAnalysis.content.ilike(pattern)
                | EmailAnalysis.summary.ilike(pattern)
            ),
        )
        .order_by(EmailAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )

    media = (
        db.query(MediaAnalysis)
        .filter(
            MediaAnalysis.user_id == current_user.id,
            MediaAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
            (
                MediaAnalysis.filename.ilike(pattern)
                | MediaAnalysis.ocr_text.ilike(pattern)
                | MediaAnalysis.summary.ilike(pattern)
            ),
        )
        .order_by(MediaAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )

    items = [
        *[
            {
                "id": f"scan-{item.id}",
                "kind": "scan",
                "title": item.indicator,
                "summary": item.summary or "",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
                "details_path": _build_ioc_href(item.scan_type, item.indicator),
            }
            for item in scans
        ],
        *[
            {
                "id": f"community-{item.id}",
                "kind": "community",
                "title": item.indicator,
                "summary": item.description or item.title or "",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.published_at),
                "details_path": _build_ioc_href(item.threat_type, item.indicator),
            }
            for item in community
        ],
        *[
            {
                "id": f"analysis-{item.id}",
                "kind": "analysis",
                "title": item.subject or item.sender or item.phone_number or "Analysis result",
                "summary": item.summary or "",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
                "details_path": "",
            }
            for item in analyses
        ],
        *[
            {
                "id": f"media-{item.id}",
                "kind": "media",
                "title": item.filename or "Media finding",
                "summary": item.summary or "",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
                "details_path": "",
            }
            for item in media
        ],
    ]
    items = _dedupe_events(
        [
            {
                "event_type": item["kind"],
                "ioc_type": item["kind"],
                "indicator": item["title"],
                "threat_level": item["threat_level"],
                "created_at": item["created_at"],
                **item,
            }
            for item in items
        ]
    )[: limit * 3]
    return {"success": True, "items": items}


@router.get("/trends")
def threat_trends(
    time_range: str = "30d",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = _parse_time_range(time_range)
    source_counts: dict[str, int] = {}
    country_counts: dict[str, int] = {}
    ioc_type_counts: dict[str, int] = {}
    daily_counts: dict[str, int] = {}

    def add_count(target: dict[str, int], key: str | None):
        normalized = (key or "Unknown").strip() or "Unknown"
        target[normalized] = target.get(normalized, 0) + 1

    scan_items = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.threat_level.in_(["suspicious", "threat", "dangerous"]),
        )
        .order_by(ScanHistory.created_at.desc())
        .limit(400)
        .all()
    )
    for item in scan_items:
        if not _in_range(item.created_at, cutoff):
            continue
        add_count(source_counts, item.source or "scanner")
        add_count(country_counts, item.country)
        add_count(ioc_type_counts, item.scan_type)
        add_count(daily_counts, (item.created_at.date().isoformat() if item.created_at else "Unknown"))

    community_items = (
        db.query(CommunityThreat)
        .filter(CommunityThreat.threat_level.in_(["suspicious", "threat", "dangerous"]))
        .order_by(CommunityThreat.published_at.desc())
        .limit(400)
        .all()
    )
    for item in community_items:
        if not _in_range(item.published_at, cutoff):
            continue
        add_count(source_counts, "community")
        raw_source = item.raw_intel.get("source") if isinstance(item.raw_intel, dict) else None
        add_count(source_counts, raw_source or "community")
        add_count(ioc_type_counts, item.threat_type)
        add_count(daily_counts, (item.published_at.date().isoformat() if item.published_at else "Unknown"))

    return {
        "success": True,
        "time_range": time_range,
        "by_source": sorted(
            [{"label": label, "count": count} for label, count in source_counts.items()],
            key=lambda item: item["count"],
            reverse=True,
        )[:8],
        "by_country": sorted(
            [{"label": label, "count": count} for label, count in country_counts.items() if label != "Unknown"],
            key=lambda item: item["count"],
            reverse=True,
        )[:8],
        "by_ioc_type": sorted(
            [{"label": label, "count": count} for label, count in ioc_type_counts.items()],
            key=lambda item: item["count"],
            reverse=True,
        )[:8],
        "timeline": sorted(
            [{"label": label, "count": count} for label, count in daily_counts.items()],
            key=lambda item: item["label"],
        )[-10:],
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
