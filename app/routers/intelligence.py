import ipaddress
import re
from datetime import datetime, timedelta, timezone
from email.parser import Parser
from email.utils import parseaddr
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.models import (
    BackgroundJobRun,
    CommunityThreat,
    EmailAnalysis,
    EnrichmentRetryTask,
    IPScanObservation,
    MediaAnalysis,
    ScanHistory,
    User,
)
import requests

from app.services.threat_intel import aggregate_ip_intel, aggregate_url_intel, collect_all_intel, get_ip_geo
from app.routers.scanner import detect_brand_impersonation

try:
    import dns.resolver as dns_resolver
except Exception:
    dns_resolver = None

router = APIRouter()
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
SOURCE_CONFIDENCE = {
    "alienvault otx": 0.72,
    "urlhaus": 0.92,
    "abuseipdb": 0.88,
    "phishtank": 0.9,
    "ibm x-force": 0.8,
    "cisa kev": 0.96,
    "community": 0.62,
    "analysis": 0.66,
    "media": 0.68,
    "scanner": 0.74,
    "scanner_enhanced": 0.84,
    "scanner_ip": 0.78,
    "scanner_url": 0.76,
    "scanner_hash": 0.9,
    "scanner_file": 0.7,
}


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


def _build_ip_lookup_href(indicator: str) -> str:
    return f"/lookup-center/ip/{quote(indicator, safe='')}"


def _build_domain_lookup_href(indicator: str) -> str:
    return f"/lookup-center/domain/{quote(indicator, safe='')}"


def _build_header_analyzer_href() -> str:
    return "/lookup-center/email-header"


def _normalize_domain(value: str | None) -> str:
    candidate = (value or "").strip().lower()
    if not candidate:
        return ""
    if "://" in candidate:
        candidate = urlparse(candidate).netloc or candidate
    candidate = candidate.split("/")[0].split(":")[0].strip(".")
    return candidate


def _parse_rdap_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _source_confidence(source: str | None) -> float:
    normalized = (source or "").strip().lower()
    return SOURCE_CONFIDENCE.get(normalized, 0.6)


def _confidence_label(score: float) -> str:
    if score >= 0.9:
        return "high"
    if score >= 0.75:
        return "strong"
    if score >= 0.6:
        return "moderate"
    return "low"


def _threat_actor_tags(indicator: str, summary: str = "", source: str = "", ioc_type: str = "") -> list[dict]:
    text = " ".join([indicator or "", summary or "", source or "", ioc_type or ""]).lower()
    tags = []
    if any(term in text for term in ["login", "verify", "credential", "phish", "bank", "paypal"]):
        tags.append({"tag": "Phishing Infrastructure", "confidence": 0.86})
    if any(term in text for term in ["wallet", "seed", "crypto", "metamask"]):
        tags.append({"tag": "Crypto Theft Campaign", "confidence": 0.78})
    if any(term in text for term in ["invoice", "wire", "payment", "ceo", "finance"]):
        tags.append({"tag": "Business Email Compromise", "confidence": 0.74})
    if any(term in text for term in ["loader", "malware", "payload", "trojan", "hash"]):
        tags.append({"tag": "Malware Delivery", "confidence": 0.72})
    if ioc_type == "ip" and any(term in text for term in ["tor", "relay", "anonymous", "vpn"]):
        tags.append({"tag": "Anonymous Infrastructure", "confidence": 0.68})
    if any(term in text for term in ["kit", "landing", "panel", "urlhaus"]):
        tags.append({"tag": "Phishing Kit", "confidence": 0.64})
    deduped = {}
    for tag in tags:
        deduped[tag["tag"]] = max(deduped.get(tag["tag"], 0), tag["confidence"])
    return [{"tag": key, "confidence": value} for key, value in deduped.items()]


def _provider_summary(source_item: dict) -> str:
    if source_item.get("error"):
        return str(source_item["error"])
    if source_item.get("total_reports"):
        return f"{source_item.get('total_reports')} abuse reports"
    if source_item.get("malicious_votes") is not None:
        return f"{source_item.get('malicious_votes', 0)} malicious detections"
    if source_item.get("noise") is True:
        return "Background internet noise observed"
    if source_item.get("classification"):
        return f"Classified as {source_item.get('classification')}"
    if source_item.get("country") or source_item.get("city"):
        return ", ".join(part for part in [source_item.get("city"), source_item.get("country")] if part)
    return "Provider returned contextual metadata"


def _unique_values(*values) -> list[str]:
    seen = set()
    items = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        items.append(normalized)
    return items


def _sorted_recent_events(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda item: item.get("created_at") or "", reverse=True)


def _lookup_dns_records(domain: str) -> dict:
    if not dns_resolver:
        return {"a": [], "mx": [], "ns": [], "txt": []}

    record_map = {"A": "a", "MX": "mx", "NS": "ns", "TXT": "txt"}
    results = {"a": [], "mx": [], "ns": [], "txt": []}
    for record_type, key in record_map.items():
        try:
            answers = dns_resolver.resolve(domain, record_type, lifetime=4)
            if record_type == "MX":
                results[key] = [str(answer.exchange).rstrip(".") for answer in answers]
            elif record_type == "TXT":
                values = []
                for answer in answers:
                    if hasattr(answer, "strings"):
                        values.append("".join(part.decode("utf-8", errors="ignore") for part in answer.strings))
                    else:
                        values.append(str(answer).replace('"', ""))
                results[key] = values
            else:
                results[key] = [str(answer).rstrip(".") for answer in answers]
        except Exception:
            results[key] = []
    return results


def _lookup_rdap(domain: str) -> dict:
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        if response.status_code != 200:
            return {}
        data = response.json()
    except Exception:
        return {}

    registrar = ""
    for entity in data.get("entities", []):
        roles = [str(role).lower() for role in entity.get("roles", [])]
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "fn":
                    registrar = item[3]
                    break
        if registrar:
            break

    created_at = None
    for event in data.get("events", []):
        if str(event.get("eventAction", "")).lower() in {"registration", "registered"}:
            created_at = _parse_rdap_datetime(event.get("eventDate"))
            if created_at:
                break

    age_days = None
    if created_at:
        age_days = max(0, int((datetime.now(timezone.utc) - created_at).days))

    return {
        "registrar": registrar,
        "created_at": created_at.isoformat() if created_at else None,
        "age_days": age_days,
        "status": data.get("status", []),
        "handle": data.get("handle"),
        "ldh_name": data.get("ldhName") or domain,
    }


def _extract_domain_from_address(value: str | None) -> str:
    address = parseaddr(value or "")[1]
    if "@" not in address:
        return _normalize_domain(address)
    return _normalize_domain(address.split("@", 1)[1])


def _extract_ips_from_received(received_headers: list[str]) -> list[str]:
    matches = []
    pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    for header in received_headers:
        matches.extend(pattern.findall(header or ""))
    deduped = []
    seen = set()
    for item in matches:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _extract_auth_value(source_text: str, key: str) -> str:
    match = re.search(rf"{key}\s*=\s*([a-zA-Z_-]+)", source_text, re.IGNORECASE)
    return match.group(1).lower() if match else "unknown"


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
    confidence_score = _source_confidence(item.source or "scanner")
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
        "source_confidence": confidence_score,
        "source_confidence_label": _confidence_label(confidence_score),
        "actor_tags": _threat_actor_tags(item.indicator, item.summary or "", item.source or "scanner", item.scan_type),
        "created_at": _iso(item.created_at),
        "details_path": _build_ioc_href(item.scan_type, item.indicator),
    }


def _build_scan_event(item: ScanHistory) -> dict:
    confidence_score = _source_confidence(item.source or "scanner")
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
        "source_confidence": confidence_score,
        "source_confidence_label": _confidence_label(confidence_score),
        "actor_tags": _threat_actor_tags(item.indicator, item.summary or "", item.source or "scanner", item.scan_type),
        "created_at": _iso(item.created_at),
        "details_path": _build_ioc_href(item.scan_type, item.indicator),
    }


def _build_community_event(item: CommunityThreat) -> dict:
    intel_source = item.raw_intel.get("source") if isinstance(item.raw_intel, dict) else "community"
    summary = item.description or "A community-visible threat indicator was published."
    confidence_score = _source_confidence(intel_source or "community")
    return {
        "id": f"community-{item.id}",
        "event_type": "community",
        "source": "community",
        "ioc_type": item.threat_type,
        "indicator": item.indicator,
        "title": item.title or f"{str(item.threat_type or 'indicator').upper()} promoted to community",
        "summary": summary,
        "threat_level": _normalize_level(item.threat_level),
        "risk_score": item.risk_score or 0,
        "source_confidence": confidence_score,
        "source_confidence_label": _confidence_label(confidence_score),
        "actor_tags": _threat_actor_tags(item.indicator, summary, intel_source or "community", item.threat_type),
        "created_at": _iso(item.published_at),
        "details_path": _build_ioc_href(item.threat_type, item.indicator),
    }


def _build_analysis_event(item: EmailAnalysis) -> dict:
    indicator = item.sender or item.phone_number or item.subject or f"{item.channel} analysis"
    ioc_type = "email" if item.channel == "email" else "phone"
    confidence = float(item.confidence or 0)
    risk_score = max(0, min(100, int(confidence * 100) if confidence <= 1 else int(confidence)))
    confidence_score = _source_confidence("analysis")
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
        "source_confidence": confidence_score,
        "source_confidence_label": _confidence_label(confidence_score),
        "actor_tags": _threat_actor_tags(indicator, item.summary or "", "analysis", ioc_type),
        "created_at": _iso(item.created_at),
    }


def _build_media_event(item: MediaAnalysis) -> dict:
    confidence_score = _source_confidence("media")
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
        "source_confidence": confidence_score,
        "source_confidence_label": _confidence_label(confidence_score),
        "actor_tags": _threat_actor_tags(item.filename or "", item.summary or "", "media", item.media_type or "media"),
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
        if normalized_country not in {"", "all"} and marker.get("country", "").lower() != normalized_country:
            continue
        if normalized_level not in {"", "all", "unknown"} and marker.get("threat_level") != normalized_level:
            continue
        if not _in_range(published_at, cutoff):
            continue
        markers.append(marker)

    markers = markers[:limit]
    playback_points = sorted(
        {
            marker["published_at"][:10]
            for marker in markers
            if marker.get("published_at")
        }
    )
    return {
        "success": True,
        "count": len(markers),
        "markers": markers,
        "playback_points": playback_points,
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


@router.get("/geo-map/country-drilldown")
def geo_map_country_drilldown(
    country: str,
    time_range: str = "30d",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = _parse_time_range(time_range)
    all_markers = _collect_geo_markers(db)
    normalized_country = (country or "").strip().lower()
    items = []
    for marker in all_markers:
        published_at = datetime.fromisoformat(marker["published_at"]) if marker.get("published_at") else None
        if marker.get("country", "").lower() != normalized_country:
            continue
        if not _in_range(published_at, cutoff):
            continue
        items.append(marker)

    items.sort(key=lambda item: item.get("published_at") or "", reverse=True)
    return {
        "success": True,
        "country": country,
        "count": len(items),
        "items": items[:60],
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
            "source_confidence": round(
                (
                    sum(
                        [
                            *[_source_confidence(item.source) for item in scan_matches],
                            *[
                                _source_confidence(item.raw_intel.get("source") if isinstance(item.raw_intel, dict) else "community")
                                for item in community_matches
                            ],
                            *[_source_confidence("analysis") for _ in analysis_matches],
                            *[_source_confidence("media") for _ in media_matches],
                            *[_source_confidence(item.source) for item in observation_matches],
                        ]
                    )
                    / max(
                        1,
                        len(scan_matches)
                        + len(community_matches)
                        + len(analysis_matches)
                        + len(media_matches)
                        + len(observation_matches),
                    )
                ),
                2,
            ),
            "source_confidence_label": _confidence_label(
                (
                    sum(
                        [
                            *[_source_confidence(item.source) for item in scan_matches],
                            *[
                                _source_confidence(item.raw_intel.get("source") if isinstance(item.raw_intel, dict) else "community")
                                for item in community_matches
                            ],
                            *[_source_confidence("analysis") for _ in analysis_matches],
                            *[_source_confidence("media") for _ in media_matches],
                            *[_source_confidence(item.source) for item in observation_matches],
                        ]
                    )
                    / max(
                        1,
                        len(scan_matches)
                        + len(community_matches)
                        + len(analysis_matches)
                        + len(media_matches)
                        + len(observation_matches),
                    )
                )
            ),
            "threat_actor_tags": _threat_actor_tags(
                indicator,
                " ".join(
                    [
                        *[item.summary or "" for item in scan_matches],
                        *[(item.description or item.title or "") for item in community_matches],
                        *[item.summary or "" for item in analysis_matches],
                        *[item.summary or "" for item in media_matches],
                    ]
                ),
                " ".join(
                    [
                        *[(item.source or "scanner") for item in scan_matches],
                        *[
                            (item.raw_intel.get("source") if isinstance(item.raw_intel, dict) else "community")
                            for item in community_matches
                        ],
                    ]
                ),
                normalized_type,
            ),
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


@router.get("/ip-lookup/{ip}")
def ip_lookup(
    ip: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    candidate = (ip or "").strip()
    try:
        normalized_ip = str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="A valid IP address is required.") from exc

    dossier = ioc_details(ioc_type="ip", indicator=normalized_ip, db=db, current_user=current_user)
    intel = aggregate_ip_intel(normalized_ip)
    geo = intel.get("geo") or {}

    providers = []
    related_domains = []
    related_networks = []
    related_organizations = []

    for item in intel.get("sources", []):
        source_name = item.get("source") or "Unknown source"
        confidence_score = _source_confidence(source_name)
        providers.append(
            {
                "source": source_name,
                "status": "error" if item.get("error") else "ok",
                "score": item.get("score"),
                "summary": _provider_summary(item),
                "confidence_score": round(confidence_score, 2),
                "confidence_label": _confidence_label(confidence_score),
                "raw": item,
            }
        )
        if item.get("domain"):
            related_domains.append(item.get("domain"))
        if item.get("page_domain"):
            related_domains.append(item.get("page_domain"))
        related_networks.extend(
            [
                item.get("network"),
                item.get("as"),
                item.get("asn"),
                item.get("as_owner"),
            ]
        )
        related_organizations.extend(
            [
                item.get("isp"),
                item.get("org"),
                item.get("organization"),
                item.get("as_owner"),
            ]
        )

    related_domains = _unique_values(*related_domains)
    related_networks = _unique_values(*related_networks)
    related_organizations = _unique_values(
        geo.get("isp"),
        geo.get("organization"),
        *related_organizations,
    )

    recent_events = []
    for item in dossier["scan_history"][:8]:
        recent_events.append(
            {
                "event_type": "scan",
                "title": f"{str(item.get('scan_type') or 'ip').upper()} scan",
                "summary": item.get("summary") or "Indicator observed in a scan workflow.",
                "threat_level": item.get("threat_level"),
                "created_at": item.get("created_at"),
                "path": item.get("details_path") or _build_ioc_href("ip", normalized_ip),
            }
        )
    for item in dossier["community"][:8]:
        recent_events.append(
            {
                "event_type": "community",
                "title": item.get("indicator") or "Community publication",
                "summary": item.get("summary") or "Published to the community feed.",
                "threat_level": item.get("threat_level"),
                "created_at": item.get("published_at"),
                "path": _build_ioc_href("ip", item.get("indicator") or normalized_ip),
            }
        )
    for item in dossier["analyses"][:6]:
        recent_events.append(
            {
                "event_type": "analysis",
                "title": item.get("subject") or item.get("sender") or "Analysis match",
                "summary": item.get("summary") or "Mentioned in an analysis result.",
                "threat_level": item.get("threat_level"),
                "created_at": item.get("created_at"),
                "path": "/investigation-center/analysis",
            }
        )
    for item in dossier["media"][:6]:
        recent_events.append(
            {
                "event_type": "media",
                "title": item.get("filename") or "Media finding",
                "summary": item.get("summary") or "Extracted during media analysis.",
                "threat_level": item.get("threat_level"),
                "created_at": item.get("created_at"),
                "path": "/investigation-center/media-lab",
            }
        )
    for item in dossier["observations"][:8]:
        recent_events.append(
            {
                "event_type": "observation",
                "title": item.get("source") or "IP observation",
                "summary": ", ".join(part for part in [item.get("city"), item.get("country")] if part) or "Observed in infrastructure telemetry.",
                "threat_level": item.get("threat_level"),
                "created_at": item.get("created_at"),
                "path": _build_ioc_href("ip", item.get("ip") or normalized_ip),
            }
        )

    geo_payload = {
        "country": geo.get("country") or dossier["ioc"].get("geo", {}).get("country") or "Unknown",
        "city": geo.get("city") or dossier["ioc"].get("geo", {}).get("city") or "",
        "region": geo.get("region") or dossier["ioc"].get("geo", {}).get("region") or "",
        "isp": geo.get("isp") or dossier["ioc"].get("geo", {}).get("isp") or "",
        "organization": geo.get("organization") or dossier["ioc"].get("geo", {}).get("organization") or "",
        "asn": geo.get("asn") or geo.get("as") or "",
        "latitude": geo.get("latitude") if geo.get("latitude") is not None else dossier["ioc"].get("geo", {}).get("latitude"),
        "longitude": geo.get("longitude") if geo.get("longitude") is not None else dossier["ioc"].get("geo", {}).get("longitude"),
    }
    geo_payload["location_name"] = (
        ", ".join(part for part in [geo_payload.get("city"), geo_payload.get("country")] if part)
        or "Unknown location"
    )

    sightings = {
        **(dossier["ioc"].get("source_breakdown") or {}),
        "total": sum((dossier["ioc"].get("source_breakdown") or {}).values()),
    }

    return {
        "success": True,
        "lookup": {
            "ip": normalized_ip,
            "threat_level": intel.get("threat_level") or dossier["ioc"].get("latest_threat_level"),
            "risk_score": intel.get("aggregated_score", 0),
            "recommendation": intel.get("recommendation") or "allow",
            "source_count": len(providers),
            "source_confidence": dossier["ioc"].get("source_confidence"),
            "source_confidence_label": dossier["ioc"].get("source_confidence_label"),
            "threat_actor_tags": dossier["ioc"].get("threat_actor_tags") or [],
            "geo": geo_payload,
        },
        "providers": providers,
        "sightings": sightings,
        "related": {
            "domains": related_domains,
            "networks": related_networks,
            "organizations": related_organizations,
        },
        "recent_events": _sorted_recent_events(recent_events)[:16],
        "community": dossier["community"][:10],
        "scan_history": dossier["scan_history"][:10],
        "observations": dossier["observations"][:10],
        "pivots": {
            "ioc_details_path": _build_ioc_href("ip", normalized_ip),
            "correlation_path": f"/correlation/ip/{quote(normalized_ip, safe='')}",
            "map_path": "/propagation",
        },
    }


@router.get("/domain-lookup/{domain:path}")
def domain_lookup(
    domain: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    normalized_domain = _normalize_domain(domain)
    if not normalized_domain or "." not in normalized_domain:
        raise HTTPException(status_code=400, detail="A valid domain is required.")

    rdap = _lookup_rdap(normalized_domain)
    dns_records = _lookup_dns_records(normalized_domain)
    related_ips = _unique_values(*(dns_records.get("a") or []))
    url_intel = aggregate_url_intel(f"https://{normalized_domain}")
    provider_sources = []
    for item in url_intel.get("sources", []):
        source_name = item.get("source") or "Unknown source"
        confidence_score = _source_confidence(source_name)
        provider_sources.append(
            {
                "source": source_name,
                "status": "error" if item.get("error") else "ok",
                "score": item.get("score"),
                "summary": _provider_summary(item),
                "confidence_score": round(confidence_score, 2),
                "confidence_label": _confidence_label(confidence_score),
                "raw": item,
            }
        )

    scan_matches = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == current_user.id,
            ScanHistory.threat_level.in_(["suspicious", "threat", "dangerous"]),
        )
        .order_by(ScanHistory.created_at.desc())
        .limit(120)
        .all()
    )
    matching_scans = [
        item
        for item in scan_matches
        if normalized_domain in _normalize_indicator(item.scan_type, item.indicator)
        or normalized_domain in str((item.result or {}).get("summary") or "").lower()
    ][:18]

    community_matches = [
        item
        for item in db.query(CommunityThreat).order_by(CommunityThreat.published_at.desc()).limit(200).all()
        if normalized_domain in _normalize_indicator(item.threat_type, item.indicator)
        or normalized_domain in str(item.description or "").lower()
        or normalized_domain in str(item.title or "").lower()
    ][:18]

    analysis_matches = (
        db.query(EmailAnalysis)
        .filter(
            EmailAnalysis.user_id == current_user.id,
            EmailAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
        )
        .order_by(EmailAnalysis.created_at.desc())
        .limit(80)
        .all()
    )
    matching_analyses = [
        item
        for item in analysis_matches
        if normalized_domain in " ".join(
            [
                str(item.content or "").lower(),
                str(item.sender or "").lower(),
                str(item.subject or "").lower(),
            ]
        )
    ][:12]

    age_days = rdap.get("age_days")
    brand_impersonation = detect_brand_impersonation(normalized_domain, age_days=age_days)
    related_ip_payload = []
    for ip_value in related_ips[:6]:
        related_ip_payload.append(
            {
                "ip": ip_value,
                "lookup_path": _build_ip_lookup_href(ip_value),
                "ioc_path": _build_ioc_href("ip", ip_value),
            }
        )

    risk_score = int(url_intel.get("aggregated_score") or 0)
    if age_days is not None and age_days <= 30:
        risk_score = min(100, risk_score + 12)
    if brand_impersonation.get("active"):
        risk_score = min(100, max(risk_score, int(brand_impersonation.get("score", 0))))

    threat_level = url_intel.get("threat_level") or ("suspicious" if risk_score >= 25 else "safe")
    if brand_impersonation.get("threat_level") == "threat":
        threat_level = "threat"
    elif brand_impersonation.get("active") and threat_level == "safe":
        threat_level = "suspicious"
    actor_tags = _threat_actor_tags(
        normalized_domain,
        " ".join(
            [
                str(item.summary or "") for item in matching_scans
            ]
            + [str(item.description or item.title or "") for item in community_matches]
            + [str(item.summary or "") for item in matching_analyses]
        ),
        " ".join(provider.get("source", "") for provider in provider_sources),
        "domain",
    )

    recent_events = []
    for item in matching_scans[:8]:
        recent_events.append(
            {
                "event_type": "scan",
                "title": f"{str(item.scan_type).upper()} scan",
                "summary": item.summary or "Domain surfaced in scan history.",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
                "path": _build_ioc_href(item.scan_type, item.indicator),
            }
        )
    for item in community_matches[:8]:
        recent_events.append(
            {
                "event_type": "community",
                "title": item.indicator,
                "summary": item.description or item.title or "Domain surfaced in public community intelligence.",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.published_at),
                "path": _build_ioc_href(item.threat_type, item.indicator),
            }
        )
    for item in matching_analyses[:6]:
        recent_events.append(
            {
                "event_type": "analysis",
                "title": item.subject or item.sender or "Analysis match",
                "summary": item.summary or "Domain surfaced in an analysis flow.",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
                "path": "/investigation-center/analysis",
            }
        )

    return {
        "success": True,
        "lookup": {
            "domain": normalized_domain,
            "registrar": rdap.get("registrar") or "Unknown",
            "created_at": rdap.get("created_at"),
            "age_days": age_days,
            "threat_level": threat_level,
            "risk_score": risk_score,
            "recommendation": url_intel.get("recommendation") or ("quarantine" if risk_score >= 25 else "allow"),
            "source_count": len(provider_sources),
            "source_confidence": round(
                sum(item["confidence_score"] for item in provider_sources) / max(1, len(provider_sources)),
                2,
            ) if provider_sources else 0.6,
            "source_confidence_label": _confidence_label(
                sum(item["confidence_score"] for item in provider_sources) / max(1, len(provider_sources))
            ) if provider_sources else "moderate",
            "threat_actor_tags": actor_tags,
            "brand_impersonation": brand_impersonation,
        },
        "dns": dns_records,
        "providers": provider_sources,
        "related_ips": related_ip_payload,
        "sightings": {
            "scan_history": len(matching_scans),
            "community": len(community_matches),
            "analyses": len(matching_analyses),
            "total": len(matching_scans) + len(community_matches) + len(matching_analyses),
        },
        "recent_events": _sorted_recent_events(recent_events)[:16],
        "pivots": {
            "ioc_details_path": _build_ioc_href("domain", normalized_domain),
            "correlation_path": f"/correlation/domain/{quote(normalized_domain, safe='')}",
        },
        "brand_impersonation": brand_impersonation,
    }


@router.post("/email-header/analyze")
def analyze_email_header(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    raw_headers = str(payload.get("headers") or "").strip()
    if not raw_headers:
        raise HTTPException(status_code=400, detail="Email headers are required.")

    parsed = Parser().parsestr(raw_headers)
    received_headers = parsed.get_all("Received", []) or []
    auth_blob = " ".join(
        [
            raw_headers,
            " ".join(parsed.get_all("Authentication-Results", []) or []),
            " ".join(parsed.get_all("Received-SPF", []) or []),
        ]
    )

    from_header = parsed.get("From", "")
    reply_to_header = parsed.get("Reply-To", "")
    return_path_header = parsed.get("Return-Path", "")
    message_id_header = parsed.get("Message-ID", "")
    subject_header = parsed.get("Subject", "")

    from_domain = _extract_domain_from_address(from_header)
    reply_to_domain = _extract_domain_from_address(reply_to_header)
    return_path_domain = _extract_domain_from_address(return_path_header)
    extracted_ips = _extract_ips_from_received(received_headers)
    origin_ip = extracted_ips[-1] if extracted_ips else ""
    header_domains = _unique_values(
        from_domain,
        reply_to_domain,
        return_path_domain,
        *[
            _normalize_domain(item)
            for item in re.findall(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}", raw_headers)
        ],
    )

    spf_status = _extract_auth_value(auth_blob, "spf")
    dkim_status = _extract_auth_value(auth_blob, "dkim")
    dmarc_status = _extract_auth_value(auth_blob, "dmarc")

    findings = []
    risk_score = 8
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        findings.append("Reply-To domain does not match the visible sender domain.")
        risk_score += 22
    if from_domain and return_path_domain and from_domain != return_path_domain:
        findings.append("Return-Path domain does not match the visible sender domain.")
        risk_score += 18
    if spf_status in {"fail", "softfail", "temperror", "permerror"}:
        findings.append(f"SPF returned {spf_status}.")
        risk_score += 24
    if dkim_status in {"fail", "temperror", "permerror", "none"}:
        findings.append(f"DKIM returned {dkim_status}.")
        risk_score += 18
    if dmarc_status in {"fail", "temperror", "permerror", "none"}:
        findings.append(f"DMARC returned {dmarc_status}.")
        risk_score += 20
    if origin_ip:
        findings.append(f"Origin IP extracted from Received chain: {origin_ip}.")
        risk_score += 6
    if len(received_headers) <= 1:
        findings.append("Very short Received chain may indicate limited delivery context.")
        risk_score += 8

    risk_score = min(100, risk_score)
    if risk_score >= 65:
        threat_level = "threat"
        recommendation = "quarantine"
    elif risk_score >= 30:
        threat_level = "suspicious"
        recommendation = "review"
    else:
        threat_level = "safe"
        recommendation = "allow"

    domain_pivots = [
        {
            "domain": item,
            "lookup_path": _build_domain_lookup_href(item),
            "ioc_path": _build_ioc_href("domain", item),
        }
        for item in header_domains[:8]
    ]
    ip_pivots = [
        {
            "ip": item,
            "lookup_path": _build_ip_lookup_href(item),
            "ioc_path": _build_ioc_href("ip", item),
        }
        for item in extracted_ips[:8]
    ]

    related_analyses = []
    if from_domain:
        related_analyses = (
            db.query(EmailAnalysis)
            .filter(
                EmailAnalysis.user_id == current_user.id,
                EmailAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
                EmailAnalysis.sender.ilike(f"%{from_domain}%"),
            )
            .order_by(EmailAnalysis.created_at.desc())
            .limit(8)
            .all()
        )

    return {
        "success": True,
        "analysis": {
            "subject": subject_header,
            "message_id": message_id_header,
            "from": from_header,
            "reply_to": reply_to_header,
            "return_path": return_path_header,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "origin_ip": origin_ip,
            "threat_level": threat_level,
            "risk_score": risk_score,
            "recommendation": recommendation,
            "summary": " ".join(findings[:3]) or "Header analysis did not reveal high-risk misalignment.",
        },
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
        },
        "received_chain": received_headers,
        "findings": findings,
        "pivot_domains": domain_pivots,
        "pivot_ips": ip_pivots,
        "related_analyses": [
            {
                "id": item.id,
                "channel": item.channel,
                "subject": item.subject,
                "sender": item.sender or item.phone_number,
                "summary": item.summary or "",
                "threat_level": _normalize_level(item.threat_level),
                "created_at": _iso(item.created_at),
            }
            for item in related_analyses
        ],
        "pivots": {
            "lookup_center_path": _build_header_analyzer_href(),
        },
    }


@router.get("/correlation/{ioc_type}/{indicator:path}")
def correlation_graph(
    ioc_type: str,
    indicator: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    details = ioc_details(ioc_type=ioc_type, indicator=indicator, db=db, current_user=current_user)
    nodes = [
        {
            "id": f"ioc:{ioc_type}:{indicator}",
            "label": indicator,
            "type": ioc_type,
            "group": "indicator",
            "threat_level": details["ioc"]["latest_threat_level"],
        }
    ]
    edges = []

    for scan in details["scan_history"]:
        node_id = f"scan:{scan['id']}"
        nodes.append(
            {
                "id": node_id,
                "label": f"{str(scan['scan_type']).upper()} scan",
                "type": "scan",
                "group": "scanner",
                "summary": scan.get("summary"),
            }
        )
        edges.append({"from": f"ioc:{ioc_type}:{indicator}", "to": node_id, "label": "scanned"})

    for item in details["community"]:
        node_id = f"community:{item['id']}"
        nodes.append(
            {
                "id": node_id,
                "label": "Community publication",
                "type": "community",
                "group": "community",
                "summary": item.get("summary"),
            }
        )
        edges.append({"from": f"ioc:{ioc_type}:{indicator}", "to": node_id, "label": "published"})

    for item in details["analyses"]:
        node_id = f"analysis:{item['id']}"
        nodes.append(
            {
                "id": node_id,
                "label": item.get("subject") or item.get("sender") or "Analysis",
                "type": "analysis",
                "group": "analysis",
                "summary": item.get("summary"),
            }
        )
        edges.append({"from": f"ioc:{ioc_type}:{indicator}", "to": node_id, "label": "mentioned"})

    for item in details["media"]:
        node_id = f"media:{item['id']}"
        nodes.append(
            {
                "id": node_id,
                "label": item.get("filename") or "Media",
                "type": "media",
                "group": "media",
                "summary": item.get("summary"),
            }
        )
        edges.append({"from": f"ioc:{ioc_type}:{indicator}", "to": node_id, "label": "extracted"})

    for item in details["ioc"]["threat_actor_tags"]:
        node_id = f"tag:{item['tag']}"
        nodes.append(
            {
                "id": node_id,
                "label": item["tag"],
                "type": "actor_tag",
                "group": "tag",
                "confidence": item["confidence"],
            }
        )
        edges.append({"from": f"ioc:{ioc_type}:{indicator}", "to": node_id, "label": "tagged"})

    seen_nodes = {}
    for node in nodes:
        seen_nodes[node["id"]] = node

    return {
        "success": True,
        "nodes": list(seen_nodes.values()),
        "edges": edges,
        "ioc": details["ioc"],
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


def _collect_recent_signal_events(
    db: Session,
    current_user: User,
    limit: int = 180,
    include_private: bool = True,
) -> list[dict]:
    events = []

    if include_private:
        for item in (
            db.query(ScanHistory)
            .filter(
                ScanHistory.user_id == current_user.id,
                ScanHistory.threat_level.in_(["suspicious", "threat", "dangerous"]),
            )
            .order_by(ScanHistory.created_at.desc())
            .limit(limit)
            .all()
        ):
            events.append(_build_scan_event(item))

    for item in (
        db.query(CommunityThreat)
        .filter(
            CommunityThreat.is_moderated == True,
            CommunityThreat.threat_level.in_(["suspicious", "threat", "dangerous"]),
        )
        .order_by(CommunityThreat.published_at.desc())
        .limit(limit)
        .all()
    ):
        events.append(_build_community_event(item))

    if include_private:
        for item in (
            db.query(EmailAnalysis)
            .filter(
                EmailAnalysis.user_id == current_user.id,
                EmailAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
            )
            .order_by(EmailAnalysis.created_at.desc())
            .limit(limit)
            .all()
        ):
            events.append(_build_analysis_event(item))

    if include_private:
        for item in (
            db.query(MediaAnalysis)
            .filter(
                MediaAnalysis.user_id == current_user.id,
                MediaAnalysis.threat_level.in_(["suspicious", "threat", "dangerous"]),
            )
            .order_by(MediaAnalysis.created_at.desc())
            .limit(limit)
            .all()
        ):
            events.append(_build_media_event(item))

    return _dedupe_events(events)[:limit]


def _build_signal_clusters(events: list[dict]) -> list[dict]:
    clusters: dict[str, dict] = {}

    for event in events:
        tags = event.get("actor_tags") or []
        sources = event.get("source") or event.get("event_type") or "intel"
        country = event.get("country") or "Unknown"
        ioc_type = event.get("ioc_type") or "signal"
        indicator = event.get("indicator") or event.get("title") or "signal"
        primary_tag = tags[0]["tag"] if tags else ""

        if primary_tag:
            cluster_id = f"tag:{primary_tag.lower().replace(' ', '-')}"
            label = primary_tag
        else:
            cluster_id = f"{ioc_type}:{country.lower()}:{str(sources).lower()}"
            label = f"{str(ioc_type).upper()} activity"

        cluster = clusters.setdefault(
            cluster_id,
            {
                "id": cluster_id,
                "label": label,
                "latest_threat_level": "safe",
                "max_risk_score": 0,
                "latest_seen": event.get("created_at"),
                "signal_count": 0,
                "sources": set(),
                "countries": set(),
                "actor_tags": set(),
                "related_indicators": [],
                "events": [],
                "details_path": f"/campaign-clusters?cluster={quote(cluster_id, safe='')}",
            },
        )

        cluster["signal_count"] += 1
        cluster["max_risk_score"] = max(cluster["max_risk_score"], int(event.get("risk_score") or 0))
        cluster["sources"].add(str(sources))
        if country and country != "Unknown":
            cluster["countries"].add(country)
        for tag in tags:
            if tag.get("tag"):
                cluster["actor_tags"].add(tag["tag"])
        if indicator and indicator not in cluster["related_indicators"]:
            cluster["related_indicators"].append(indicator)
        cluster["events"].append(
            {
                "id": event.get("id"),
                "title": event.get("title") or indicator,
                "indicator": indicator,
                "ioc_type": ioc_type,
                "source": sources,
                "summary": event.get("summary") or "",
                "threat_level": event.get("threat_level") or "unknown",
                "risk_score": event.get("risk_score") or 0,
                "created_at": event.get("created_at"),
                "details_path": event.get("details_path") or "",
            }
        )
        if event.get("created_at") and (cluster["latest_seen"] or "") < event.get("created_at", ""):
            cluster["latest_seen"] = event.get("created_at")
        if _normalize_level(event.get("threat_level")) == "threat":
            cluster["latest_threat_level"] = "threat"
        elif (
            _normalize_level(event.get("threat_level")) == "suspicious"
            and cluster["latest_threat_level"] != "threat"
        ):
            cluster["latest_threat_level"] = "suspicious"

    items = []
    for cluster in clusters.values():
        sources = sorted(cluster["sources"])
        countries = sorted(cluster["countries"])
        actor_tags = sorted(cluster["actor_tags"])
        related_indicators = cluster["related_indicators"][:8]
        items.append(
            {
                "id": cluster["id"],
                "label": cluster["label"],
                "summary": (
                    f"{cluster['signal_count']} related signals across {len(sources)} sources"
                    + (f" with country focus on {', '.join(countries[:2])}" if countries else "")
                    + "."
                ),
                "latest_threat_level": cluster["latest_threat_level"],
                "max_risk_score": cluster["max_risk_score"],
                "latest_seen": cluster["latest_seen"],
                "signal_count": cluster["signal_count"],
                "sources": sources,
                "countries": countries,
                "actor_tags": actor_tags,
                "related_indicators": related_indicators,
                "events": _sorted_recent_events(cluster["events"])[:12],
                "details_path": cluster["details_path"],
            }
        )

    return sorted(
        items,
        key=lambda item: (item["signal_count"], item["max_risk_score"], item["latest_seen"] or ""),
        reverse=True,
    )


@router.get("/trending-indicators")
def trending_indicators(
    time_range: str = "30d",
    limit: int = Query(default=12, ge=1, le=40),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = _parse_time_range(time_range)
    events = _collect_recent_signal_events(db, current_user, limit=240, include_private=False)
    buckets: dict[tuple[str, str], dict] = {}

    for event in events:
        created_at = datetime.fromisoformat(event["created_at"]) if event.get("created_at") else None
        if not _in_range(created_at, cutoff):
            continue
        indicator = (event.get("indicator") or "").strip()
        ioc_type = (event.get("ioc_type") or "").strip().lower()
        if not indicator or ioc_type not in {"ip", "url", "hash", "domain", "file", "email", "phone"}:
            continue

        key = (ioc_type, _normalize_indicator(ioc_type, indicator))
        item = buckets.setdefault(
            key,
            {
                "indicator": indicator,
                "ioc_type": ioc_type,
                "sightings": 0,
                "latest_threat_level": "safe",
                "max_risk_score": 0,
                "latest_seen": event.get("created_at"),
                "sources": set(),
                "countries": set(),
                "details_path": event.get("details_path") or _build_ioc_href(ioc_type, indicator),
            },
        )
        item["sightings"] += 1
        item["max_risk_score"] = max(item["max_risk_score"], int(event.get("risk_score") or 0))
        item["sources"].add(str(event.get("source") or event.get("event_type") or "intel"))
        if event.get("country"):
            item["countries"].add(str(event.get("country")))
        if event.get("created_at") and (item["latest_seen"] or "") < event.get("created_at", ""):
            item["latest_seen"] = event.get("created_at")
        if _normalize_level(event.get("threat_level")) == "threat":
            item["latest_threat_level"] = "threat"
        elif (
            _normalize_level(event.get("threat_level")) == "suspicious"
            and item["latest_threat_level"] != "threat"
        ):
            item["latest_threat_level"] = "suspicious"

    items = [
        {
            **value,
            "sources": sorted(value["sources"]),
            "countries": sorted(value["countries"]),
        }
        for value in buckets.values()
    ]
    items = sorted(
        items,
        key=lambda item: (item["sightings"], item["max_risk_score"], item["latest_seen"] or ""),
        reverse=True,
    )[:limit]
    return {"success": True, "items": items}


@router.get("/public-incident-briefs")
def public_incident_briefs(
    limit: int = Query(default=6, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    clusters = _build_signal_clusters(
        _collect_recent_signal_events(db, current_user, limit=220, include_private=False)
    )
    briefs = []
    for cluster in clusters[:limit]:
        briefs.append(
            {
                "id": cluster["id"],
                "title": f"{cluster['label']} brief",
                "summary": cluster["summary"],
                "latest_threat_level": cluster["latest_threat_level"],
                "signal_count": cluster["signal_count"],
                "max_risk_score": cluster["max_risk_score"],
                "latest_seen": cluster["latest_seen"],
                "sources": cluster["sources"][:4],
                "countries": cluster["countries"][:4],
                "actor_tags": cluster["actor_tags"][:4],
                "related_indicators": cluster["related_indicators"][:5],
                "details_path": cluster["details_path"],
            }
        )
    return {"success": True, "items": briefs}


@router.get("/campaign-clusters")
def campaign_clusters(
    cluster: str | None = None,
    limit: int = Query(default=12, ge=1, le=40),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items = _build_signal_clusters(
        _collect_recent_signal_events(db, current_user, limit=260, include_private=False)
    )[:limit]
    selected = next((item for item in items if item["id"] == (cluster or "").strip()), None)
    if selected is None and items:
        selected = items[0]
    return {"success": True, "items": items, "selected": selected}


@router.get("/jobs/status")
def background_jobs_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    recent_runs = (
        db.query(BackgroundJobRun)
        .order_by(BackgroundJobRun.started_at.desc())
        .limit(20)
        .all()
    )
    latest_by_job = {}
    for item in recent_runs:
        latest_by_job.setdefault(item.job_name, item)

    retry_tasks = (
        db.query(EnrichmentRetryTask)
        .filter(EnrichmentRetryTask.status == "pending")
        .order_by(EnrichmentRetryTask.created_at.desc())
        .all()
    )

    jobs = [
        {
            "job_name": item.job_name,
            "status": item.status,
            "message": item.message,
            "started_at": _iso(item.started_at),
            "finished_at": _iso(item.finished_at),
            "stats": item.stats or {},
        }
        for item in latest_by_job.values()
    ]

    return {
        "success": True,
        "jobs": sorted(jobs, key=lambda item: item["job_name"]),
        "retry_queue": [
            {
                "id": task.id,
                "source": task.source,
                "task_type": task.task_type,
                "attempts": task.attempts or 0,
                "last_error": task.last_error,
                "created_at": _iso(task.created_at),
            }
            for task in retry_tasks
        ],
    }


@router.get("/jobs/history")
def background_jobs_history(
    limit: int = Query(default=30, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items = (
        db.query(BackgroundJobRun)
        .order_by(BackgroundJobRun.started_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "success": True,
        "items": [
            {
                "id": item.id,
                "job_name": item.job_name,
                "status": item.status,
                "message": item.message,
                "stats": item.stats or {},
                "started_at": _iso(item.started_at),
                "finished_at": _iso(item.finished_at),
            }
            for item in items
        ],
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
            path = f"/investigation-center/analysis?result={analysis.id}"

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
def sources_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    pending = (
        db.query(EnrichmentRetryTask)
        .filter(
            EnrichmentRetryTask.status == "pending",
            EnrichmentRetryTask.task_type == "threat_feed",
        )
        .all()
    )
    pending_sources = {item.source: item for item in pending}
    catalog = [
        {"name": "AlienVault OTX", "key": "otx", "type": "ip/url"},
        {"name": "URLhaus", "key": "urlhaus", "type": "url"},
        {"name": "AbuseIPDB", "key": "abuseipdb", "type": "ip"},
        {"name": "PhishTank", "key": "phishtank", "type": "url"},
        {"name": "IBM X-Force", "key": "ibm_xforce", "type": "ip/url"},
        {"name": "CISA KEV", "key": "cisa_kev", "type": "cve"},
    ]
    sources = []
    for item in catalog:
        task = pending_sources.get(item["key"])
        confidence_score = _source_confidence(item["name"])
        sources.append(
            {
                "name": item["name"],
                "key": item["key"],
                "type": item["type"],
                "status": "degraded" if task else "healthy",
                "confidence_score": confidence_score,
                "confidence_label": _confidence_label(confidence_score),
                "retry_attempts": task.attempts if task else 0,
                "last_error": task.last_error if task else None,
            }
        )
    return {"success": True, "sources": sources}


@router.post("/collect-now")
def collect_now(current_user: User = Depends(get_current_user)):
    return {
        "success": True,
        "result": collect_all_intel(),
    }
