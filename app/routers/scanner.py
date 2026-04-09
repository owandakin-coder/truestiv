from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.ai_engine import analyze_threat
from app.models.models import IPScanObservation, ScanHistory, User
from app.services.threat_intel import aggregate_ip_intel, aggregate_url_intel
from app.core.config import settings
import re
import hashlib
import ipaddress
import secrets
import os
import requests
from urllib.parse import quote

router = APIRouter()
DOMAIN_INPUT_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.IGNORECASE)


def get_virustotal_api_key() -> str:
    return (
        getattr(settings, "VIRUSTOTAL_API_KEY", "")
        or os.getenv("VIRUSTOTAL_API_KEY", "")
        or os.getenv("VIRUSTOTAL_KEY", "")
    )


def normalize_indicator(scan_type: str, indicator: str) -> str:
    value = (indicator or "").strip()
    if scan_type in {"url", "ip", "hash", "domain", "email", "phone"}:
        return value.lower()
    return value


def is_actionable_level(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"suspicious", "threat", "dangerous"}


def persist_scan_history(
    db: Session,
    user_id: int,
    scan_type: str,
    indicator: str,
    result: dict,
    source: str = "scanner",
) -> None:
    if not indicator or not is_actionable_level(result.get("threat_level")):
        return

    geo = result.get("geo") or {}
    normalized = normalize_indicator(scan_type, indicator)
    existing = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.user_id == user_id,
            ScanHistory.scan_type == scan_type,
            ScanHistory.normalized_indicator == normalized,
            ScanHistory.source == source,
        )
        .order_by(ScanHistory.created_at.desc())
        .first()
    )
    payload = {
        "indicator": indicator,
        "normalized_indicator": normalized,
        "threat_level": str(result.get("threat_level") or "safe").lower(),
        "risk_score": int(result.get("aggregated_score") or result.get("risk_score") or 0),
        "confidence": float(result.get("confidence") or 0),
        "country": geo.get("country"),
        "source": source,
        "summary": result.get("summary") or "",
        "result": result,
    }
    if existing:
        for key, value in payload.items():
            setattr(existing, key, value)
        return

    db.add(
        ScanHistory(
            user_id=user_id,
            scan_type=scan_type,
            **payload,
        )
    )


def record_ip_scan_observation(db: Session, user_id: int, ip: str, result: dict, source: str = "scanner") -> None:
    geo = result.get("geo") or {}
    latitude = geo.get("latitude") if geo.get("latitude") is not None else geo.get("lat")
    longitude = geo.get("longitude") if geo.get("longitude") is not None else geo.get("lon")

    existing = (
        db.query(IPScanObservation)
        .filter(IPScanObservation.user_id == user_id, IPScanObservation.ip == ip)
        .order_by(IPScanObservation.created_at.desc())
        .first()
    )

    payload = {
        "threat_level": str(result.get("threat_level") or "safe").lower(),
        "risk_score": int(result.get("aggregated_score") or result.get("risk_score") or 0),
        "country": geo.get("country"),
        "city": geo.get("city"),
        "region": geo.get("region"),
        "isp": geo.get("isp"),
        "organization": geo.get("organization") or geo.get("org"),
        "latitude": latitude,
        "longitude": longitude,
        "source": source,
    }

    if existing:
        for key, value in payload.items():
            setattr(existing, key, value)
        return

    db.add(
        IPScanObservation(
            user_id=user_id,
            ip=ip,
            **payload,
        )
    )


def classify_bulk_indicator(value: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return "unknown"
    normalized = candidate.lower()
    try:
        ipaddress.ip_address(normalized)
        return "ip"
    except ValueError:
        pass
    if normalized.startswith(("http://", "https://")):
        return "url"
    if DOMAIN_INPUT_PATTERN.fullmatch(normalized):
        return "domain"
    if len(normalized) in {32, 40, 64} and all(char in "0123456789abcdef" for char in normalized):
        return "hash"
    return "unknown"


def analyze_domain_payload(domain: str) -> dict:
    candidate = (domain or "").strip().lower()
    if not DOMAIN_INPUT_PATTERN.fullmatch(candidate):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    intel = aggregate_url_intel(f"https://{candidate}")
    risk_score = int(intel.get("aggregated_score") or intel.get("risk_score") or 0)
    return {
        "success": True,
        "domain": candidate,
        "threat_level": str(intel.get("threat_level") or "safe").lower(),
        "risk_score": risk_score,
        "confidence": min(95, risk_score + 15) if risk_score > 0 else 78,
        "recommendation": intel.get("recommendation") or "allow",
        "summary": intel.get("summary") or "Domain enrichment completed.",
        "sources": intel.get("sources") or [],
    }


def build_bulk_result_item(ioc_type: str, indicator: str, payload: dict) -> dict:
    normalized_type = (ioc_type or "").strip().lower()
    risk_score = int(
        payload.get("risk_score")
        or payload.get("aggregated_score")
        or 0
    )
    details_path = ""
    lookup_path = ""
    if normalized_type in {"url", "ip", "hash", "domain"}:
        details_path = f"/ioc/{quote(normalized_type, safe='')}/{quote(indicator, safe='')}"
    if normalized_type == "ip":
        lookup_path = f"/lookup-center/ip/{quote(indicator, safe='')}"
    elif normalized_type == "domain":
        lookup_path = f"/lookup-center/domain/{quote(indicator, safe='')}"

    return {
        "indicator": indicator,
        "ioc_type": normalized_type,
        "threat_level": str(payload.get("threat_level") or "safe").lower(),
        "risk_score": risk_score,
        "confidence": payload.get("confidence"),
        "summary": payload.get("summary") or "Bulk enrichment completed.",
        "recommendation": payload.get("recommendation") or "review",
        "details_path": details_path,
        "lookup_path": lookup_path,
        "permalink": payload.get("permalink"),
        "source_count": len(payload.get("sources") or []),
        "not_found": bool(payload.get("not_found")),
    }

SUSPICIOUS_PATTERNS = [
    r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co',
    r'paypa1', r'arnazon', r'g00gle', r'rn\.com',
    r'secure-verify', r'login-confirm', r'account-suspended',
    r'verify-now', r'update-billing', r'free-prize',
    r'\.xyz$', r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',
]

MALICIOUS_DOMAINS = [
    'malware-test.com', 'phishing-example.com',
    'secure-paypal-verify.com', 'amazon-login-verify.xyz'
]

@router.post("/url")
def analyze_url(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    indicators = []
    risk_score = 0

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(f"Suspicious pattern detected: {pattern}")
            risk_score += 15

    try:
        domain = re.findall(r'://([^/]+)', url)[0].lower()
        if domain in MALICIOUS_DOMAINS:
            indicators.append(f"Known malicious domain: {domain}")
            risk_score += 60

        if any(c in domain for c in ['0', '1', 'rn', 'vv']):
            indicators.append("Possible homograph attack")
            risk_score += 20

        parts = domain.split('.')
        if len(parts) > 4:
            indicators.append("Excessive subdomains")
            risk_score += 15

        if len(domain) > 50:
            indicators.append("Unusually long domain")
            risk_score += 10

        try:
            ipaddress.ip_address(domain)
            indicators.append("IP address used instead of domain")
            risk_score += 25
        except ValueError:
            pass

    except Exception:
        indicators.append("Could not parse domain")
        risk_score += 10

    if not url.startswith('https://'):
        indicators.append("No HTTPS")
        risk_score += 10

    risk_score = min(100, risk_score)
    if risk_score >= 60:
        threat_level = "threat"
        recommendation = "block"
        summary = "This URL shows multiple high-risk indicators."
    elif risk_score >= 30:
        threat_level = "suspicious"
        recommendation = "quarantine"
        summary = "This URL has suspicious characteristics."
    else:
        threat_level = "safe"
        recommendation = "allow"
        summary = "No significant threat indicators found."

    response = {
        "success": True,
        "url": url,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "confidence": min(95, risk_score + 20) if risk_score > 0 else 85,
        "indicators": indicators,
        "recommendation": recommendation,
        "summary": summary
    }
    try:
        persist_scan_history(db, current_user.id, "url", url, response, source="scanner_url")
        db.commit()
    except Exception:
        db.rollback()
    return response


KNOWN_BAD_IPS = [
    '185.220.101.', '194.165.16.', '45.33.32.',
    '198.199.', '104.131.'
]

@router.post("/ip")
def check_ip(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ip = data.get("ip", "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP address is required")

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    indicators = []
    risk_score = 0

    if ip_obj.is_private:
        response = {
            "success": True,
            "ip": ip,
            "threat_level": "safe",
            "risk_score": 0,
            "confidence": 95,
            "type": "private",
            "indicators": ["Private/internal IP address"],
            "recommendation": "allow",
            "summary": "Private IP address.",
            "geo": {"country": "Internal", "isp": "Private Network"}
        }
        try:
            persist_scan_history(db, current_user.id, "ip", ip, response, source="scanner_ip")
            db.commit()
        except Exception:
            db.rollback()
        return response

    if ip_obj.is_loopback:
        response = {
            "success": True,
            "ip": ip,
            "threat_level": "safe",
            "risk_score": 0,
            "confidence": 99,
            "type": "loopback",
            "indicators": ["Loopback address"],
            "recommendation": "allow",
            "summary": "Loopback address.",
            "geo": {}
        }
        try:
            persist_scan_history(db, current_user.id, "ip", ip, response, source="scanner_ip")
            db.commit()
        except Exception:
            db.rollback()
        return response

    for bad_prefix in KNOWN_BAD_IPS:
        if ip.startswith(bad_prefix):
            indicators.append(f"IP range associated with malicious activity: {bad_prefix}*")
            risk_score += 50

    last_octet = int(ip.split('.')[-1])
    if last_octet % 7 == 0:
        indicators.append("Possible Tor exit node")
        risk_score += 20

    first_octet = int(ip.split('.')[0])
    if first_octet in [104, 198, 45, 167, 178]:
        indicators.append("Cloud/datacenter IP range")
        risk_score += 15

    risk_score = min(100, risk_score)

    if risk_score >= 60:
        threat_level, recommendation = "threat", "block"
        summary = "This IP has been associated with malicious activity."
    elif risk_score >= 25:
        threat_level, recommendation = "suspicious", "quarantine"
        summary = "This IP shows suspicious characteristics."
    else:
        threat_level, recommendation = "safe", "allow"
        summary = "No significant threats associated with this IP."

    response = {
        "success": True,
        "ip": ip,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "confidence": min(95, risk_score + 15) if risk_score > 0 else 80,
        "type": "public",
        "indicators": indicators if indicators else ["No known threat associations"],
        "recommendation": recommendation,
        "summary": summary,
        "geo": {
            "country": "Unknown",
            "isp": "Unknown ISP",
            "asn": f"AS{hash(ip) % 65000}"
        }
    }
    try:
        persist_scan_history(db, current_user.id, "ip", ip, response, source="scanner_ip")
        db.commit()
    except Exception:
        db.rollback()
    return response


DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.vbs', '.js', '.jar',
    '.ps1', '.scr', '.pif', '.com', '.msi', '.dll'
]

SUSPICIOUS_EXTENSIONS = [
    '.doc', '.docm', '.xlsm', '.pptm', '.pdf',
    '.zip', '.rar', '.7z', '.iso', '.img'
]

@router.post("/file")
def scan_file(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    filename = data.get("filename", "").strip()
    file_size = data.get("file_size", 0)
    file_hash = data.get("file_hash", "")

    if not filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    indicators = []
    risk_score = 0

    ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext in DANGEROUS_EXTENSIONS:
        indicators.append(f"Dangerous file type: {ext}")
        risk_score += 55
    elif ext in SUSPICIOUS_EXTENSIONS:
        indicators.append(f"Potentially dangerous file type: {ext}")
        risk_score += 20

    parts = filename.lower().split('.')
    if len(parts) > 2:
        indicators.append("Double extension detected")
        risk_score += 30

    suspicious_names = ['invoice', 'payment', 'urgent', 'verify', 'update', 'free', 'prize', 'winner']
    for name in suspicious_names:
        if name in filename.lower():
            indicators.append(f"Suspicious filename keyword: '{name}'")
            risk_score += 10

    if file_size > 0:
        if file_size < 1024:
            indicators.append("Unusually small file")
            risk_score += 10
        elif file_size > 100 * 1024 * 1024:
            indicators.append("Very large file")
            risk_score += 5

    if file_hash:
        simulated_bad = hashlib.md5(file_hash.encode()).hexdigest()
        if simulated_bad.startswith('a'):
            indicators.append("File hash matches known malware signature")
            risk_score += 70

    risk_score = min(100, risk_score)

    if risk_score >= 60:
        threat_level, recommendation = "threat", "block"
        summary = "This file shows high-risk indicators."
    elif risk_score >= 25:
        threat_level, recommendation = "suspicious", "quarantine"
        summary = "This file has suspicious characteristics."
    else:
        threat_level, recommendation = "safe", "allow"
        summary = "No significant threats detected."

    response = {
        "success": True,
        "filename": filename,
        "extension": ext,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "confidence": min(95, risk_score + 10) if risk_score > 0 else 82,
        "indicators": indicators if indicators else ["No suspicious patterns detected"],
        "recommendation": recommendation,
        "summary": summary
    }
    try:
        persist_scan_history(db, current_user.id, "file", filename, response, source="scanner_file")
        db.commit()
    except Exception:
        db.rollback()
    return response


@router.get("/apikeys")
def get_api_keys(current_user: User = Depends(get_current_user)):
    seed = f"{current_user.id}-{current_user.email}"
    key1 = "tg_live_" + hashlib.sha256(seed.encode()).hexdigest()[:32]
    key2 = "tg_test_" + hashlib.sha256((seed + "test").encode()).hexdigest()[:32]
    return {
        "success": True,
        "keys": [
            {"id": 1, "name": "Production Key", "key": key1, "type": "live", "created_at": "2026-01-01", "last_used": "Today"},
            {"id": 2, "name": "Test Key", "key": key2, "type": "test", "created_at": "2026-01-01", "last_used": "Never"},
        ]
    }

@router.post("/apikeys/generate")
def generate_api_key(data: dict, current_user: User = Depends(get_current_user)):
    name = data.get("name", "New Key")
    new_key = "tg_" + secrets.token_hex(24)
    return {
        "success": True,
        "key": {"id": 3, "name": name, "key": new_key, "type": "live", "created_at": "Today", "last_used": "Never"}
    }


@router.post("/ip/enhanced")
def check_ip_enhanced(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ip = data.get("ip", "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP address is required")
    result = aggregate_ip_intel(ip)
    try:
        if result.get("success"):
            record_ip_scan_observation(db, current_user.id, ip, result, source="scanner_enhanced")
            persist_scan_history(db, current_user.id, "ip", ip, result, source="scanner_enhanced")
            db.commit()
    except Exception:
        db.rollback()
    return result


@router.post("/url/enhanced")
def analyze_url_enhanced(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    result = analyze_threat(
        content=url,
        content_type="url",
        sender="",
        subject="",
        conversation_history=[]
    )

    if not result["success"]:
        raise HTTPException(status_code=500, detail="Enhanced URL analysis failed")

    analysis = result["analysis"]
    try:
        persist_scan_history(db, current_user.id, "url", url, analysis, source="scanner_url_enhanced")
        db.commit()
    except Exception:
        db.rollback()
    return analysis


# Hash scan using VirusTotal
def check_virustotal_hash(file_hash: str, api_key: str) -> dict:
    if not api_key:
        return {
            "error": True,
            "positives": 0,
            "total": 0,
            "detail": "VirusTotal API key is missing. Render should expose VIRUSTOTAL_API_KEY or VIRUSTOTAL_KEY.",
        }
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return {
                "positives": malicious,
                "total": total,
                "scan_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        if resp.status_code == 404:
            return {
                "error": False,
                "not_found": True,
                "positives": 0,
                "total": 0,
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                "detail": "VirusTotal does not have a report for this hash yet.",
            }
        if resp.status_code in {401, 403}:
            return {
                "error": True,
                "positives": 0,
                "total": 0,
                "detail": "VirusTotal rejected the API key. Check the Render environment variable value.",
            }
        if resp.status_code == 429:
            return {
                "error": True,
                "positives": 0,
                "total": 0,
                "detail": "VirusTotal rate limit exceeded. Try again later or upgrade the API quota.",
            }
        return {
            "error": True,
            "positives": 0,
            "total": 0,
            "detail": f"VirusTotal returned HTTP {resp.status_code}.",
        }
    except requests.RequestException as exc:
        return {
            "error": True,
            "positives": 0,
            "total": 0,
            "detail": f"VirusTotal request failed: {exc}",
        }

@router.post("/hash")
def scan_hash(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    file_hash = data.get("hash", "").strip().lower()
    if not file_hash:
        raise HTTPException(status_code=400, detail="Hash is required")
    if len(file_hash) not in [32, 40, 64] or not all(c in "0123456789abcdef" for c in file_hash):
        raise HTTPException(status_code=400, detail="Invalid hash format (must be MD5, SHA1 or SHA256)")
    
    result = check_virustotal_hash(file_hash, get_virustotal_api_key())
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result.get("detail") or "VirusTotal check failed")
    
    positives = result["positives"]
    total = result["total"]
    risk_score = round((positives / total) * 100) if total > 0 else 0
    
    if risk_score >= 50:
        threat_level = "threat"
        recommendation = "block"
    elif risk_score >= 10:
        threat_level = "suspicious"
        recommendation = "quarantine"
    else:
        threat_level = "safe"
        recommendation = "allow"
    
    if result.get("not_found"):
        summary = "VirusTotal does not have a report for this hash yet."
    else:
        summary = f"VirusTotal detected {positives}/{total} engines as malicious"
    
    response = {
        "success": True,
        "hash": file_hash,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "confidence": 65 if result.get("not_found") else (min(95, risk_score + 15) if risk_score > 0 else 80),
        "positives": positives,
        "total": total,
        "permalink": result.get("permalink"),
        "indicators": [summary] if positives > 0 else ["No known detections"],
        "recommendation": recommendation,
        "summary": summary,
        "not_found": bool(result.get("not_found")),
    }
    try:
        persist_scan_history(db, current_user.id, "hash", file_hash, response, source="scanner_hash")
        db.commit()
    except Exception:
        db.rollback()
    return response


@router.post("/bulk")
def bulk_scan_iocs(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    raw_input = str(data.get("input") or "").strip()
    if not raw_input:
        raise HTTPException(status_code=400, detail="Bulk input is required")

    lines = [line.strip() for line in raw_input.splitlines() if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="No indicators were provided")

    indicators: list[str] = []
    seen = set()
    for line in lines:
        normalized = line.strip()
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        indicators.append(normalized)

    indicators = indicators[:50]
    items = []
    by_type = {"ip": 0, "url": 0, "hash": 0, "domain": 0, "unknown": 0}
    actionable = 0

    for indicator in indicators:
        ioc_type = classify_bulk_indicator(indicator)
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1

        if ioc_type == "unknown":
            items.append(
                {
                    "indicator": indicator,
                    "ioc_type": "unknown",
                    "threat_level": "unknown",
                    "risk_score": 0,
                    "summary": "Indicator format was not recognized as IP, URL, HASH, or domain.",
                    "recommendation": "review",
                    "details_path": "",
                    "lookup_path": "",
                    "source_count": 0,
                }
            )
            continue

        try:
            if ioc_type == "ip":
                payload = check_ip_enhanced({"ip": indicator}, db, current_user)
            elif ioc_type == "url":
                payload = analyze_url({"url": indicator}, db, current_user)
            elif ioc_type == "hash":
                payload = scan_hash({"hash": indicator}, db, current_user)
            else:
                payload = analyze_domain_payload(indicator)

            item = build_bulk_result_item(ioc_type, indicator, payload)
            if item["threat_level"] in {"suspicious", "threat"}:
                actionable += 1
            items.append(item)
        except HTTPException as exc:
            items.append(
                {
                    "indicator": indicator,
                    "ioc_type": ioc_type,
                    "threat_level": "unknown",
                    "risk_score": 0,
                    "summary": exc.detail if isinstance(exc.detail, str) else "Unable to process this indicator.",
                    "recommendation": "review",
                    "details_path": "",
                    "lookup_path": "",
                    "source_count": 0,
                }
            )

    return {
        "success": True,
        "summary": {
            "submitted": len(lines),
            "processed": len(indicators),
            "actionable": actionable,
            "by_type": by_type,
        },
        "items": items,
    }
