import requests
import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from tenacity import retry, stop_after_attempt, wait_exponential
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.models import CommunityThreat, EnrichmentRetryTask

# Attempt Redis import gracefully
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

VIRUSTOTAL_KEY = (
    getattr(settings, "VIRUSTOTAL_API_KEY", "")
    or os.getenv("VIRUSTOTAL_API_KEY", "")
    or os.getenv("VIRUSTOTAL_KEY", "")
)
ABUSEIPDB_KEY = settings.ABUSEIPDB_API_KEY
GREYNOISE_KEY = settings.GREYNOISE_API_KEY
OTX_KEY = getattr(settings, "OTX_API_KEY", "")
logger = logging.getLogger(__name__)
FAILED_SOURCES_CACHE_KEY = "trustive:intel:failed_sources"

# Redis connection (if available)
redis_client = None
if REDIS_AVAILABLE:
    try:
        redis_client = redis.Redis(
            host=settings.REDIS_HOST if hasattr(settings, "REDIS_HOST") else "localhost",
            port=settings.REDIS_PORT if hasattr(settings, "REDIS_PORT") else 6379,
            decode_responses=True,
            socket_timeout=2
        )
        redis_client.ping()
    except Exception:
        redis_client = None


def _cache_get(key: str):
    if redis_client:
        return redis_client.get(key)
    return None


def _cache_set(key: str, value: str, ttl: int = 300):
    if redis_client:
        redis_client.setex(key, ttl, value)


def _register_failed_source(source: str, error: str) -> None:
    db = SessionLocal()
    try:
        if redis_client:
            redis_client.sadd(FAILED_SOURCES_CACHE_KEY, source)

        task = (
            db.query(EnrichmentRetryTask)
            .filter(
                EnrichmentRetryTask.source == source,
                EnrichmentRetryTask.task_type == "threat_feed",
                EnrichmentRetryTask.status == "pending",
            )
            .order_by(EnrichmentRetryTask.created_at.desc())
            .first()
        )
        if task:
            task.attempts = int(task.attempts or 0) + 1
            task.last_error = error
        else:
            db.add(
                EnrichmentRetryTask(
                    source=source,
                    task_type="threat_feed",
                    attempts=1,
                    last_error=error,
                    status="pending",
                    payload={"source": source},
                )
            )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to register retry task for source %s", source)
    finally:
        db.close()


def _clear_failed_source(source: str) -> None:
    db = SessionLocal()
    try:
        if redis_client:
            redis_client.srem(FAILED_SOURCES_CACHE_KEY, source)
        tasks = (
            db.query(EnrichmentRetryTask)
            .filter(
                EnrichmentRetryTask.source == source,
                EnrichmentRetryTask.task_type == "threat_feed",
                EnrichmentRetryTask.status == "pending",
            )
            .all()
        )
        for task in tasks:
            task.status = "completed"
            task.last_error = None
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to clear retry task for source %s", source)
    finally:
        db.close()


# ------------------------------
# IP Geolocation
# ------------------------------
def get_ip_geo(ip: str) -> Dict[str, Any]:
    providers = [
        ("https://ipapi.co/{ip}/json/", "ipapi"),
        ("http://ip-api.com/json/{ip}", "ip-api"),
    ]
    for template, provider_name in providers:
        try:
            response = requests.get(template.format(ip=ip), timeout=4)
            if response.status_code != 200:
                continue
            data = response.json()
            if provider_name == "ipapi" and not data.get("error"):
                return {
                    "country": data.get("country_name", "Unknown"),
                    "country_code": data.get("country_code", ""),
                    "region": data.get("region", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("org", ""),
                    "org": data.get("org", ""),
                    "as": data.get("asn", ""),
                    "lat": data.get("latitude"),
                    "lon": data.get("longitude"),
                }
            if provider_name == "ip-api" and data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as": data.get("as", ""),
                    "lat": data.get("lat"),
                    "lon": data.get("lon")
                }
        except Exception as exc:
            logger.debug("IP geolocation provider %s failed for %s: %s", provider_name, ip, exc)
    return {"country": "Unknown", "isp": "Unknown", "org": "Unknown", "as": "Unknown"}


# ------------------------------
# VirusTotal (IP)
# ------------------------------
def check_virustotal(ip: str) -> Dict[str, Any]:
    if not VIRUSTOTAL_KEY:
        return {"source": "VirusTotal", "error": "Missing API key"}

    cache_key = f"vt_ip:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return json.loads(cached)

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = stats.get("total", 1)
            score = min(100, int((malicious + suspicious) / total * 100))

            result = {
                "source": "VirusTotal",
                "score": score,
                "malicious_votes": malicious,
                "suspicious_votes": suspicious,
                "harmless_votes": stats.get("harmless", 0),
                "country": data.get("country", "Unknown"),
                "as_owner": data.get("as_owner", ""),
                "network": data.get("network", ""),
                "whois": data.get("whois", "")[:500]
            }
            _cache_set(cache_key, json.dumps(result), ttl=3600)
            return result

        return {"source": "VirusTotal", "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


# ------------------------------
# AbuseIPDB
# ------------------------------
def check_abuseipdb(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_KEY:
        return {"source": "AbuseIPDB", "error": "No API key configured"}

    cache_key = f"abuseipdb:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return json.loads(cached)

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": True}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]
            result = {
                "source": "AbuseIPDB",
                "score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryName", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", ""),
                "usage_type": data.get("usageType", ""),
                "categories": [c.get("title") for c in data.get("reports", [])[:5]]
            }
            _cache_set(cache_key, json.dumps(result), ttl=3600)
            return result

        return {"source": "AbuseIPDB", "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}


# ------------------------------
# GreyNoise
# ------------------------------
def check_greynoise(ip: str) -> Dict[str, Any]:
    if not GREYNOISE_KEY:
        return {"source": "GreyNoise", "error": "No API key configured"}

    cache_key = f"greynoise:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return json.loads(cached)

    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": GREYNOISE_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            classification = data.get("classification", "unknown")
            score = 80 if classification == "malicious" else 40 if classification == "noise" else 10
            result = {
                "source": "GreyNoise",
                "score": score,
                "classification": classification,
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "name": data.get("name", ""),
                "last_seen": data.get("last_seen", "Never"),
                "tags": data.get("tags", [])
            }
            _cache_set(cache_key, json.dumps(result), ttl=3600)
            return result

        return {"source": "GreyNoise", "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"source": "GreyNoise", "error": str(e)}


# ------------------------------
# AlienVault OTX
# ------------------------------
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=10))
def check_otx(indicator: str, indicator_type: str = "ip") -> Dict[str, Any]:
    """Check IP or URL against AlienVault OTX (free, API key optional but recommended)"""
    cache_key = f"otx:{indicator_type}:{indicator}"
    cached = _cache_get(cache_key)
    if cached:
        return json.loads(cached)

    headers = {}
    if OTX_KEY:
        headers["X-OTX-API-KEY"] = OTX_KEY

    if indicator_type == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
    elif indicator_type == "url":
        # OTX expects URL encoded
        import urllib.parse
        encoded = urllib.parse.quote(indicator, safe="")
        url = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded}/general"
    else:
        return {"source": "OTX", "error": "Unsupported type"}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            reputation = data.get("reputation", 0)
            score = 0
            if reputation < -3:
                score = 80
            elif reputation < 0:
                score = 50
            elif pulse_count > 5:
                score = 30
            else:
                score = 10
            result = {
                "source": "AlienVault OTX",
                "score": score,
                "pulse_count": pulse_count,
                "reputation": reputation,
                "country": data.get("country_code", ""),
                "asn": data.get("asn", "")
            }
            _cache_set(cache_key, json.dumps(result), ttl=3600)
            return result
        return {"source": "OTX", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"source": "OTX", "error": str(e)}


# ------------------------------
# Aggregate IP Intel
# ------------------------------
def aggregate_ip_intel(ip: str) -> Dict[str, Any]:
    geo = get_ip_geo(ip)
    results = []

    results.append({
        "source": "IP Geolocation (ip-api.com)",
        "country": geo.get("country"),
        "country_code": geo.get("country_code"),
        "region": geo.get("region"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "org": geo.get("org"),
        "as": geo.get("as"),
        "lat": geo.get("lat"),
        "lon": geo.get("lon"),
        "score": 0
    })

    vt = check_virustotal(ip)
    if vt.get("score") is not None:
        results.append(vt)

    if ABUSEIPDB_KEY:
        abuse = check_abuseipdb(ip)
        if abuse.get("score") is not None:
            results.append(abuse)

    if GREYNOISE_KEY:
        gn = check_greynoise(ip)
        if gn.get("score") is not None:
            results.append(gn)

    # OTX check
    otx = check_otx(ip, "ip")
    if otx.get("score") is not None:
        results.append(otx)

    scores = [r["score"] for r in results if "score" in r and not r.get("error")]
    avg_score = sum(scores) // len(scores) if scores else 0

    if avg_score >= 60:
        threat_level = "threat"
        recommendation = "block"
    elif avg_score >= 25:
        threat_level = "suspicious"
        recommendation = "quarantine"
    else:
        threat_level = "safe"
        recommendation = "allow"

    return {
        "success": True,
        "ip": ip,
        "threat_level": threat_level,
        "aggregated_score": avg_score,
        "recommendation": recommendation,
        "geo": {
            "country": geo.get("country"),
            "city": geo.get("city"),
            "region": geo.get("region"),
            "isp": geo.get("isp"),
            "organization": geo.get("org"),
            "asn": geo.get("as"),
            "latitude": geo.get("lat"),
            "longitude": geo.get("lon")
        },
        "sources": results,
        "summary": f"IP analyzed across {len(results)} intelligence sources."
    }


# ------------------------------
# VirusTotal URL
# ------------------------------
def check_virustotal_url(url: str) -> Dict[str, Any]:
    if not VIRUSTOTAL_KEY:
        return {"source": "VirusTotal", "error": "Missing API key"}

    cache_key = f"vt_url:{url}"
    cached = _cache_get(cache_key)
    if cached:
        return json.loads(cached)

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = stats.get("total", 1)
            score = min(100, int((malicious + suspicious) / total * 100))
            result = {
                "source": "VirusTotal",
                "score": score,
                "malicious_votes": malicious,
                "suspicious_votes": suspicious,
                "harmless_votes": stats.get("harmless", 0),
                "url": url,
                "title": data.get("title", "")
            }
            _cache_set(cache_key, json.dumps(result), ttl=3600)
            return result
        return {"source": "VirusTotal", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


# ------------------------------
# urlscan.io
# ------------------------------
def check_urlscan_io(url: str) -> Dict[str, Any]:
    cache_key = f"urlscan:{url}"
    cached = _cache_get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        search_url = f"https://urlscan.io/api/v1/search/?q={url}"
        resp = requests.get(search_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if results:
                latest = results[0]
                malicious = latest.get("malicious", False)
                score = 85 if malicious else 15
                result = {
                    "source": "urlscan.io",
                    "score": score,
                    "malicious": malicious,
                    "url": url,
                    "screenshot": latest.get("screenshot"),
                    "page_domain": latest.get("page", {}).get("domain")
                }
                _cache_set(cache_key, json.dumps(result), ttl=3600)
                return result
        return {"source": "urlscan.io", "error": "No results or error"}
    except Exception as e:
        return {"source": "urlscan.io", "error": str(e)}


# ------------------------------
# Aggregate URL Intel
# ------------------------------
def aggregate_url_intel(url: str) -> Dict[str, Any]:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    results = []

    vt = check_virustotal_url(url)
    if vt.get("score") is not None:
        results.append(vt)

    us = check_urlscan_io(url)
    if us.get("score") is not None:
        results.append(us)

    # OTX URL check
    otx = check_otx(url, "url")
    if otx.get("score") is not None:
        results.append(otx)

    scores = [r["score"] for r in results if "score" in r and not r.get("error")]
    avg_score = sum(scores) // len(scores) if scores else 0

    if avg_score >= 60:
        threat_level = "threat"
        recommendation = "block"
    elif avg_score >= 25:
        threat_level = "suspicious"
        recommendation = "quarantine"
    else:
        threat_level = "safe"
        recommendation = "allow"

    return {
        "success": True,
        "url": url,
        "threat_level": threat_level,
        "aggregated_score": avg_score,
        "recommendation": recommendation,
        "sources": results,
        "summary": f"URL analyzed across {len(results)} intelligence sources."
    }


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()

    normalized = value.strip()
    if not normalized:
        return datetime.utcnow()

    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%a, %d %b %Y %H:%M:%S %Z",
    ]

    for fmt in formats:
        try:
            parsed = datetime.strptime(normalized, fmt)
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            continue

    logger.debug("Failed to parse datetime value: %s", value)
    return datetime.utcnow()


def _normalize_indicator(indicator: str | None) -> str:
    return (indicator or "").strip()


def _resolve_threat_level(risk_score: int) -> str:
    if risk_score >= 80:
        return "threat"
    if risk_score >= 50:
        return "suspicious"
    return "safe"


def _append_threat(
    threats: List[Dict[str, Any]],
    indicator: str | None,
    threat_type: str,
    risk_score: int,
    summary: str,
    source: str,
    published_at: datetime | str | None,
    raw_intel: Dict[str, Any],
):
    normalized_indicator = _normalize_indicator(indicator)
    if not normalized_indicator:
        return

    threats.append(
        {
            "indicator": normalized_indicator,
            "threat_type": threat_type,
            "risk_score": max(0, min(100, int(risk_score))),
            "summary": summary,
            "source": source,
            "published_at": _parse_datetime(published_at) if not isinstance(published_at, datetime) else published_at,
            "raw_intel": raw_intel,
        }
    )


def fetch_otx_pulses(days_back: int = 1) -> List[Dict[str, Any]]:
    threats: List[Dict[str, Any]] = []
    headers = {}
    if OTX_KEY:
        headers["X-OTX-API-KEY"] = OTX_KEY

    try:
        response = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers=headers,
            params={"limit": 20, "page": 1},
            timeout=10,
        )
        response.raise_for_status()
        pulses = response.json().get("results", [])
        cutoff = datetime.utcnow() - timedelta(days=days_back)

        for pulse in pulses:
            modified_at = _parse_datetime(pulse.get("modified") or pulse.get("created"))
            if modified_at < cutoff:
                continue

            pulse_name = pulse.get("name", "OTX pulse")
            pulse_tags = pulse.get("tags", [])
            pulse_author = (pulse.get("author") or {}).get("username", "unknown")

            for item in pulse.get("indicators", []):
                indicator_type = item.get("type", "").lower()
                if indicator_type == "ipv4":
                    threat_type = "ip"
                elif indicator_type == "url":
                    threat_type = "url"
                else:
                    continue

                pulse_count = pulse.get("subscriber_count", 0) or 0
                risk_score = 90 if pulse.get("tlp") == "red" else 80 if pulse_count > 100 else 70
                summary = f"{pulse_name} from OTX by {pulse_author}"

                _append_threat(
                    threats=threats,
                    indicator=item.get("indicator"),
                    threat_type=threat_type,
                    risk_score=risk_score,
                    summary=summary,
                    source="AlienVault OTX",
                    published_at=modified_at,
                    raw_intel={
                        "pulse_id": pulse.get("id"),
                        "pulse_name": pulse_name,
                        "description": pulse.get("description"),
                        "tags": pulse_tags,
                        "author": pulse_author,
                        "indicator_type": item.get("type"),
                        "indicator_title": item.get("title"),
                    },
                )
    except Exception as exc:
        logger.exception("Failed to fetch AlienVault OTX pulses: %s", exc)

    return threats


def fetch_urlhaus_recent() -> List[Dict[str, Any]]:
    threats: List[Dict[str, Any]] = []

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/",
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()

        for item in payload.get("urls", []):
            indicator = item.get("url")
            url_status = (item.get("url_status") or "").lower()
            threat_type_name = item.get("threat") or "malicious url"
            tags = item.get("tags") or []
            risk_score = 90 if url_status == "online" else 75
            summary = f"URLhaus classified this URL as {threat_type_name}"

            _append_threat(
                threats=threats,
                indicator=indicator,
                threat_type="url",
                risk_score=risk_score,
                summary=summary,
                source="URLhaus",
                published_at=item.get("date_added") or item.get("dateadded"),
                raw_intel={
                    "id": item.get("id"),
                    "url_status": url_status,
                    "threat": threat_type_name,
                    "host": item.get("host"),
                    "tags": tags,
                    "reporter": item.get("reporter"),
                },
            )
    except Exception as exc:
        logger.exception("Failed to fetch URLhaus data: %s", exc)

    return threats


def fetch_abuseipdb_recent(api_key: str, days: int = 1) -> List[Dict[str, Any]]:
    threats: List[Dict[str, Any]] = []
    if not api_key:
        logger.warning("Skipping AbuseIPDB collection because API key is missing")
        return threats

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": api_key, "Accept": "application/json"},
            params={
                "confidenceMinimum": 90,
                "limit": 20,
                "ipVersion": 4,
            },
            timeout=10,
        )
        response.raise_for_status()
        entries = response.json().get("data", [])
        cutoff = datetime.utcnow() - timedelta(days=days)

        for item in entries:
            last_reported_at = _parse_datetime(item.get("lastReportedAt"))
            if last_reported_at < cutoff:
                continue

            confidence = int(item.get("abuseConfidenceScore", 0) or 0)
            summary = f"AbuseIPDB confidence score {confidence} with {item.get('totalReports', 0)} reports"

            _append_threat(
                threats=threats,
                indicator=item.get("ipAddress"),
                threat_type="ip",
                risk_score=confidence,
                summary=summary,
                source="AbuseIPDB",
                published_at=last_reported_at,
                raw_intel={
                    "country_code": item.get("countryCode"),
                    "usage_type": item.get("usageType"),
                    "isp": item.get("isp"),
                    "domain": item.get("domain"),
                    "total_reports": item.get("totalReports"),
                    "num_distinct_users": item.get("numDistinctUsers"),
                    "last_reported_at": item.get("lastReportedAt"),
                },
            )
    except Exception as exc:
        logger.exception("Failed to fetch AbuseIPDB blacklist: %s", exc)

    return threats


def fetch_phish_tank_recent() -> List[Dict[str, Any]]:
    threats: List[Dict[str, Any]] = []

    try:
        response = requests.get(
            "https://data.phishtank.com/data/online-valid.json",
            timeout=15,
        )
        response.raise_for_status()
        entries = response.json()

        for item in entries[:20]:
            target = item.get("target") or "phishing target"
            verified_at = item.get("verified_at") or item.get("submission_time")
            summary = f"PhishTank verified this URL as phishing for {target}"

            _append_threat(
                threats=threats,
                indicator=item.get("url"),
                threat_type="url",
                risk_score=95,
                summary=summary,
                source="PhishTank",
                published_at=verified_at,
                raw_intel={
                    "phish_id": item.get("phish_id"),
                    "phish_detail_page": item.get("phish_detail_page"),
                    "verified": item.get("verified"),
                    "verification_time": item.get("verification_time"),
                    "target": target,
                },
            )
    except Exception as exc:
        logger.exception("Failed to fetch PhishTank data: %s", exc)

    return threats


def fetch_ibm_xforce_recent() -> List[Dict[str, Any]]:
    threats: List[Dict[str, Any]] = []
    api_key = getattr(settings, "IBM_XFORCE_API_KEY", "")
    api_password = getattr(settings, "IBM_XFORCE_API_PASSWORD", "")
    if not api_key or not api_password:
        logger.warning("Skipping IBM X-Force collection because credentials are missing")
        return threats

    try:
        response = requests.get(
            "https://api.xforce.ibmcloud.com/url/malware",
            auth=(api_key, api_password),
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()

        for item in payload.get("malware", [])[:20]:
            _append_threat(
                threats=threats,
                indicator=item.get("domain") or item.get("url"),
                threat_type="url",
                risk_score=88,
                summary="IBM X-Force identified this indicator as malware infrastructure.",
                source="IBM X-Force",
                published_at=item.get("last") or item.get("created"),
                raw_intel=item,
            )
    except Exception as exc:
        logger.exception("Failed to fetch IBM X-Force data: %s", exc)

    return threats


def fetch_cisa_kev_recent() -> List[Dict[str, Any]]:
    threats: List[Dict[str, Any]] = []
    feed_url = getattr(
        settings,
        "CISA_KEV_FEED_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    try:
        response = requests.get(feed_url, timeout=15)
        response.raise_for_status()
        payload = response.json()

        for item in payload.get("vulnerabilities", [])[:20]:
            _append_threat(
                threats=threats,
                indicator=item.get("cveID"),
                threat_type="cve",
                risk_score=82,
                summary=f"CISA KEV lists {item.get('cveID')} as actively exploited.",
                source="CISA KEV",
                published_at=item.get("dateAdded"),
                raw_intel={
                    "vendor_project": item.get("vendorProject"),
                    "product": item.get("product"),
                    "vulnerability_name": item.get("vulnerabilityName"),
                    "required_action": item.get("requiredAction"),
                    "due_date": item.get("dueDate"),
                },
            )
    except Exception as exc:
        logger.exception("Failed to fetch CISA KEV feed: %s", exc)

    return threats


def save_threats_to_db(threats: List[Dict[str, Any]]) -> int:
    if not threats:
        return 0

    db = SessionLocal()
    saved_count = 0

    try:
        indicators = {
            _normalize_indicator(threat.get("indicator"))
            for threat in threats
            if _normalize_indicator(threat.get("indicator"))
        }
        existing_indicators = {
            item[0]
            for item in db.query(CommunityThreat.indicator)
            .filter(CommunityThreat.indicator.in_(list(indicators)))
            .all()
        }

        for threat in threats:
            indicator = _normalize_indicator(threat.get("indicator"))
            if not indicator or indicator in existing_indicators:
                continue

            risk_score = int(threat.get("risk_score", 0) or 0)
            source = threat.get("source", "Threat intelligence feed")
            summary = threat.get("summary", f"Threat collected from {source}")

            db.add(
                CommunityThreat(
                    threat_type=threat.get("threat_type", "unknown"),
                    indicator=indicator,
                    risk_score=risk_score,
                    threat_level=_resolve_threat_level(risk_score),
                    published_by=1,
                    raw_intel={
                        "source": source,
                        "summary": summary,
                        "published_at": (
                            threat.get("published_at").isoformat()
                            if isinstance(threat.get("published_at"), datetime)
                            else str(threat.get("published_at") or "")
                        ),
                        "raw": threat.get("raw_intel", {}),
                    },
                    published_at=(
                        threat.get("published_at")
                        if isinstance(threat.get("published_at"), datetime)
                        else _parse_datetime(threat.get("published_at"))
                    ),
                    is_moderated=True,
                    title=f"{source} indicator",
                    description=summary,
                )
            )
            existing_indicators.add(indicator)
            saved_count += 1

        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to save collected threats: %s", exc)
    finally:
        db.close()

    return saved_count


FETCHERS = {
    "otx": lambda: fetch_otx_pulses(days_back=1),
    "urlhaus": fetch_urlhaus_recent,
    "abuseipdb": lambda: fetch_abuseipdb_recent(ABUSEIPDB_KEY, days=1),
    "phishtank": fetch_phish_tank_recent,
    "ibm_xforce": fetch_ibm_xforce_recent,
    "cisa_kev": fetch_cisa_kev_recent,
}


def collect_all_intel() -> Dict[str, int]:
    collected_threats: List[Dict[str, Any]] = []

    for fetcher_name, fetcher in FETCHERS.items():
        try:
            fetched = fetcher()
            collected_threats.extend(fetched)
            _clear_failed_source(fetcher_name)
        except Exception as exc:
            logger.exception("Threat intel fetcher %s failed: %s", fetcher_name, exc)
            _register_failed_source(fetcher_name, str(exc))

    saved_count = save_threats_to_db(collected_threats)
    logger.info(
        "Threat intelligence collection finished: collected=%s saved=%s",
        len(collected_threats),
        saved_count,
    )
    return {"collected": len(collected_threats), "saved": saved_count}


def retry_failed_intel_sources() -> Dict[str, int]:
    db = SessionLocal()
    retried = 0
    recovered = 0
    collected_threats: List[Dict[str, Any]] = []

    try:
        tasks = (
            db.query(EnrichmentRetryTask)
            .filter(
                EnrichmentRetryTask.task_type == "threat_feed",
                EnrichmentRetryTask.status == "pending",
            )
            .order_by(EnrichmentRetryTask.created_at.asc())
            .limit(20)
            .all()
        )
    finally:
        db.close()

    for task in tasks:
        fetcher = FETCHERS.get(task.source)
        if not fetcher:
            continue
        retried += 1
        try:
            fetched = fetcher()
            if fetched:
                collected_threats.extend(fetched)
            _clear_failed_source(task.source)
            recovered += 1
        except Exception as exc:
            logger.exception("Retry for threat intel source %s failed: %s", task.source, exc)
            _register_failed_source(task.source, str(exc))

    saved_count = save_threats_to_db(collected_threats)
    return {
        "retried": retried,
        "recovered": recovered,
        "collected": len(collected_threats),
        "saved": saved_count,
    }
