import requests
import base64
import json
from typing import Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential
from app.core.config import settings

# Attempt Redis import gracefully
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

VIRUSTOTAL_KEY = settings.VIRUSTOTAL_API_KEY
ABUSEIPDB_KEY = settings.ABUSEIPDB_API_KEY
GREYNOISE_KEY = settings.GREYNOISE_API_KEY
OTX_KEY = getattr(settings, "OTX_API_KEY", "")

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


# ------------------------------
# IP Geolocation
# ------------------------------
def get_ip_geo(ip: str) -> Dict[str, Any]:
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
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
    except Exception:
        pass
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
