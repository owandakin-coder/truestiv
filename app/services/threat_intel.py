import requests
from app.core.config import settings
from typing import Dict, Any

VIRUSTOTAL_KEY = settings.VIRUSTOTAL_API_KEY
ABUSEIPDB_KEY = settings.ABUSEIPDB_API_KEY
GREYNOISE_KEY = settings.GREYNOISE_API_KEY

def get_ip_geo(ip: str) -> Dict[str, Any]:
    """שירות חינמי לקבלת מיקום גיאוגרפי וספק רשת (ip-api.com)"""
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

def check_virustotal(ip: str) -> Dict[str, Any]:
    """בדיקה מול VirusTotal"""
    if not VIRUSTOTAL_KEY:
        return {"source": "VirusTotal", "error": "Missing API key"}
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
            return {
                "source": "VirusTotal",
                "score": score,
                "malicious_votes": malicious,
                "suspicious_votes": suspicious,
                "harmless_votes": stats.get("harmless", 0),
                "country": data.get("country", "Unknown"),
                "as_owner": data.get("as_owner", ""),
                "network": data.get("network", ""),
                "whois": data.get("whois", "")[:500]  # קיצור
            }
        return {"source": "VirusTotal", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}

def check_abuseipdb(ip: str) -> Dict[str, Any]:
    """בדיקה מול AbuseIPDB"""
    if not ABUSEIPDB_KEY:
        return {"source": "AbuseIPDB", "error": "No API key configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": True}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "source": "AbuseIPDB",
                "score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryName", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", ""),
                "usage_type": data.get("usageType", ""),
                "categories": [c.get("title") for c in data.get("reports", [])[:5]]
            }
        return {"source": "AbuseIPDB", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}

def check_greynoise(ip: str) -> Dict[str, Any]:
    """בדיקה מול GreyNoise (Community)"""
    if not GREYNOISE_KEY:
        return {"source": "GreyNoise", "error": "No API key configured"}
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": GREYNOISE_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            classification = data.get("classification", "unknown")
            score = 80 if classification == "malicious" else 40 if classification == "noise" else 10
            return {
                "source": "GreyNoise",
                "score": score,
                "classification": classification,
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "name": data.get("name", ""),
                "last_seen": data.get("last_seen", "Never"),
                "tags": data.get("tags", [])
            }
        return {"source": "GreyNoise", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"source": "GreyNoise", "error": str(e)}

def aggregate_ip_intel(ip: str) -> Dict[str, Any]:
    """מריץ את כל הבדיקות ומחזיר ניקוד מאוחד + פרטים מלאים"""
    geo = get_ip_geo(ip)
    results = []
    
    # תמיד נוסיף מידע גיאוגרפי
    geo_source = {
        "source": "IP Geolocation (ip-api.com)",
        "country": geo.get("country"),
        "country_code": geo.get("country_code"),
        "region": geo.get("region"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "org": geo.get("org"),
        "as": geo.get("as"),
        "lat": geo.get("lat"),
        "lon": geo.get("lon")
    }
    results.append(geo_source)
    
    # שאר המקורות
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
    
    # חישוב ניקוד ממוצע (רק ממקורות שהחזירו score)
    scores = [r["score"] for r in results if "score" in r and not r.get("error")]
    avg_score = sum(scores) // len(scores) if scores else 0
    
    # קביעת רמת איום
    if avg_score >= 60:
        threat_level = "threat"
        recommendation = "block"
    elif avg_score >= 25:
        threat_level = "suspicious"
        recommendation = "quarantine"
    else:
        threat_level = "safe"
        recommendation = "allow"
    
    # אספקת פרטים מובילים (מהתוצאות)
    main_isp = geo.get("isp") or next((r.get("isp") for r in results if r.get("isp")), "Unknown")
    main_country = geo.get("country") or next((r.get("country") for r in results if r.get("country")), "Unknown")
    main_as = geo.get("as") or next((r.get("as_owner") for r in results if r.get("as_owner")), "")
    
    return {
        "success": True,
        "ip": ip,
        "threat_level": threat_level,
        "aggregated_score": avg_score,
        "recommendation": recommendation,
        "geo": {
            "country": main_country,
            "city": geo.get("city"),
            "region": geo.get("region"),
            "isp": main_isp,
            "organization": geo.get("org"),
            "asn": main_as,
            "latitude": geo.get("lat"),
            "longitude": geo.get("lon")
        },
        "sources": results,
        "summary": f"IP analyzed across {len(results)} intelligence sources.",
        "summary_hebrew": f"ה-IP נותח מול {len(results)} מקורות מודיעין."
    }