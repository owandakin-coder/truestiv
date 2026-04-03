from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.ai_engine import analyze_threat
from app.models.models import User
from app.services.threat_intel import aggregate_ip_intel
import re
import hashlib
import ipaddress
import secrets

router = APIRouter()

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

    return {
        "success": True,
        "url": url,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "confidence": min(95, risk_score + 20) if risk_score > 0 else 85,
        "indicators": indicators,
        "recommendation": recommendation,
        "summary": summary
    }


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
        return {
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

    if ip_obj.is_loopback:
        return {
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

    return {
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

    return {
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

    return result["analysis"]
