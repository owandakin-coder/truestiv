import hashlib
import re
import socket
import requests
import base64
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc, text
from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.transformer_ai_engine import analyze_threat
from app.core.billing import check_scan_limit, increment_scan_usage
from app.core.config import settings
from app.models.models import User, EmailAnalysis, EmailThread, ThreatPropagation, ThreatSignature
from app.schemas.schemas import EmailAnalysisRequest
from typing import List, Dict, Tuple
from urllib.parse import urlparse

router = APIRouter()

EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"
PHONE_REGEX = r"^\+?[0-9]{7,15}$"

def is_valid_email(email: str) -> bool:
    return bool(re.match(EMAIL_REGEX, email or ""))

def is_valid_phone(phone: str) -> bool:
    return bool(re.match(PHONE_REGEX, phone or ""))

def split_email(email: str) -> Tuple[str, str]:
    if "@" not in email:
        return email, ""
    local, domain = email.split("@", 1)
    return local, domain.lower().strip()

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
}

def is_disposable_domain(domain: str) -> bool:
    return domain in DISPOSABLE_DOMAINS

def has_mx_record(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

def looks_like_spoof(domain: str, trusted_domains: List[str]) -> bool:
    domain_lower = domain.lower()
    for trusted in trusted_domains:
        if trusted in domain_lower and domain_lower != trusted:
            return True
    return False

SUSPICIOUS_KEYWORDS = [
    "urgent", "immediately", "password", "bank", "verify", "click here",
    "account locked", "wire transfer", "payment", "invoice", "reset",
]

def extract_urls(text: str) -> List[str]:
    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(url_pattern, text)
    return [urlparse(url).netloc or url for url in urls]

def analyze_urls_basic(urls: List[str]) -> dict:
    suspicious = []
    for u in urls:
        u_lower = u.lower()
        if any(bad in u_lower for bad in ["login", "verify", "update", "secure", "paypal", "bank"]):
            suspicious.append(u)
    return {
        "suspicious_urls": suspicious,
        "has_suspicious_urls": len(suspicious) > 0,
    }

def keyword_risk_score(content: str) -> int:
    text = (content or "").lower()
    score = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in text:
            score += 5
    return score

def vt_check_url(url: str, api_key: str) -> dict:
    if not api_key:
        return {"error": True, "malicious": False, "stats": {}}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=5
        )
        if resp.status_code != 200:
            return {"error": True, "malicious": False, "stats": {}}
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) > 0
        return {"error": False, "malicious": malicious, "stats": stats}
    except Exception:
        return {"error": True, "malicious": False, "stats": {}}

def abuseip_check(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"error": True, "abuse_score": 0}
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        resp = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
            headers=headers,
            timeout=5
        )
        if resp.status_code != 200:
            return {"error": True, "abuse_score": 0}
        data = resp.json()
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        return {"error": False, "abuse_score": score}
    except Exception:
        return {"error": True, "abuse_score": 0}

def greynoise_check(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"error": True, "noise": False}
    try:
        headers = {"key": api_key, "Accept": "application/json"}
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=headers,
            timeout=5
        )
        if resp.status_code != 200:
            return {"error": True, "noise": False}
        data = resp.json()
        noise = data.get("noise", False)
        return {"error": False, "noise": noise}
    except Exception:
        return {"error": True, "noise": False}

def generate_threat_signature(analysis: dict, sender: str, urls: List[str]) -> str:
    components = []
    if analysis.get("threat_type"):
        components.append(analysis["threat_type"])
    if urls:
        components.append(urls[0])
    if sender:
        components.append(sender)
    signature = "|".join(components)
    return hashlib.sha256(signature.encode()).hexdigest()[:32]

def find_related_threats(db: Session, user_id: int, threat_signature: str, urls: List[str], sender: str) -> List[Dict]:
    related = []
    signature_record = db.query(ThreatSignature).filter(
        ThreatSignature.signature_hash == threat_signature
    ).first()
    if signature_record:
        analyses = db.query(EmailAnalysis).filter(
            EmailAnalysis.user_id == user_id,
            EmailAnalysis.threat_type == signature_record.threat_type
        ).order_by(desc(EmailAnalysis.created_at)).limit(10).all()
        for analysis in analyses:
            if analysis.id:
                related.append({
                    "id": analysis.id,
                    "user_id": analysis.user_id,
                    "sender": analysis.sender or analysis.phone_number,
                    "created_at": analysis.created_at,
                    "threat_level": analysis.threat_level
                })
    if urls:
        all_analyses = db.query(EmailAnalysis).filter(
            EmailAnalysis.user_id == user_id,
            EmailAnalysis.content.contains(urls[0])
        ).order_by(desc(EmailAnalysis.created_at)).limit(5).all()
        for analysis in all_analyses:
            if analysis.id and not any(r["id"] == analysis.id for r in related):
                related.append({
                    "id": analysis.id,
                    "user_id": analysis.user_id,
                    "sender": analysis.sender or analysis.phone_number,
                    "created_at": analysis.created_at,
                    "threat_level": analysis.threat_level
                })
    return related

def update_threat_signature(db: Session, signature_hash: str, threat_type: str, threat_level: str, user_id: int):
    signature = db.query(ThreatSignature).filter(
        ThreatSignature.signature_hash == signature_hash
    ).first()
    if signature:
        signature.last_seen = datetime.utcnow()
        signature.occurrences += 1
        affected = signature.affected_users or []
        if user_id not in affected:
            affected.append(user_id)
            signature.affected_users = affected
    else:
        signature = ThreatSignature(
            signature_hash=signature_hash,
            threat_type=threat_type,
            threat_level=threat_level,
            affected_users=[user_id]
        )
        db.add(signature)
    db.commit()
    return signature

def _save_analysis(request: EmailAnalysisRequest, analysis: dict, db: Session, current_user: User):
    if request.channel == "email":
        sender = request.sender
        phone = None
        subject = request.subject or "(no subject)"
    else:
        sender = None
        phone = request.phone_number
        subject = f"{request.channel.upper()} Message"

    thread = None
    if request.channel == "email":
        thread = db.query(EmailThread).filter(
            EmailThread.user_id == current_user.id,
            EmailThread.thread_identifier == request.subject
        ).first()
        if not thread:
            thread = EmailThread(
                user_id=current_user.id,
                thread_identifier=request.subject,
                participants=[sender]
            )
            db.add(thread)
            db.flush()
        else:
            participants = set(thread.participants or [])
            participants.add(sender)
            thread.participants = list(participants)
            thread.last_seen = datetime.utcnow()

    db_analysis = EmailAnalysis(
        user_id=current_user.id,
        thread_id=thread.id if thread else None,
        subject=subject,
        sender=sender,
        phone_number=phone,
        channel=request.channel,
        content=request.content,
        threat_level=analysis["threat_level"],
        confidence=analysis["confidence"],
        threat_type=analysis.get("threat_type", "unknown"),
        summary=analysis["summary"],
        indicators=analysis.get("indicators", []),
        recommendation=analysis.get("recommendation", "allow"),
        hijack_detected=analysis.get("hijack_detected", False),
        writing_style_change=analysis.get("writing_style_change", False),
        suspicious_domain=analysis.get("suspicious_domain", False),
        is_quarantined=analysis.get("recommendation", "allow") != "allow"
    )
    db.add(db_analysis)
    db.flush()
    return db_analysis

def _publish_threat_background(indicator: str, threat_type: str, risk_score: int, threat_level: str, analysis_id: int, token: str):
    try:
        base_url = getattr(settings, "BASE_URL", "https://trustiveai.onrender.com")
        url = f"{base_url}/api/community/publish-threat"
        headers = {"Authorization": f"Bearer {token}"}
        requests.post(
            url,
            json={
                "threat_type": threat_type,
                "indicator": indicator,
                "risk_score": risk_score,
                "threat_level": threat_level,
                "analysis_id": analysis_id
            },
            headers=headers,
            timeout=2
        )
    except Exception as e:
        print(f"Background auto-publish failed: {e}")

@router.post("/analyze", response_model=dict)
def analyze_message(
    request: EmailAnalysisRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if request.channel == "email":
        if not request.sender:
            raise HTTPException(status_code=400, detail="Sender email is required")
        if not is_valid_email(request.sender):
            raise HTTPException(status_code=400, detail="Invalid email format")
    if request.channel in ["sms", "whatsapp"]:
        if not request.phone_number:
            raise HTTPException(status_code=400, detail="Phone number is required")
        if not is_valid_phone(request.phone_number):
            raise HTTPException(status_code=400, detail="Invalid phone number")

    content = (request.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    check_scan_limit(db, current_user.id)

    urls = extract_urls(content)
    sender_value = request.sender or request.phone_number or ""
    missing_identity = not sender_value

    result = analyze_threat(
        content=content,
        content_type=request.channel,
        sender=sender_value,
        subject=request.subject or "",
        conversation_history=[]
    )
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Analysis failed"))
    analysis = result["analysis"]

    risk_score = 0

    if missing_identity:
        if analysis["threat_level"] == "safe":
            analysis["threat_level"] = "suspicious"
        analysis["confidence"] = min(analysis.get("confidence", 0.5), 0.5)
        analysis["summary"] += " | Warning: Missing sender/phone information"
        risk_score += 15

    if request.channel == "email" and request.sender:
        local, domain = split_email(request.sender)
        if not has_mx_record(domain):
            analysis["threat_level"] = "suspicious"
            analysis["summary"] += " | Domain has no valid DNS/MX record"
            risk_score += 15
        if is_disposable_domain(domain):
            analysis["threat_level"] = "suspicious"
            analysis["summary"] += " | Disposable email domain detected"
            risk_score += 10
        trusted_domains = ["paypal.com", "google.com", "microsoft.com", "bankofamerica.com"]
        if looks_like_spoof(domain, trusted_domains):
            analysis["threat_level"] = "dangerous"
            analysis["summary"] += " | Possible spoofed domain"
            risk_score += 25

    if request.channel in ["sms", "whatsapp"] and request.phone_number:
        risk_score += 5

    url_info = analyze_urls_basic(urls)
    if url_info["has_suspicious_urls"]:
        analysis["threat_level"] = "suspicious"
        analysis["summary"] += " | Suspicious URLs detected"
        risk_score += 20

    risk_score += keyword_risk_score(content)

    if len(content) < 5:
        analysis["threat_level"] = "suspicious"
        analysis["summary"] += " | Very short content"
        risk_score += 10

    external_risk = 0
    for url in urls:
        vt = vt_check_url(url, settings.VIRUSTOTAL_API_KEY)
        if not vt["error"] and vt["malicious"]:
            analysis["threat_level"] = "dangerous"
            analysis["summary"] += " | VirusTotal flagged this URL as malicious"
            external_risk += 30

    ips = [u for u in urls if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", u)]
    for ip in ips:
        abuse = abuseip_check(ip, settings.ABUSEIPDB_API_KEY)
        if not abuse["error"] and abuse["abuse_score"] >= 50:
            analysis["threat_level"] = "dangerous"
            analysis["summary"] += " | AbuseIPDB reports high abuse score"
            external_risk += 25
        gn = greynoise_check(ip, settings.GREYNOISE_API_KEY)
        if not gn["error"] and gn["noise"]:
            analysis["threat_level"] = "dangerous"
            analysis["summary"] += " | GreyNoise identifies this IP as malicious"
            external_risk += 20

    risk_score += external_risk
    risk_score = max(0, min(100, risk_score))

    if risk_score >= 60 and analysis["threat_level"] == "safe":
        analysis["threat_level"] = "suspicious"

    threat_signature = generate_threat_signature(analysis, sender_value, urls)
    related_threats = find_related_threats(db, current_user.id, threat_signature, urls, sender_value)
    update_threat_signature(db, threat_signature, analysis.get("threat_type", "unknown"), analysis["threat_level"], current_user.id)

    db_analysis = _save_analysis(request, analysis, db, current_user)
    for related in related_threats:
        propagation = ThreatPropagation(
            threat_signature=threat_signature,
            source_analysis_id=related["id"],
            target_analysis_id=db_analysis.id,
            propagation_type="same_threat",
            user_id=current_user.id
        )
        db.add(propagation)
    db.commit()
    db.refresh(db_analysis)

    increment_scan_usage(db, current_user.id)

    # Auto-publish to community (non-blocking)
    if analysis["threat_level"] in ["threat", "suspicious"]:
        indicator = urls[0] if urls else (request.sender or request.phone_number or "")
        threat_type = "url" if urls else ("email" if request.channel == "email" else "phone")
        auth_header = http_request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "")
        background_tasks.add_task(
            _publish_threat_background,
            indicator,
            threat_type,
            risk_score,
            analysis["threat_level"],
            db_analysis.id,
            token
        )

    return {
        "success": True,
        "id": db_analysis.id,
        "threat_level": analysis["threat_level"],
        "confidence": analysis["confidence"],
        "threat_type": analysis.get("threat_type", "unknown"),
        "summary": analysis["summary"],
        "indicators": analysis.get("indicators", []),
        "recommendation": analysis.get("recommendation", "allow"),
        "is_quarantined": db_analysis.is_quarantined,
        "channel": request.channel,
        "related_threats_count": len(related_threats),
        "risk_score": risk_score,
    }

# ----------------------
# ENDPOINTS: history, propagation-map, stats, threat-clusters
# ----------------------
@router.get("/history")
def get_history(db: Session = Depends(get_db), current_user: User = Depends(get_current_user), limit: int = 50):
    analyses = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id
    ).order_by(desc(EmailAnalysis.created_at)).limit(limit).all()
    return [
        {
            "id": a.id,
            "subject": a.subject,
            "sender": a.sender or a.phone_number,
            "channel": a.channel,
            "threat_level": a.threat_level,
            "threat_type": a.threat_type,
            "confidence": a.confidence,
            "summary": a.summary,
            "is_quarantined": a.is_quarantined,
            "hijack_detected": a.hijack_detected,
            "created_at": str(a.created_at)
        }
        for a in analyses
    ]

@router.get("/propagation-map")
def get_propagation_map(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    records = db.query(ThreatPropagation).filter(
        ThreatPropagation.user_id == current_user.id
    ).order_by(desc(ThreatPropagation.detected_at)).limit(200).all()
    nodes = {}
    edges = []
    for prop in records:
        if prop.source_analysis_id and prop.source_analysis_id not in nodes:
            src = db.query(EmailAnalysis).filter(EmailAnalysis.id == prop.source_analysis_id).first()
            if src:
                nodes[prop.source_analysis_id] = {
                    "id": src.id,
                    "name": src.sender or src.phone_number or "Unknown",
                    "threat_level": src.threat_level,
                    "timestamp": str(src.created_at)
                }
        if prop.target_analysis_id and prop.target_analysis_id not in nodes:
            tgt = db.query(EmailAnalysis).filter(EmailAnalysis.id == prop.target_analysis_id).first()
            if tgt:
                nodes[prop.target_analysis_id] = {
                    "id": tgt.id,
                    "name": tgt.sender or tgt.phone_number or "Unknown",
                    "threat_level": tgt.threat_level,
                    "timestamp": str(tgt.created_at)
                }
        if prop.source_analysis_id and prop.target_analysis_id:
            edges.append({
                "source": prop.source_analysis_id,
                "target": prop.target_analysis_id,
                "type": prop.propagation_type
            })
    return {"nodes": list(nodes.values()), "edges": edges}

@router.get("/stats")
def analysis_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total = db.query(EmailAnalysis).filter(EmailAnalysis.user_id == current_user.id).count()
    dangerous = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.threat_level == "dangerous"
    ).count()
    suspicious = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.threat_level == "suspicious"
    ).count()
    safe = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.threat_level == "safe"
    ).count()
    return {"total": total, "dangerous": dangerous, "suspicious": suspicious, "safe": safe}

@router.get("/threat-clusters")
def threat_clusters(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = db.query(
        EmailAnalysis.threat_type,
        EmailAnalysis.threat_level
    ).filter(
        EmailAnalysis.user_id == current_user.id
    ).all()
    clusters = {}
    for t, lvl in rows:
        key = f"{t}:{lvl}"
        clusters[key] = clusters.get(key, 0) + 1
    return clusters
