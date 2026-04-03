import hashlib
import re
import socket
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc, text
from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.ai_engine import analyze_threat
from app.core.billing import check_scan_limit, increment_scan_usage
from app.models.models import User, EmailAnalysis, EmailThread, ThreatPropagation, ThreatSignature
from app.schemas.schemas import EmailAnalysisRequest
from typing import List, Dict
from urllib.parse import urlparse
from typing import List, Tuple

router = APIRouter()

EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"
PHONE_REGEX = r"^\+?[0-9]{7,15}$"

DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "tempmail.com",
}

SUSPICIOUS_KEYWORDS = [
    "urgent", "immediately", "password", "bank", "verify", "click here",
    "account locked", "wire transfer", "payment", "invoice", "reset",
]

def is_valid_email(email: str) -> bool:
    return bool(re.match(EMAIL_REGEX, email or ""))

def is_valid_phone(phone: str) -> bool:
    return bool(re.match(PHONE_REGEX, phone or ""))

def split_email(email: str) -> Tuple[str, str]:
    if "@" not in email:
        return email, ""
    local, domain = email.split("@", 1)
    return local, domain.lower().strip()

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

def extract_urls(text: str) -> List[str]:
    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(url_pattern, text)
    return [urlparse(url).netloc or url for url in urls]


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
        recommendation_hebrew=analysis.get("recommendation_hebrew", ""),
        hijack_detected=analysis.get("hijack_detected", False),
        writing_style_change=analysis.get("writing_style_change", False),
        suspicious_domain=analysis.get("suspicious_domain", False),
        is_quarantined=analysis.get("recommendation", "allow") != "allow"
    )
    db.add(db_analysis)
    db.flush()

    return db_analysis

def is_valid_email(email: str) -> bool:
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

def is_valid_phone(phone: str) -> bool:
    return bool(re.match(r"^\+?[0-9]{7,15}$", phone))


@router.post("/analyze", response_model=dict)
def analyze_message(
    request: EmailAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # 1. VALIDATION

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

    # 2. CHECK USAGE LIMIT
    check_scan_limit(db, current_user.id)

    # 3. PREPROCESS
    urls = extract_urls(content)
    sender_value = request.sender or request.phone_number or ""
    missing_identity = not sender_value

    # 4. AI ANALYSIS
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

    # 5. SECURITY ENHANCEMENTS & RISK SCORING
    risk_score = 0

    # Missing sender
    if missing_identity:
        if analysis["threat_level"] == "safe":
            analysis["threat_level"] = "suspicious"
        analysis["confidence"] = min(analysis.get("confidence", 0.5), 0.5)
        analysis["summary"] += " | Warning: Missing sender/phone information"
        risk_score += 15

    # Email checks
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

    # Phone checks
    if request.channel in ["sms", "whatsapp"] and request.phone_number:
        risk_score += 5

    # URL checks
    url_info = analyze_urls_basic(urls)
    if url_info["has_suspicious_urls"]:
        analysis["threat_level"] = "suspicious"
        analysis["summary"] += " | Suspicious URLs detected"
        risk_score += 20

    # Keyword risk
    risk_score += keyword_risk_score(content)

    # Very short content
    if len(content) < 5:
        analysis["threat_level"] = "suspicious"
        analysis["summary"] += " | Very short content"
        risk_score += 10

    # Normalize risk score
    risk_score = max(0, min(100, risk_score))

    if risk_score >= 60 and analysis["threat_level"] == "safe":
        analysis["threat_level"] = "suspicious"

    # 6. THREAT SIGNATURE
    threat_signature = generate_threat_signature(
        analysis,
        sender_value,
        urls
    )

    related_threats = find_related_threats(
        db,
        current_user.id,
        threat_signature,
        urls,
        sender_value
    )

    update_threat_signature(
        db,
        threat_signature,
        analysis.get("threat_type", "unknown"),
        analysis["threat_level"],
        current_user.id
    )

    # 7. SAVE
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

    # 8. USAGE TRACKING
    increment_scan_usage(db, current_user.id)

    # 9. RESPONSE
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


@router.get("/history", response_model=List[dict])
def get_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50
):
    analyses = db.query(EmailAnalysis)\
        .filter(EmailAnalysis.user_id == current_user.id)\
        .order_by(desc(EmailAnalysis.created_at))\
        .limit(limit)\
        .all()

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


@router.get("/threads", response_model=List[dict])
def get_threads(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    threads = db.query(EmailThread).filter(
        EmailThread.user_id == current_user.id
    ).order_by(desc(EmailThread.last_seen)).all()

    result = []
    for thread in threads:
        hijack_risk = db.query(EmailAnalysis).filter(
            EmailAnalysis.thread_id == thread.id,
            EmailAnalysis.hijack_detected == True
        ).first() is not None

        message_count = db.query(EmailAnalysis).filter(
            EmailAnalysis.thread_id == thread.id
        ).count()

        result.append({
            "id": thread.id,
            "thread_identifier": thread.thread_identifier,
            "participants": thread.participants,
            "message_count": message_count,
            "hijack_risk": hijack_risk,
            "last_seen": str(thread.last_seen),
            "first_seen": str(thread.first_seen)
        })

    return result


@router.get("/stats", response_model=dict)
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total = db.query(EmailAnalysis).filter(EmailAnalysis.user_id == current_user.id).count()
    threats = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.threat_level == "threat"
    ).count()
    quarantined = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.is_quarantined == True
    ).count()
    hijack_detected = db.query(EmailAnalysis).filter(
        EmailAnalysis.user_id == current_user.id,
        EmailAnalysis.hijack_detected == True
    ).count()

    propagations = db.query(ThreatPropagation).filter(
        ThreatPropagation.user_id == current_user.id
    ).count()

    sql = text("""
        SELECT COUNT(*) FROM threat_signatures 
        WHERE affected_users @> :user_json
    """)
    result = db.execute(sql, {"user_json": f'[{current_user.id}]'}).scalar()

    return {
        "total_analyzed": total,
        "threats_detected": threats,
        "quarantined": quarantined,
        "safe": total - threats,
        "hijack_detected": hijack_detected,
        "propagation_links": propagations,
        "threat_clusters": result or 0
    }


@router.get("/propagation-map", response_model=dict)
def get_propagation_map(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    threat_signature: str = None
):
    cutoff_date = datetime.utcnow() - timedelta(days=30)

    if threat_signature:
        propagations = db.query(ThreatPropagation).filter(
            ThreatPropagation.threat_signature == threat_signature,
            ThreatPropagation.user_id == current_user.id
        ).all()
    else:
        propagations = db.query(ThreatPropagation).filter(
            ThreatPropagation.user_id == current_user.id,
            ThreatPropagation.detected_at >= cutoff_date
        ).all()

    nodes = {}
    edges = []

    for prop in propagations:
        if prop.source_analysis_id and prop.source_analysis_id not in nodes:
            source = db.query(EmailAnalysis).filter(
                EmailAnalysis.id == prop.source_analysis_id
            ).first()
            if source:
                nodes[prop.source_analysis_id] = {
                    "id": source.id,
                    "name": (source.sender or source.phone_number or "").split('@')[0],
                    "email": source.sender,
                    "phone": source.phone_number,
                    "channel": source.channel,
                    "threat_level": source.threat_level,
                    "threat_type": source.threat_type,
                    "timestamp": str(source.created_at),
                    "subject": source.subject
                }

        if prop.target_analysis_id and prop.target_analysis_id not in nodes:
            target = db.query(EmailAnalysis).filter(
                EmailAnalysis.id == prop.target_analysis_id
            ).first()
            if target:
                nodes[prop.target_analysis_id] = {
                    "id": target.id,
                    "name": (target.sender or target.phone_number or "").split('@')[0],
                    "email": target.sender,
                    "phone": target.phone_number,
                    "channel": target.channel,
                    "threat_level": target.threat_level,
                    "threat_type": target.threat_type,
                    "timestamp": str(target.created_at),
                    "subject": target.subject
                }

        if prop.source_analysis_id and prop.target_analysis_id:
            edges.append({
                "source": prop.source_analysis_id,
                "target": prop.target_analysis_id,
                "type": prop.propagation_type,
                "timestamp": str(prop.detected_at)
            })

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "total_propagations": len(propagations)
    }


@router.get("/threat-clusters", response_model=List[dict])
def get_threat_clusters(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    sql = text("""
        SELECT id, signature_hash, threat_type, threat_level,
               occurrences, first_seen, last_seen, affected_users
        FROM threat_signatures
        WHERE affected_users @> :user_json
        ORDER BY occurrences DESC
        LIMIT 20
    """)
    rows = db.execute(sql, {"user_json": f'[{current_user.id}]'}).fetchall()

    result = []
    for row in rows:
        recent_analyses = db.query(EmailAnalysis).filter(
            EmailAnalysis.user_id == current_user.id,
            EmailAnalysis.threat_type == row.threat_type
        ).order_by(desc(EmailAnalysis.created_at)).limit(5).all()

        result.append({
            "signature": row.signature_hash[:16],
            "threat_type": row.threat_type,
            "threat_level": row.threat_level,
            "occurrences": row.occurrences,
            "first_seen": str(row.first_seen),
            "last_seen": str(row.last_seen),
            "recent_emails": [
                {
                    "id": a.id,
                    "sender": a.sender or a.phone_number,
                    "channel": a.channel,
                    "subject": a.subject,
                    "created_at": str(a.created_at)
                }
                for a in recent_analyses
            ]
        })

    return result
