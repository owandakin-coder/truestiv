import hashlib
import re
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

router = APIRouter()


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


@router.post("/analyze", response_model=dict)
def analyze_message(
    request: EmailAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check scan limit before analysis
    check_scan_limit(db, current_user.id)

    urls = extract_urls(request.content)
    conversation_history = []

    result = analyze_threat(
        content=request.content,
        content_type=request.channel,
        sender=request.sender or request.phone_number or "",
        subject=request.subject or "",
        conversation_history=conversation_history
    )

    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Analysis failed"))

    analysis = result["analysis"]

    sender_for_sig = request.sender or request.phone_number or ""
    threat_signature = generate_threat_signature(analysis, sender_for_sig, urls)
    related_threats = find_related_threats(db, current_user.id, threat_signature, urls, sender_for_sig)

    update_threat_signature(
        db,
        threat_signature,
        analysis.get("threat_type", "unknown"),
        analysis["threat_level"],
        current_user.id
    )

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

    # Update scan usage after successful analysis
    increment_scan_usage(db, current_user.id)

    return {
        "success": True,
        "id": db_analysis.id,
        "threat_level": analysis["threat_level"],
        "confidence": analysis["confidence"],
        "threat_type": analysis.get("threat_type", "unknown"),
        "summary": analysis["summary"],
        "explanation_hebrew": analysis.get("explanation_hebrew", ""),
        "indicators": analysis.get("indicators", []),
        "recommendation": analysis.get("recommendation", "allow"),
        "recommendation_hebrew": analysis.get("recommendation_hebrew", ""),
        "is_quarantined": db_analysis.is_quarantined,
        "hijack_detected": analysis.get("hijack_detected", False),
        "writing_style_change": analysis.get("writing_style_change", False),
        "suspicious_domain": analysis.get("suspicious_domain", False),
        "channel": request.channel,
        "related_threats_count": len(related_threats)
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