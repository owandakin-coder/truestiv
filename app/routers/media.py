from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.models import MediaAnalysis, User
from app.services.media_analysis import analyze_media_bytes

router = APIRouter()


@router.post("/analyze")
async def analyze_media(
    media_type: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    result = analyze_media_bytes(content, file.filename or "upload", media_type)
    record = MediaAnalysis(
        user_id=current_user.id,
        filename=result["filename"],
        media_type=result["media_type"],
        threat_level=result["threat_level"],
        risk_score=result["risk_score"],
        summary=result["summary"],
        ocr_text=result["ocr_text"],
        deepfake_score=result["deepfake_score"],
        detected_objects=result["detected_objects"],
        extra_data=result["metadata"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "success": True,
        "id": record.id,
        **result,
    }


@router.get("/history")
def media_history(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (
        db.query(MediaAnalysis)
        .filter(MediaAnalysis.user_id == current_user.id)
        .order_by(MediaAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "success": True,
        "items": [
            {
                "id": item.id,
                "filename": item.filename,
                "media_type": item.media_type,
                "threat_level": item.threat_level,
                "risk_score": item.risk_score,
                "summary": item.summary,
                "deepfake_score": item.deepfake_score,
                "detected_objects": item.detected_objects or [],
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in rows
        ],
    }
