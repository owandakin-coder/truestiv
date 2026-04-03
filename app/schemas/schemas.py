from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, List

class ThreatPublishRequest(BaseModel):
    threat_type: str   # 'ip', 'url', 'domain', 'email'
    indicator: str
    risk_score: Optional[int] = None
    threat_level: str
    analysis_id: Optional[int] = None

    
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class EmailAnalysisRequest(BaseModel):
    subject: Optional[str] = ""          # למייל
    sender: Optional[str] = ""           # למייל
    phone_number: Optional[str] = None   # ל-SMS/WhatsApp
    content: str
    channel: str = "email"               # email, sms, whatsapp


class EmailAnalysisResponse(BaseModel):
    id: int
    threat_level: str
    threat_type: str
    confidence: float
    summary: str
    explanation_hebrew: Optional[str] = None
    indicators: List[str] = []
    recommendation: str
    recommendation_hebrew: Optional[str] = None
    is_quarantined: bool
    hijack_detected: bool = False
    writing_style_change: bool = False
    suspicious_domain: bool = False
    channel: str = "email"
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatReportCreate(BaseModel):
    title: str
    description: str
    threat_type: str
    severity: str


class ThreatReportResponse(BaseModel):
    id: int
    title: str
    threat_type: str
    severity: str
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ThreadResponse(BaseModel):
    id: int
    thread_identifier: str
    participants: List[str]
    message_count: int
    hijack_risk: bool
    last_seen: str
    first_seen: str
