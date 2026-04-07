from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    Text, Float, ForeignKey, JSON, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

# ======================
# USER
# ======================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    analyses = relationship("EmailAnalysis", back_populates="user", cascade="all, delete-orphan")
    trusted_contacts = relationship("TrustedContact", back_populates="user", cascade="all, delete-orphan")
    threat_reports = relationship("ThreatReport", back_populates="user", cascade="all, delete-orphan")
    email_threads = relationship("EmailThread", back_populates="user", cascade="all, delete-orphan")
    subscription = relationship("Subscription", back_populates="user", uselist=False)


# ======================
# TRUSTED CONTACT
# ======================
class TrustedContact(Base):
    __tablename__ = "trusted_contacts"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    email = Column(String(255), nullable=False, index=True)
    name = Column(String(100))

    trust_level = Column(String(20), default="medium")  # low / medium / high

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="trusted_contacts")


# ======================
# EMAIL THREAD
# ======================
class EmailThread(Base):
    __tablename__ = "email_threads"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    thread_identifier = Column(String(255), index=True)
    participants = Column(JSON, default=list)

    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", back_populates="email_threads")
    messages = relationship("EmailAnalysis", back_populates="thread", cascade="all, delete-orphan")


# ======================
# EMAIL ANALYSIS
# ======================
class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    thread_id = Column(Integer, ForeignKey("email_threads.id"), nullable=True)

    # Message Info
    subject = Column(String(255))
    sender = Column(String(255), index=True)
    phone_number = Column(String(50), nullable=True)

    channel = Column(String(20), default="email")  # email / sms / whatsapp
    content = Column(Text, nullable=False)

    # AI Results
    threat_level = Column(String(20))
    threat_type = Column(String(50), default="unknown")

    confidence = Column(Float)

    summary = Column(Text)
    explanation_hebrew = Column(Text)

    indicators = Column(JSON, default=list)

    recommendation = Column(String(255))
    recommendation_hebrew = Column(Text)

    # Detection Flags
    hijack_detected = Column(Boolean, default=False)
    writing_style_change = Column(Boolean, default=False)
    suspicious_domain = Column(Boolean, default=False)
    is_quarantined = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", back_populates="analyses")
    thread = relationship("EmailThread", back_populates="messages")


# ======================
# THREAT REPORT
# ======================
class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    title = Column(String(255), nullable=False)
    description = Column(Text)

    threat_type = Column(String(50))
    severity = Column(String(20))  # low / medium / high / critical

    is_verified = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="threat_reports")


# ======================
# THREAT PROPAGATION
# ======================
class ThreatPropagation(Base):
    __tablename__ = "threat_propagations"

    id = Column(Integer, primary_key=True, index=True)

    threat_signature = Column(String(255), index=True)

    source_analysis_id = Column(Integer, ForeignKey("email_analyses.id"))
    target_analysis_id = Column(Integer, ForeignKey("email_analyses.id"))

    propagation_type = Column(String(50))

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    detected_at = Column(DateTime(timezone=True), server_default=func.now())

    source_analysis = relationship("EmailAnalysis", foreign_keys=[source_analysis_id])
    target_analysis = relationship("EmailAnalysis", foreign_keys=[target_analysis_id])
    user = relationship("User")


# ======================
# THREAT SIGNATURE
# ======================
class ThreatSignature(Base):
    __tablename__ = "threat_signatures"

    id = Column(Integer, primary_key=True, index=True)

    signature_hash = Column(String(255), unique=True, index=True)

    threat_type = Column(String(50))
    threat_level = Column(String(20))

    occurrences = Column(Integer, default=1)
    affected_users = Column(JSON, default=list)

    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now())


# ======================
# COMMUNITY MODELS
# ======================
class CommunityThreat(Base):
    __tablename__ = "community_threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(50), index=True, nullable=False)   # ip, url, email
    indicator = Column(String(500), index=True, nullable=False)    # the actual value
    risk_score = Column(Integer)
    threat_level = Column(String(20))
    source_analysis_id = Column(Integer, ForeignKey("email_analyses.id"), nullable=True)
    published_by = Column(Integer, ForeignKey("users.id"))
    raw_intel = Column(JSON, default=list)
    published_at = Column(DateTime(timezone=True), server_default=func.now())

    # Engagement fields
    likes_count = Column(Integer, default=0)
    comments_count = Column(Integer, default=0)
    score = Column(Integer, default=0)
    is_moderated = Column(Boolean, default=False)

    # Optional title/description (can be auto-generated from indicator)
    title = Column(String, nullable=True)
    description = Column(String, nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    threat_id = Column(Integer, ForeignKey("community_threats.id"), nullable=True)
    source = Column(String, index=True)
    title = Column(String)
    body = Column(String)
    severity = Column(String, default="info")
    read = Column(Boolean, default=False)
    extra_data = Column(JSON, default={})   # renamed from 'metadata'
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class CommunityComment(Base):
    __tablename__ = "community_comments"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("community_threats.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    body = Column(Text, nullable=False)
    parent_id = Column(Integer, ForeignKey("community_comments.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    edited_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    threat = relationship("CommunityThreat", foreign_keys=[threat_id])
    user = relationship("User", foreign_keys=[user_id])
    parent = relationship("CommunityComment", remote_side=[id])


class CommunityLike(Base):
    __tablename__ = "community_likes"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("community_threats.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint('threat_id', 'user_id', name='unique_threat_user_like'),)


# ======================
# BILLING MODELS
# ======================
class Plan(Base):
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # free, pro, enterprise
    display_name = Column(String, nullable=False)
    price_monthly = Column(Float, default=0)
    price_yearly = Column(Float, default=0)
    scans_per_month = Column(Integer, default=10)  # -1 = unlimited
    api_access = Column(Boolean, default=False)
    multi_user = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    subscriptions = relationship("Subscription", back_populates="plan")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=False)
    status = Column(String, default="active")  # active, cancelled, expired
    billing_cycle = Column(String, default="monthly")  # monthly, yearly
    stripe_subscription_id = Column(String, nullable=True)
    stripe_customer_id = Column(String, nullable=True)
    current_period_start = Column(DateTime(timezone=True))
    current_period_end = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="subscription")
    plan = relationship("Plan", back_populates="subscriptions")


class ScanUsage(Base):
    __tablename__ = "scan_usage"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    month = Column(String, nullable=False)  # "2026-04"
    scan_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class UserAPIKey(Base):
    __tablename__ = "user_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(100), nullable=False, index=True)
    label = Column(String(150), nullable=False)
    masked_value = Column(String(30), nullable=False)
    encrypted_value = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User")


class MediaAnalysis(Base):
    __tablename__ = "media_analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255))
    media_type = Column(String(30), nullable=False, index=True)
    threat_level = Column(String(20), nullable=False, default="safe")
    risk_score = Column(Integer, default=0)
    summary = Column(Text)
    ocr_text = Column(Text)
    deepfake_score = Column(Float, default=0)
    detected_objects = Column(JSON, default=list)
    extra_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")


class IPScanObservation(Base):
    __tablename__ = "ip_scan_observations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String(64), nullable=False, index=True)
    threat_level = Column(String(20), nullable=False, default="safe")
    risk_score = Column(Integer, default=0)
    country = Column(String(120))
    city = Column(String(120))
    region = Column(String(120))
    isp = Column(String(255))
    organization = Column(String(255))
    latitude = Column(Float)
    longitude = Column(Float)
    source = Column(String(120), default="scanner")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_type = Column(String(30), nullable=False, index=True)
    indicator = Column(String(500), nullable=False, index=True)
    normalized_indicator = Column(String(500), nullable=False, index=True)
    threat_level = Column(String(20), nullable=False, default="safe", index=True)
    risk_score = Column(Integer, default=0)
    confidence = Column(Float, default=0)
    country = Column(String(120))
    source = Column(String(120), default="scanner")
    summary = Column(Text)
    result = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    user = relationship("User")
