import logging
import os
import re
from functools import lru_cache
from typing import Any, Dict, List

from app.core.config import settings

logger = logging.getLogger(__name__)

PHISHING_KEYWORDS = {
    "verify", "suspended", "click here", "urgent", "compromised", "login",
    "password", "account", "paypal", "secure", "locked", "limited", "access",
    "restricted", "alert", "security", "fraud", "unusual", "activity", "bank",
    "payment", "invoice", "transaction", "confirm", "update", "immediately",
    "asap", "wire transfer", "gift cards", "wallet", "crypto", "recovery phrase",
}
SMS_KEYWORDS = {
    "code", "verification code", "2fa", "otp", "delivery", "package",
    "courier", "sms", "text", "whatsapp",
}
ZERO_SHOT_LABELS = [
    "phishing",
    "business email compromise",
    "conversation hijack",
    "credential theft",
    "benign business communication",
]


@lru_cache(maxsize=1)
def _load_zero_shot_classifier():
    try:
        os.environ.setdefault(
            "TRANSFORMERS_CACHE",
            getattr(settings, "TRANSFORMERS_CACHE_DIR", ".cache/huggingface"),
        )
        from transformers import pipeline

        return pipeline(
            "zero-shot-classification",
            model=getattr(
                settings,
                "HF_ZERO_SHOT_MODEL",
                "MoritzLaurer/deberta-v3-base-zeroshot-v1.1-all-33",
            ),
        )
    except Exception as exc:
        logger.warning("Transformer classifier unavailable, using heuristic fallback: %s", exc)
        return None


def _heuristic_score(text: str, channel: str) -> Dict[str, Any]:
    keyword_hits = [keyword for keyword in PHISHING_KEYWORDS if keyword in text]
    sms_hits = [keyword for keyword in SMS_KEYWORDS if keyword in text]
    score = len(keyword_hits) * 12

    if channel in {"sms", "whatsapp"}:
        score += len(sms_hits) * 8

    if re.search(r"https?://|www\.", text):
        score += 12
    if re.search(r"bit\.ly|tinyurl|t\.co|short\.link|is\.gd|goo\.gl", text):
        score += 18
    if re.search(r"\b(urgent|immediately|right away|today)\b", text):
        score += 12

    threat_type = "legitimate"
    if score >= 70:
        threat_type = "phishing"
    elif score >= 40:
        threat_type = "suspicious"

    return {
        "score": max(0, min(100, score)),
        "keyword_hits": keyword_hits + sms_hits,
        "threat_type": threat_type,
    }


def _detect_hijack(text: str, sender: str, conversation_history: List[str] | None) -> Dict[str, Any]:
    cyrillic_chars = {"а", "е", "о", "р", "с", "х", "у", "в", "н", "к"}
    homograph_suspicious = any(char in (sender or "").lower() for char in cyrillic_chars)
    style_change = False

    if conversation_history:
        previous_text = " ".join(conversation_history[:2]).lower()
        urgent_now = any(word in text for word in ["urgent", "asap", "immediately", "wire transfer"])
        urgent_before = any(word in previous_text for word in ["urgent", "asap", "immediately", "wire transfer"])
        if urgent_now and not urgent_before:
            style_change = True

    return {
        "hijack_detected": homograph_suspicious or style_change,
        "writing_style_change": style_change,
        "suspicious_domain": homograph_suspicious,
    }


def _label_to_summary(label: str, channel: str) -> tuple[str, str]:
    if label == "conversation hijack":
        return "conversation_hijack", f"This {channel} shows signs of a conversation hijack attack."
    if label == "business email compromise":
        return "business_email_compromise", f"This {channel} matches business email compromise patterns."
    if label == "credential theft":
        return "credential_theft", f"This {channel} is attempting to steal credentials."
    if label == "phishing":
        return "phishing", f"This {channel} contains strong phishing indicators."
    return "legitimate", f"This {channel} appears legitimate."


def analyze_threat(
    content: str,
    content_type: str = "email",
    sender: str = "",
    subject: str = "",
    conversation_history: list | None = None,
) -> dict:
    text = f"{content or ''}\n{sender or ''}\n{subject or ''}".strip()
    lowered = text.lower()
    heuristic = _heuristic_score(lowered, content_type)
    hijack = _detect_hijack(lowered, sender, conversation_history or [])
    classifier = _load_zero_shot_classifier()

    top_label = heuristic["threat_type"]
    model_score = heuristic["score"] / 100

    if classifier and text:
        try:
            result = classifier(text[:2500], ZERO_SHOT_LABELS, multi_label=False)
            top_label = result["labels"][0]
            model_score = max(model_score, float(result["scores"][0]))
        except Exception as exc:
            logger.warning("Transformer inference failed, continuing with heuristic result: %s", exc)

    mapped_type, summary = _label_to_summary(top_label, content_type)
    confidence = min(99, int(max(model_score * 100, heuristic["score"])))
    indicators = list(dict.fromkeys(heuristic["keyword_hits"]))[:6]

    if hijack["hijack_detected"]:
        mapped_type = "conversation_hijack"
        summary = f"This {content_type} shows signs of a conversation hijack attack."
        confidence = max(confidence, 82)
        indicators = list(dict.fromkeys(indicators + ["tone shift", "sender anomaly"]))[:6]

    if confidence >= 75:
        threat_level = "threat"
        recommendation = "block"
    elif confidence >= 45:
        threat_level = "suspicious"
        recommendation = "quarantine"
    else:
        threat_level = "safe"
        recommendation = "allow"

    if mapped_type == "legitimate" and threat_level != "safe":
        mapped_type = "suspicious"

    return {
        "success": True,
        "analysis": {
            "threat_level": threat_level,
            "confidence": confidence,
            "threat_type": mapped_type,
            "summary": summary,
            "explanation_hebrew": summary,
            "indicators": indicators,
            "recommendation": recommendation,
            "hijack_detected": hijack["hijack_detected"],
            "writing_style_change": hijack["writing_style_change"],
            "suspicious_domain": hijack["suspicious_domain"],
            "model_source": "transformers" if classifier else "heuristic",
        },
    }
