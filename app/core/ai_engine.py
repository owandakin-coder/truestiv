import json
import re
from app.core.config import settings


def analyze_threat(content: str, content_type: str = "email", sender: str = "", subject: str = "", conversation_history: list = None) -> dict:
    """
    Analyze email/SMS/WhatsApp for threats with optional conversation context
    """
    return _mock_analysis_with_hijack(content, sender, subject, conversation_history, content_type)


def _mock_analysis_with_hijack(content: str, sender: str = "", subject: str = "", conversation_history: list = None, channel: str = "email") -> dict:
    """
    Mock analysis with hijack detection logic, adapted for channel
    """
    text = f"{content or ''} {sender or ''} {subject or ''}".lower()
    
    # General phishing keywords (expanded)
    phishing = [
        "verify", "suspended", "click here", "urgent", "compromised",
        "login", "password", "account", "fake-paypal", "paypal", "secure",
        "locked", "limited", "access", "restricted", "alert", "security",
        "fraud", "unusual", "activity", "bank", "payment", "invoice",
        "transaction", "confirm", "update", "immediately", "asap", "now",
        "link", "http", "https", "bit.ly", "tinyurl", "short.link"
    ]
    
    # SMS/WhatsApp specific keywords
    sms_phishing = [
        "code", "verification code", "2fa", "otp", "bank", "transfer",
        "payment", "delivery", "package", "courier", "whatsapp", "sms", "text"
    ]
    
    # Calculate score based on channel
    if channel in ["sms", "whatsapp"]:
        p_score = sum(1 for kw in phishing if kw in text) + sum(1 for kw in sms_phishing if kw in text)
        # Short links
        if re.search(r'bit\.ly|tinyurl|short\.link|ow\.ly|is\.gd|goo\.gl|t\.co', text):
            p_score += 2
        # Suspicious phone numbers (Israeli format example)
        if re.search(r'\b0[23489]\d{7,8}\b', text):
            p_score += 1
        # Urgent messages with emojis
        if re.search(r'[⚠️🔴❗🚨]', text):
            p_score += 1
        # Detect any URL
        if re.search(r'https?://|www\.', text):
            p_score += 1
    else:
        p_score = sum(1 for kw in phishing if kw in text)
        # Detect URL in email as well
        if re.search(r'https?://|www\.', text):
            p_score += 1
    
    # Homograph attack detection (Cyrillic)
    homograph_suspicious = False
    cyrillic_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у', 'в', 'н', 'к']
    for char in cyrillic_chars:
        if char in sender.lower():
            homograph_suspicious = True
            break
    
    # Writing style change detection
    style_change = False
    if conversation_history and len(conversation_history) > 0:
        urgency_indicators = ["urgent", "immediately", "asap", "right away", "now", "immediate"]
        if any(word in text for word in urgency_indicators):
            prev_text = conversation_history[0].lower()
            if not any(word in prev_text for word in urgency_indicators):
                style_change = True
    
    hijack_detected = style_change or homograph_suspicious
    
    # Determine threat level
    if hijack_detected and p_score >= 1:
        return {
            "success": True,
            "analysis": {
                "threat_level": "threat",
                "confidence": min(98, 75 + p_score * 5),
                "threat_type": "conversation_hijack",
                "summary": f"⚠️ CONVERSATION HIJACK DETECTED! This {channel} shows signs of a thread hijacking attack.",
                "explanation": f"This {channel} appears to be part of an ongoing conversation takeover. Sudden urgency and suspicious sender indicators.",
                "indicators": ["Sudden tone change", "Urgency introduced", "Suspicious sender" if homograph_suspicious else "Unusual language pattern"],
                "recommendation": "block",
                "hijack_detected": True,
                "writing_style_change": style_change,
                "suspicious_domain": homograph_suspicious
            }
        }
    elif p_score >= 2:
        return {
            "success": True,
            "analysis": {
                "threat_level": "threat",
                "confidence": 85,
                "threat_type": "phishing",
                "summary": f"This {channel} contains multiple phishing indicators.",
                "explanation": f"Detected suspicious keywords and possible malicious intent. Likely a phishing attempt.",
                "indicators": ["Suspicious URL", "Urgency language", "Fake domain"],
                "recommendation": "block",
                "hijack_detected": False,
                "writing_style_change": False,
                "suspicious_domain": homograph_suspicious
            }
        }
    elif p_score >= 1:
        return {
            "success": True,
            "analysis": {
                "threat_level": "suspicious",
                "confidence": 65,
                "threat_type": "suspicious",
                "summary": f"This {channel} contains suspicious elements.",
                "explanation": f"The message exhibits some unusual patterns that warrant further inspection.",
                "indicators": ["Unusual sender", "Suspicious content pattern"],
                "recommendation": "quarantine",
                "hijack_detected": False,
                "writing_style_change": False,
                "suspicious_domain": homograph_suspicious
            }
        }
    else:
        return {
            "success": True,
            "analysis": {
                "threat_level": "safe",
                "confidence": 90,
                "threat_type": "legitimate",
                "summary": f"This {channel} appears legitimate.",
                "explanation": f"No significant threat indicators found. The message seems safe.",
                "indicators": [],
                "recommendation": "allow",
                "hijack_detected": False,
                "writing_style_change": False,
                "suspicious_domain": False
            }
        }
