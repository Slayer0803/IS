"""
Semantic & NLP Text Analyzer for Real-World Phishing and Scam Detection.
Analyzes webpage textual content for psychological manipulation triggers,
urgency cues, credential requests, crypto wallet drainers, tech support scams,
package delivery scams, and financial extortion patterns.
"""
import re
from typing import Any, Dict, List


URGENCY_PATTERNS = [
    r"\b(within\s+\d+\s*(hours?|minutes?|days?)|immediate(ly)?|urgent(ly)?|act\s+now|action\s+required)\b",
    r"\b(expires?\s+(soon|in\s+\d+|today)|time\s+sensitive|critical\s+notice|instant\s+action)\b",
    r"\b(final\s+notice|last\s+chance|before\s+it'?s\s+too\s+late|promptly|session\s+(has\s+)?expired)\b",
    r"\b(limited\s+time|temporary\s+hold|suspended\s+within\s+\d+\s*hours?)\b"
]

THREAT_PATTERNS = [
    r"\b(account\s+(will\s+be|has\s+been|is)\s+(suspended|terminated|closed|restricted|locked|deactivated|on\s+hold))\b",
    r"\b(unauthorized\s+access|security\s+(breach|alert|incident)|suspicious\s+activity\s+detected)\b",
    r"\b(subject\s+to\s+legal\s+action|face\s+(prosecution|penalties)|terms\s+violation\s+notice|failure\s+to\s+verify)\b",
    r"\b(unusual\s+(sign-?in|login|activity)|device\s+not\s+recognized|access\s+(denied|blocked))\b"
]

CREDENTIAL_PATTERNS = [
    r"\b(enter\s+your\s+(password|passcode|pin|credentials?|secret\s+key|private\s+key|recovery\s+phrase|seed\s+phrase))\b",
    r"\b(confirm\s+your\s+(identity|password|account|social\s+security|ssn|seed\s+phrase))\b",
    r"\b(re-?enter\s+(password|pin)|verify\s+your\s+(login|credentials?|identity))\b",
    r"\b(sign\s*in\s+to\s+(verify|confirm|unlock|restore|claim))\b",
    r"\b(12[\s-]word\s+(seed|phrase|mnemonic)|24[\s-]word\s+(seed|phrase|mnemonic)|connect\s+wallet)\b",
    r"\b(username\b[\s\S]{0,60}\bpassword\b|login\s+credentials?|log\s*in\s+to\s+continue)\b"
]

FINANCIAL_PATTERNS = [
    r"\b(update\s+(billing|payment|credit\s+card|debit\s+card|bank\s+account))\b",
    r"\b(payment\s+declined|card\s+expired|billing\s+failure|unpaid\s+invoice|wire\s+transfer)\b",
    r"\b(claim\s+your\s+(refund|prize|reward|lottery|payout|bitcoin|crypto|airdrop|tokens?))\b",
    r"\b(cvv|card\s+number|expiration\s+date|security\s+code|ssn|social\s+security\s+number)\b"
]

SCAM_VECTORS = [
    # Crypto drainer
    r"\b(connect\s+(your\s+)?wallet|claim\s+airdrop|claim\s+free\s+tokens?|mint\s+now|sync\s+wallet)\b",
    # Tech support scam
    r"\b(call\s+(us|support|helpdesk|microsoft|apple)|toll-?free|virus\s+detected|trojan\s+spyware|call\s+\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b",
    # Delivery scam
    r"\b(package\s+(on\s+hold|delivery\s+failed|cannot\s+be\s+delivered)|update\s+(your\s+)?(address|delivery\s+address)|redelivery\s+fee|customs\s+duty)\b",
    # Prize/giveaway scam
    r"\b(congratulations\s+winner|you\s+have\s+won|spin\s+the\s+wheel|gift\s+card\s+winner|selected\s+user)\b",
    # Phishing / Deception / Social engineering indicators
    r"\b(phishing(\s+page)?|social\s+engineering|trick\s+you|mimics?\s+a\s+dialogue|out-?of-?date\s+software|fake\s+update)\b"
]


class TextSemanticAnalyzer:
    """
    Evaluates webpage semantic content and social engineering vectors.
    """

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Executes semantic analysis on visible text and returns structured risk indicators.
        """
        if not text or not isinstance(text, str):
            return {
                "text_risk": 0.0,
                "social_engineering": False,
                "credential_request": False,
                "financial_request": False,
                "urgency": False,
                "threatening_language": False,
                "account_verification": False,
                "indicators": [],
                "confidence": 0.50,
            }

        text_lower = text.lower()
        indicators: List[str] = []
        risk_score = 0.0

        # 1. Urgency detection
        urgency_matches = []
        for pat in URGENCY_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                urgency_matches.append(found[0][0] if isinstance(found[0], tuple) else found[0])
        has_urgency = len(urgency_matches) > 0
        if has_urgency:
            risk_score += 0.30
            indicators.append(f"Urgent psychological pressure detected: '{urgency_matches[0]}'")

        # 2. Threatening language
        threat_matches = []
        for pat in THREAT_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                threat_matches.append(found[0][0] if isinstance(found[0], tuple) else found[0])
        has_threats = len(threat_matches) > 0
        if has_threats:
            risk_score += 0.35
            indicators.append(f"Threatening account restriction or suspension language: '{threat_matches[0]}'")

        # 3. Credential requests
        cred_matches = []
        for pat in CREDENTIAL_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                cred_matches.append(found[0][0] if isinstance(found[0], tuple) else found[0])
        has_credential_request = len(cred_matches) > 0
        if has_credential_request:
            risk_score += 0.45
            indicators.append(f"Request for sensitive credentials, PINs, or recovery keys: '{cred_matches[0]}'")

        # 4. Financial requests
        fin_matches = []
        for pat in FINANCIAL_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                fin_matches.append(found[0][0] if isinstance(found[0], tuple) else found[0])
        has_financial_request = len(fin_matches) > 0
        if has_financial_request:
            risk_score += 0.30
            indicators.append(f"Financial, payment card, or tax refund collection language: '{fin_matches[0]}'")

        # 5. Specialized scam vectors (Crypto, Tech Support, Delivery, Prize)
        scam_matches = []
        for pat in SCAM_VECTORS:
            found = re.findall(pat, text_lower)
            if found:
                scam_matches.append(found[0][0] if isinstance(found[0], tuple) else found[0])
        has_scam_vector = len(scam_matches) > 0
        if has_scam_vector:
            risk_score += 0.40
            indicators.append(f"Active scam pattern identified (crypto/tech support/shipping/giveaway): '{scam_matches[0]}'")

        # Account verification pattern
        has_account_verification = "verify" in text_lower and ("account" in text_lower or "identity" in text_lower)
        if has_account_verification and not has_threats:
            risk_score += 0.15
            indicators.append("Account verification requested")

        # Clamp risk score
        text_risk = min(1.0, round(risk_score, 3))

        # Confidence calculation
        active_signals = sum([has_urgency, has_threats, has_credential_request, has_financial_request, has_scam_vector])
        confidence = round(min(0.98, 0.65 + active_signals * 0.08), 2)

        return {
            "text_risk": text_risk,
            "social_engineering": has_scam_vector or has_threats,
            "credential_request": has_credential_request,
            "financial_request": has_financial_request,
            "urgency": has_urgency,
            "threatening_language": has_threats,
            "account_verification": has_account_verification,
            "indicators": indicators,
            "confidence": confidence,
        }
