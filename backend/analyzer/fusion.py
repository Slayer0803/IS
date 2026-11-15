"""
Multimodal Feature Fusion & Explainability Engine.
Integrates URL, Visual (VLM), Semantic/Text, and HTML structural risks into a unified risk score.
Synthesizes transparent, human-readable explanations categorizing detection evidence.
"""
from typing import Any, Dict, List, Tuple
from backend.config import (
    WEIGHT_URL,
    WEIGHT_VISUAL,
    WEIGHT_TEXT,
    WEIGHT_HTML,
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
)


class MultimodalFusionEngine:
    """
    Fuses predictions and signals from URL, Visual/VLM, NLP Text, and HTML analyzers.
    Computes a weighted risk score, final classification, confidence, and explainability breakdown.
    """

    def __init__(
        self,
        w_url: float = WEIGHT_URL,
        w_visual: float = WEIGHT_VISUAL,
        w_text: float = WEIGHT_TEXT,
        w_html: float = WEIGHT_HTML,
        threshold_safe: float = THRESHOLD_SAFE,
        threshold_suspicious: float = THRESHOLD_SUSPICIOUS,
    ):
        # Normalize weights so they sum to 1.0
        total_w = w_url + w_visual + w_text + w_html
        self.w_url = w_url / total_w
        self.w_visual = w_visual / total_w
        self.w_text = w_text / total_w
        self.w_html = w_html / total_w
        self.threshold_safe = threshold_safe
        self.threshold_suspicious = threshold_suspicious

    def fuse(
        self,
        url_analysis: Dict[str, Any],
        visual_analysis: Dict[str, Any],
        text_analysis: Dict[str, Any],
        html_analysis: Dict[str, Any],
        is_unreachable: bool = False,
        unreachable_reason: str = ""
    ) -> Dict[str, Any]:
        """
        Executes feature fusion and returns unified prediction and explainability report.
        """
        url_risk = float(url_analysis.get("url_risk", 0.0))
        visual_risk = float(visual_analysis.get("visual_risk", 0.0))
        text_risk = float(text_analysis.get("text_risk", 0.0))
        html_risk = float(html_analysis.get("html_risk", 0.0))

        # Initial weighted linear combination
        linear_risk = (
            self.w_url * url_risk
            + self.w_visual * visual_risk
            + self.w_text * text_risk
            + self.w_html * html_risk
        )

        # Zero-Day Threat Correlation Rules:
        is_brand_impersonation = visual_analysis.get("brand_impersonation", False)
        has_any_input = html_analysis.get("features", {}).get("num_input_fields", 0) > 0
        has_password_field = bool(html_analysis.get("features", {}).get("has_password_field", False))
        is_credential_harvesting = (
            visual_analysis.get("credential_harvesting", False)
            or has_password_field
            or (text_analysis.get("credential_request", False) and has_any_input)
        )
        cross_domain_post = len(html_analysis.get("features", {}).get("cross_domain_forms", [])) > 0
        has_social_eng = text_analysis.get("social_engineering", False)
        has_urgency = text_analysis.get("urgency", False)
        brand_in_sub = bool(url_analysis.get("features", {}).get("brand_in_subdomain", []))
        is_free_hosting_abuse = bool(url_analysis.get("features", {}).get("is_free_hosting_abuse", False))
        suspicious_kw_count = url_analysis.get("features", {}).get("suspicious_keywords_count", 0)

        # Gather explainability indicators
        url_indicators = list(url_analysis.get("indicators", []))
        visual_indicators = list(visual_analysis.get("visual_indicators", []))
        text_indicators = list(text_analysis.get("indicators", []))
        html_indicators = list(html_analysis.get("indicators", []))

        # UNREACHABLE / OFFLINE SITES HANDLING:
        if is_unreachable:
            if brand_in_sub:
                final_risk = 0.80
                classification = "PHISHING"
                confidence = 0.65
                summary_points = [
                    "⚠️ WARNING: Target host is offline or unreachable (DNS resolution failed or connection dropped).",
                    f"High-risk brand impersonation detected in URL targeting '{url_analysis.get('features', {}).get('brand_in_subdomain', ['brand'])[0]}' on unauthorized infrastructure.",
                    "Ephemeral zero-day phishing campaigns are frequently taken down within hours of deployment.",
                    "Do NOT visit or trust this domain if it comes back online."
                ]
            elif url_risk >= 0.35:
                final_risk = max(0.55, round(url_risk, 2))
                classification = "SUSPICIOUS"
                confidence = 0.45
                summary_points = [
                    "⚠️ WARNING: Target host is offline or unreachable (DNS resolution failed or host connection refused).",
                    f"The URL exhibits suspicious lexical anomalies and high-risk domain structure ({int(url_risk * 100)}% URL risk).",
                    "Zero-day phishing infrastructure often uses rapid DNS cloaking or is abandoned after campaigns.",
                    "Automated inspection cannot certify an unreachable host as safe."
                ]
            else:
                final_risk = 0.35
                classification = "SUSPICIOUS"
                confidence = 0.25
                diag_msg = unreachable_reason[:80] if unreachable_reason else "Host resolution failed / Connection timeout"
                summary_points = [
                    "⚠️ WARNING: Target host is offline, unreachable, or does not exist.",
                    f"Network diagnostic: {diag_msg}.",
                    "Live visual layout and DOM forms could not be retrieved to certify safety.",
                    "Confidence is low (25%) due to absent live server responses. The domain cannot be verified as safe."
                ]

            return {
                "classification": classification,
                "risk_score": final_risk,
                "confidence": confidence,
                "weights_used": {
                    "url": round(self.w_url, 3),
                    "visual": round(self.w_visual, 3),
                    "text": round(self.w_text, 3),
                    "html": round(self.w_html, 3),
                },
                "sub_scores": {
                    "url_score": url_risk,
                    "visual_score": visual_risk,
                    "text_score": text_risk,
                    "html_score": html_risk,
                },
                "categorized_indicators": {
                    "url_indicators": url_indicators,
                    "visual_indicators": visual_indicators,
                    "text_indicators": text_indicators,
                    "technical_indicators": html_indicators,
                },
                "explanation_summary": summary_points,
            }

        final_risk = linear_risk

        # 1. Visual Brand Impersonation on unverified domain (Near-certain phishing)
        if is_brand_impersonation:
            final_risk = max(final_risk, 0.88 if is_credential_harvesting else 0.80)

        # 1b. Brand spoofing in URL subdomain or PaaS cloud prefix
        if brand_in_sub:
            final_risk = max(final_risk, 0.85 if is_credential_harvesting else 0.78)

        # 2. Form posts credentials to completely different third-party domain
        if cross_domain_post:
            final_risk = max(final_risk, 0.82)

        # 3. High Visual Risk (Scareware / Tech Support / Crypto Drainer / Package Delivery / Zero-Day form)
        if visual_risk >= 0.70:
            final_risk = max(final_risk, visual_risk)

        # 4. Critical Text Risk (Crypto wallet drainer, tech support scam, delivery fee, prize scam)
        if text_risk >= 0.65:
            final_risk = max(final_risk, 0.78)

        # 4b. Credential harvesting with social engineering or deceptive context
        if is_credential_harvesting and (has_social_eng or "phishing" in url_analysis.get("features", {}).get("url", "").lower()):
            final_risk = max(final_risk, 0.85)

        # 4c. Active Credential Harvesting on PaaS or Unverified Cloud
        if is_credential_harvesting and (is_free_hosting_abuse or url_risk >= 0.20):
            final_risk = max(final_risk, 0.80)

        # 5. Multi-modal Red Flag Convergence (Suspicious URL + Credential ask or PaaS abuse)
        if url_risk >= 0.35 and is_credential_harvesting:
            final_risk = max(final_risk, 0.78)
        elif is_free_hosting_abuse and (suspicious_kw_count > 0 or is_credential_harvesting):
            final_risk = max(final_risk, 0.75)
        elif url_risk >= 0.50 and (has_urgency and has_social_eng):
            final_risk = max(final_risk, 0.72)
        elif url_risk >= 0.40 and (has_urgency or has_social_eng):
            final_risk = max(final_risk, 0.58)

        # 6. Dangerous URL with high lexical/structural manipulation or IP host
        if url_risk >= 0.60:
            final_risk = max(final_risk, 0.70)
        elif url_risk >= 0.40 and (visual_risk == 0.0 and text_risk == 0.0):
            # Target website is offline, cloaking, or blocking crawler, but URL itself has severe anomalies
            final_risk = max(final_risk, min(0.68, url_risk * 1.35))

        # High-Trust Whitelist Domains (Legitimate encyclopedias, government, and documentation portals)
        hostname = str(url_analysis.get("features", {}).get("hostname", "")).lower()
        is_high_trust = any(
            hostname == d or hostname.endswith("." + d)
            for d in [
                "wikipedia.org", "wikimedia.org", "github.com", "gitlab.com",
                "google.com", "apple.com", "microsoft.com", "mozilla.org", "w3.org",
                "ietf.org", "nih.gov", "cdc.gov", "nasa.gov", "arxiv.org",
                "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "bloomberg.com"
            ]
        ) or any(hostname.endswith(t) for t in [".edu", ".gov", ".mil"])

        if is_high_trust and not cross_domain_post and not has_password_field:
            final_risk = 0.0
            classification = "SAFE"
            confidence = 0.98
        else:
            final_risk = min(1.0, max(0.0, round(final_risk, 3)))
            # Determine Classification
            if final_risk <= self.threshold_safe:
                classification = "SAFE"
            elif final_risk <= self.threshold_suspicious:
                classification = "SUSPICIOUS"
            else:
                classification = "PHISHING"

        # Calculate Confidence Score based on cross-modal consensus
        risks = [url_risk, visual_risk, text_risk, html_risk]
        # Standard deviation / agreement across modalities
        avg_risk = sum(risks) / len(risks)
        variance = sum((r - avg_risk) ** 2 for r in risks) / len(risks)
        
        # When risks are either consistently high (clear phish) or consistently low (clear safe),
        # confidence is highest.
        if final_risk >= 0.80 or final_risk <= 0.15:
            confidence = round(min(0.98, 0.85 + (1.0 - min(1.0, variance * 2)) * 0.12), 2)
        elif final_risk >= 0.65:
            confidence = round(0.88 - variance * 0.15, 2)
        else:
            confidence = round(0.75 + (0.5 - abs(final_risk - 0.5)) * 0.20, 2)

        # Gather explainability indicators
        url_indicators = url_analysis.get("indicators", [])
        visual_indicators = visual_analysis.get("visual_indicators", [])
        text_indicators = text_analysis.get("indicators", [])
        html_indicators = html_analysis.get("indicators", [])

        # Human-Readable Explanation Summary
        summary_points: List[str] = []
        if classification == "PHISHING":
            if is_brand_impersonation:
                impersonated = visual_analysis.get("impersonated_brand") or "a known brand"
                summary_points.append(
                    f"Visual analysis identified brand impersonation of {impersonated} on an unauthorized zero-day domain."
                )
            if is_credential_harvesting:
                summary_points.append("The page actively requests and harvests account credentials or passwords.")
            if cross_domain_post:
                summary_points.append("Form submissions are routed to an external third-party domain.")
            if text_analysis.get("social_engineering"):
                summary_points.append("Social engineering deception cues or psychological manipulation triggers detected.")
            if text_analysis.get("urgency"):
                summary_points.append("Psychological urgency or account suspension threats were detected.")
            if not summary_points:
                summary_points.append(
                    "Multiple high-risk anomalies across URL structure, DOM elements, and visual cues indicate a deceptive page."
                )
        elif classification == "SUSPICIOUS":
            summary_points.append(
                "The page exhibits anomalies such as unverified credentials handling or suspicious structural patterns, but does not conclusively prove brand spoofing."
            )
            if text_analysis.get("urgency"):
                summary_points.append("Urgent language was observed.")
            if url_risk > 0.4:
                summary_points.append("The URL structure contains non-standard lexical features.")
        else:
            summary_points.append(
                "No deceptive brand impersonation, credential harvesting forms, or suspicious URL characteristics were found. The site appears legitimate."
            )

        return {
            "classification": classification,
            "risk_score": final_risk,
            "confidence": confidence,
            "weights_used": {
                "url": round(self.w_url, 3),
                "visual": round(self.w_visual, 3),
                "text": round(self.w_text, 3),
                "html": round(self.w_html, 3),
            },
            "sub_scores": {
                "url_score": url_risk,
                "visual_score": visual_risk,
                "text_score": text_risk,
                "html_score": html_risk,
            },
            "categorized_indicators": {
                "url_indicators": url_indicators,
                "visual_indicators": visual_indicators,
                "text_indicators": text_indicators,
                "technical_indicators": html_indicators,
            },
            "explanation_summary": summary_points,
        }

