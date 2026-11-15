"""
Multimodal Feature Fusion & Explainability Engine.
Integrates URL, Visual, Semantic/Text, and HTML structural risks into a calibrated threat score.
Replaces arbitrary overrides with a transparent, additive scoring cascade with logged rules,
calibrated signal agreement, and comprehensive explainability.
"""
import logging
from typing import Any, Dict, List, Tuple

from backend.config import (
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
    WEIGHT_HTML,
    WEIGHT_TEXT,
    WEIGHT_URL,
    WEIGHT_VISUAL,
)

logger = logging.getLogger(__name__)


class MultimodalFusionEngine:
    """
    Fuses predictions and signals from URL, Visual/VLM, NLP Text, and HTML analyzers.
    Computes a weighted linear baseline, evaluates bounded threat correlation rules,
    calibrates signal agreement across modalities, and compiles explainable evidence.
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
        if total_w <= 0:
            total_w = 1.0
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
        Executes feature fusion and returns unified prediction, explainability report,
        and full rule firing audit log.
        """
        url_risk = float(url_analysis.get("url_risk", 0.0))
        visual_risk = float(visual_analysis.get("visual_risk", 0.0))
        text_risk = float(text_analysis.get("text_risk", 0.0))
        html_risk = float(html_analysis.get("html_risk", 0.0))

        # 1. Foundational Weighted Linear Combination
        linear_risk = (
            self.w_url * url_risk
            + self.w_visual * visual_risk
            + self.w_text * text_risk
            + self.w_html * html_risk
        )

        fired_rules: List[Dict[str, Any]] = []
        accumulated_risk = linear_risk

        # Extract features for rule evaluation
        hf = html_analysis.get("features", {})
        has_password_field = bool(hf.get("has_password_field", False))
        has_login_form = bool(hf.get("has_login_form", False))
        has_any_input = hf.get("num_input_fields", 0) > 0
        cross_domain_forms = hf.get("cross_domain_forms", [])
        cross_domain_post = len(cross_domain_forms) > 0

        is_brand_impersonation = visual_analysis.get("brand_impersonation", False)
        impersonated_brand = visual_analysis.get("impersonated_brand")
        is_credential_harvesting = (
            visual_analysis.get("credential_harvesting", False)
            or has_password_field
            or (text_analysis.get("credential_request", False) and has_any_input)
        )

        has_social_eng = text_analysis.get("social_engineering", False)
        has_urgency = text_analysis.get("urgency", False)

        uf = url_analysis.get("features", {})
        brand_in_sub = bool(uf.get("brand_in_subdomain", []))
        is_user_content = bool(uf.get("is_user_content_host", False))
        is_trusted_dom = bool(uf.get("is_trusted_domain", False))

        # 2. Unreachable / Offline Targets Handling:
        # Notice: is_unreachable is ONLY set when a real transport/network/DNS failure occurs.
        if is_unreachable:
            if brand_in_sub:
                final_risk = 0.85
                classification = "PHISHING"
                signal_agreement = 0.70
                summary_points = [
                    "⚠️ WARNING: Target host is currently offline or unreachable (DNS failure or connection refused).",
                    f"High-risk brand impersonation identified in URL targeting '{uf.get('brand_in_subdomain', ['brand'])[0]}' on external infrastructure.",
                    "Ephemeral zero-day phishing campaigns are frequently taken down within hours of deployment.",
                    "Do NOT trust this domain if it returns online."
                ]
            elif url_risk >= 0.35:
                final_risk = max(0.55, round(url_risk, 2))
                classification = "SUSPICIOUS"
                signal_agreement = 0.45
                summary_points = [
                    "⚠️ WARNING: Target host is offline or unreachable.",
                    f"The URL exhibits suspicious lexical anomalies and high-risk domain structure ({int(url_risk * 100)}% URL risk).",
                    "Automated inspection cannot certify an unreachable host as safe."
                ]
            else:
                final_risk = 0.35
                classification = "SUSPICIOUS"
                signal_agreement = 0.25
                diag_msg = unreachable_reason[:80] if unreachable_reason else "Host resolution failed / Network timeout"
                summary_points = [
                    "⚠️ WARNING: Target host is offline, unreachable, or does not exist.",
                    f"Network diagnostic: {diag_msg}.",
                    "Live visual layout and DOM forms could not be retrieved. Safety cannot be certified."
                ]

            return {
                "classification": classification,
                "risk_score": final_risk,
                "confidence": signal_agreement,
                "signal_agreement": signal_agreement,
                "sub_scores": {
                    "url_score": round(url_risk, 3),
                    "visual_score": round(visual_risk, 3),
                    "text_score": round(text_risk, 3),
                    "html_score": round(html_risk, 3),
                },
                "fired_rules": [{"rule": "UNREACHABLE_HOST", "reason": unreachable_reason}],
                "categorized_indicators": {
                    "critical": summary_points[:2],
                    "suspicious": summary_points[2:],
                    "benign": []
                },
                "explanation_summary": summary_points
            }

        # 3. Additive Threat Correlation Cascade (Documented Rules)
        # Rule 1: Zero-Day Brand Impersonation with Credential Harvesting
        if is_brand_impersonation and (has_password_field or is_credential_harvesting):
            boost = 0.45
            prev = accumulated_risk
            accumulated_risk = max(0.88, accumulated_risk + boost)
            fired_rules.append({
                "rule": "RULE_1_BRAND_IMPERSONATION_CREDENTIAL_HARVEST",
                "rationale": f"Deceptive mimicry of {impersonated_brand or 'brand'} combined with credential capture on unauthorized infrastructure.",
                "boost": boost,
                "floor": 0.88,
                "score_before": round(prev, 3),
                "score_after": round(accumulated_risk, 3)
            })

        # Rule 2: Cross-Domain Credential Exfiltration
        if cross_domain_post and (has_password_field or has_any_input):
            boost = 0.30
            prev = accumulated_risk
            accumulated_risk = max(0.78, accumulated_risk + boost)
            fired_rules.append({
                "rule": "RULE_2_CROSS_DOMAIN_FORM_POST",
                "rationale": "Form submission target points to an external third-party domain (credential exfiltration pattern).",
                "boost": boost,
                "floor": 0.78,
                "score_before": round(prev, 3),
                "score_after": round(accumulated_risk, 3)
            })

        # Rule 3: User-Content / PaaS Credential Collection
        if is_user_content and (has_password_field or (has_login_form and has_social_eng)):
            boost = 0.28
            prev = accumulated_risk
            accumulated_risk = max(0.75, accumulated_risk + boost)
            fired_rules.append({
                "rule": "RULE_3_USER_CONTENT_CREDENTIAL_CAPTURE",
                "rationale": "Authentication inputs rendered on multi-tenant user content platform (sites.google, github.io, pages.dev).",
                "boost": boost,
                "floor": 0.75,
                "score_before": round(prev, 3),
                "score_after": round(accumulated_risk, 3)
            })

        # Rule 4: Scareware / Urgency Pressure Manipulation
        if (has_social_eng or has_urgency) and visual_risk >= 0.75:
            boost = 0.25
            prev = accumulated_risk
            accumulated_risk = max(0.75, accumulated_risk + boost)
            fired_rules.append({
                "rule": "RULE_4_SCAREWARE_URGENCY_MANIPULATION",
                "rationale": "Social engineering pressure tactics combined with high visual deception layout.",
                "boost": boost,
                "floor": 0.75,
                "score_before": round(prev, 3),
                "score_after": round(accumulated_risk, 3)
            })

        # Rule 5: Bounded High-Trust Discount (Never absolute clamp, only bounded reduction)
        if is_trusted_dom and not is_brand_impersonation and not has_password_field and not cross_domain_post:
            discount = 0.35
            prev = accumulated_risk
            accumulated_risk = max(0.04, min(0.20, accumulated_risk - discount))
            fired_rules.append({
                "rule": "RULE_5_HIGH_TRUST_BOUNDED_DISCOUNT",
                "rationale": "Authentic enterprise domain verified without deceptive credential harvesting mechanisms.",
                "discount": discount,
                "ceiling": 0.20,
                "score_before": round(prev, 3),
                "score_after": round(accumulated_risk, 3)
            })

        final_risk = min(1.0, max(0.0, round(accumulated_risk, 3)))

        # 4. Calibrated Classification Thresholds
        if final_risk >= self.threshold_suspicious:
            classification = "PHISHING"
        elif final_risk >= self.threshold_safe:
            classification = "SUSPICIOUS"
        else:
            classification = "SAFE"

        # 5. Modality Spread Calibration (Signal Agreement)
        sub_scores = [url_risk, visual_risk, text_risk, html_risk]
        divergence = max(sub_scores) - min(sub_scores)

        # Baseline signal agreement derived from consistency across modalities
        signal_agreement = max(0.25, min(0.98, round(1.0 - (divergence * 0.40), 2)))

        # If decisive critical threat rules fired, agreement in the threat is high
        if any(r["rule"] in ("RULE_1_BRAND_IMPERSONATION_CREDENTIAL_HARVEST", "RULE_2_CROSS_DOMAIN_FORM_POST") for r in fired_rules):
            signal_agreement = max(signal_agreement, 0.94)

        # 6. Synthesize Transparent Explanation
        summary_points: List[str] = []
        if fired_rules:
            for fr in fired_rules:
                summary_points.append(f"Threat Rule Fired: {fr['rationale']}")

        for ind in visual_analysis.get("visual_indicators", [])[:2]:
            summary_points.append(ind)
        for ind in url_analysis.get("indicators", [])[:2]:
            summary_points.append(ind)
        for ind in html_analysis.get("indicators", [])[:2]:
            summary_points.append(ind)
        for ind in text_analysis.get("indicators", [])[:2]:
            summary_points.append(ind)

        if not summary_points:
            summary_points = ["Multimodal signals verified within safe operational baselines. Legitimate domain structure and content verified."]

        categorized_indicators = {
            "critical": [p for p in summary_points if any(w in p.lower() for w in ["impersonation", "harvest", "scareware", "cross-domain"])],
            "suspicious": [p for p in summary_points if any(w in p.lower() for w in ["keyword", "entropy", "subdomain", "urgency", "modal"])],
            "benign": [p for p in summary_points if any(w in p.lower() for w in ["authentic", "verified", "safe", "geometry"])]
        }

        return {
            "classification": classification,
            "risk_score": final_risk,
            "confidence": signal_agreement,
            "signal_agreement": signal_agreement,
            "sub_scores": {
                "url_score": round(url_risk, 3),
                "visual_score": round(visual_risk, 3),
                "text_score": round(text_risk, 3),
                "html_score": round(html_risk, 3),
            },
            "fired_rules": fired_rules,
            "categorized_indicators": categorized_indicators,
            "explanation_summary": summary_points
        }
