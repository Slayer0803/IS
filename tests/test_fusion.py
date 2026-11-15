"""
Unit tests for multimodal feature fusion, risk score weights, and classification thresholds.
"""
import pytest
from backend.analyzer.fusion import MultimodalFusionEngine


def test_fusion_safe_webpage():
    engine = MultimodalFusionEngine()
    url_analysis = {"url_risk": 0.05, "indicators": []}
    visual_analysis = {
        "visual_risk": 0.08,
        "brand_impersonation": False,
        "credential_harvesting": False,
        "visual_indicators": []
    }
    text_analysis = {"text_risk": 0.05, "urgency": False, "indicators": []}
    html_analysis = {"html_risk": 0.02, "features": {}, "indicators": []}

    res = engine.fuse(url_analysis, visual_analysis, text_analysis, html_analysis)
    assert res["classification"] == "SAFE"
    assert res["risk_score"] < 0.20
    assert "legitimate" in res["explanation_summary"][0].lower()


def test_fusion_zero_day_phishing_amplification():
    """
    Zero-Day scenario: Newly registered domain (low traditional URL history),
    but visual brand impersonation + password harvesting triggers high-confidence zero-day alert!
    """
    engine = MultimodalFusionEngine()
    url_analysis = {"url_risk": 0.35, "indicators": ["Suspicious TLD .xyz"]}
    visual_analysis = {
        "visual_risk": 0.75,
        "brand_impersonation": True,
        "impersonated_brand": "Microsoft 365",
        "credential_harvesting": True,
        "visual_indicators": ["Zero-Day Brand Impersonation of Microsoft 365"]
    }
    text_analysis = {"text_risk": 0.70, "urgency": True, "indicators": ["Urgent verification"]}
    html_analysis = {
        "html_risk": 0.60,
        "features": {"has_password_field": True, "cross_domain_forms": []},
        "indicators": ["Password field detected"]
    }

    res = engine.fuse(url_analysis, visual_analysis, text_analysis, html_analysis)
    assert res["classification"] == "PHISHING"
    assert res["risk_score"] >= 0.85
    assert res["confidence"] >= 0.85
    assert any("Microsoft" in exp for exp in res["explanation_summary"])


def test_fusion_suspicious_borderline():
    engine = MultimodalFusionEngine()
    url_analysis = {"url_risk": 0.45, "indicators": ["Multiple hyphens"]}
    visual_analysis = {
        "visual_risk": 0.40,
        "brand_impersonation": False,
        "credential_harvesting": False,
        "visual_indicators": []
    }
    text_analysis = {"text_risk": 0.40, "urgency": True, "indicators": ["Urgent"]}
    html_analysis = {"html_risk": 0.35, "features": {}, "indicators": []}

    res = engine.fuse(url_analysis, visual_analysis, text_analysis, html_analysis)
    assert res["classification"] == "SUSPICIOUS"
    assert 0.30 <= res["risk_score"] <= 0.65


def test_fusion_unreachable_site_clean_url():
    """
    Unreachable site scenario: Connection drops or DNS fails on an unknown site.
    Must NOT give 97% confidence or 0% risk!
    Must output low confidence and prominent warning explanations.
    """
    engine = MultimodalFusionEngine()
    url_analysis = {
        "url_risk": 0.05,
        "features": {"hostname": "non-existent-server-404.com", "brand_in_subdomain": []},
        "indicators": []
    }
    visual_analysis = {"visual_risk": 0.0, "visual_indicators": []}
    text_analysis = {"text_risk": 0.0, "indicators": []}
    html_analysis = {"html_risk": 0.0, "features": {}, "indicators": []}

    res = engine.fuse(
        url_analysis, visual_analysis, text_analysis, html_analysis,
        is_unreachable=True, unreachable_reason="DNS_PROBE_FINISHED_NXDOMAIN"
    )

    assert res["classification"] == "SUSPICIOUS"
    assert res["risk_score"] == 0.35
    assert res["confidence"] == 0.25  # Low confidence, not 97%!
    assert any("offline or unreachable" in exp.lower() or "unreachable" in exp.lower() for exp in res["explanation_summary"])


def test_fusion_unreachable_site_spoofed_brand():
    """
    Dismantled zero-day phishing scenario: Site is already taken down or offline,
    but URL clearly attempts brand spoofing on third-party infrastructure.
    """
    engine = MultimodalFusionEngine()
    url_analysis = {
        "url_risk": 0.65,
        "features": {
            "hostname": "paypal-update-account.offline-scam.xyz",
            "brand_in_subdomain": ["paypal"],
            "is_free_hosting_abuse": False
        },
        "indicators": ["Brand spoofing in URL"]
    }
    visual_analysis = {"visual_risk": 0.0, "visual_indicators": []}
    text_analysis = {"text_risk": 0.0, "indicators": []}
    html_analysis = {"html_risk": 0.0, "features": {}, "indicators": []}

    res = engine.fuse(
        url_analysis, visual_analysis, text_analysis, html_analysis,
        is_unreachable=True, unreachable_reason="Connection refused"
    )

    assert res["classification"] == "PHISHING"
    assert res["risk_score"] >= 0.80
    assert res["confidence"] <= 0.70  # Reduced confidence because host is offline
    assert any("offline or unreachable" in exp.lower() for exp in res["explanation_summary"])
    assert any("paypal" in exp.lower() for exp in res["explanation_summary"])

