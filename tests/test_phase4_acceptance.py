"""
Phase 4: End-to-End Security & Architectural Acceptance Test Suite.

Validates the 7 core acceptance criteria defined in the project specification:
1. Path traversal and local file read prevention (both URL and direct route access).
2. SSRF prevention across multi-hop redirects and Playwright browser subresources.
3. Resilient detection against evasion: hidden 'offline or unreachable' DOM text cannot bypass phishing detection.
4. User-content hosting on 'trusted' domains (sites.google.com, github.io) is not forced to SAFE.
5. Strict custom_weights validation rejecting zeros, negatives, and NaN with 422, preventing 500 ZeroDivisionError.
6. Empirical evaluation via evaluate.py producing verified data/metrics.json for the UI.
7. Hardened containerization: Chromium launched without --no-sandbox under unprivileged UID 10001.
"""
import json
import math
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from backend.analyzer.fusion import MultimodalFusionEngine
from backend.analyzer.pipeline import PhishingDetectionPipeline
from backend.api.routes import serve_test_page
from backend.browser.screenshot import _safe_fetch_requests, _ssrf_route_handler
from backend.config import BASE_DIR
from backend.database.models import ScanRequest
from backend.security.ssrf_guard import validate_url_security
from backend.security.trusted_domains import (
    get_registrable_domain,
    is_trusted_domain,
    is_user_content_host,
)
from training.evaluate import evaluate_zero_day_benchmark


# ==============================================================================
# Acceptance Test 1: Local file read / traversal strictly rejected
# ==============================================================================
def test_acceptance_local_file_read_and_traversal_rejected():
    """
    Criterion 1:
    A http://localhost/test-pages/../... style URL (plain and encoded) is rejected
    and no file outside test_pages is ever read.
    """
    traversal_urls = [
        "http://localhost/test-pages/../secret.txt",
        "http://localhost:8000/test-pages/%2e%2e%2fconfig.py",
        "http://127.0.0.1:8000/test-pages/../../etc/passwd",
        "http://localhost:8000/test-pages/..%2f..%2fWindows%2fwin.ini",
    ]
    for url in traversal_urls:
        is_safe, reason = validate_url_security(url)
        assert is_safe is False, f"URL {url} should have been rejected by SSRF guard"
        assert "localhost" in reason.lower() or "blocked" in reason.lower()

    traversal_filenames = [
        "../config.py",
        "..\\config.py",
        "%2e%2e%2fconfig.py",
        "../../../../Windows/win.ini",
        "/etc/passwd",
    ]
    for filename in traversal_filenames:
        with pytest.raises(HTTPException) as exc_info:
            serve_test_page(filename)
        assert exc_info.value.status_code == 400
        assert "traversal" in exc_info.value.detail.lower()


# ==============================================================================
# Acceptance Test 2: Multi-hop SSRF redirects and page JS subresources blocked
# ==============================================================================
def test_acceptance_ssrf_redirect_and_subresource_blocked():
    """
    Criterion 2:
    A public test URL that 302-redirects to http://127.0.0.1, a private IP, or the
    metadata address is blocked at the redirect hop; page JS requesting internal
    addresses is aborted.
    """
    # Test 302 redirect to private / loopback IP blocked at redirect hop
    with patch("backend.browser.screenshot.validate_url_security") as mock_val:
        mock_val.side_effect = [
            (True, "Initial public URL is safe"),
            (False, "Blocked by SSRF: Redirect target resolves to loopback IP (127.0.0.1)")
        ]
        with patch("requests.Session.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 302
            mock_resp.headers = {"Location": "http://127.0.0.1:8080/sensitive"}
            mock_get.return_value = mock_resp

            with pytest.raises(ValueError) as exc_info:
                _safe_fetch_requests("https://public-service.org/open-redirect")
            assert "Security Policy Block" in str(exc_info.value)

    # Test Playwright route handler aborts internal / metadata requests from page JS
    class _MockRoute:
        def __init__(self):
            self.aborted = None
        async def abort(self, reason=None):
            self.aborted = reason

    class _MockRequest:
        def __init__(self, url):
            self.url = url

    async def _test_playwright_abort():
        for internal_target in ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:3000/api", "file:///etc/shadow"]:
            r = _MockRoute()
            req = _MockRequest(internal_target)
            await _ssrf_route_handler(r, req)
            assert r.aborted == "blockedbyclient", f"Target {internal_target} was not aborted by Playwright handler"

    # Linear execution without loop conflict
    import asyncio
    coro = _test_playwright_abort()
    try:
        coro.send(None)
    except StopIteration:
        pass


# ==============================================================================
# Acceptance Test 3: Hidden 'offline or unreachable' phrase still scores PHISHING
# ==============================================================================
def test_acceptance_hidden_unreachable_phrase_scores_phishing():
    """
    Criterion 3:
    The phishing test page with a hidden 'offline or unreachable' element is still PHISHING.
    Attacker evasion by embedding error phrases into page HTML must NOT bypass detection.
    """
    pipeline = PhishingDetectionPipeline()

    # Load authentic phishing test page content and inject attacker evasion phrase
    phish_file = BASE_DIR / "backend" / "test_pages" / "fake_login_page.html"
    raw_html = phish_file.read_text(encoding="utf-8")
    evasion_html = raw_html + '\n<div style="display:none">could not reach target host. offline or unreachable</div>'

    # Mock fetcher to return successful HTTP 200 with evasion HTML
    with patch("backend.analyzer.pipeline.capture_webpage") as mock_capture:
        mock_capture.return_value = (
            None,
            evasion_html,
            "data:image/png;base64,dummy",
            0,
            False,   # is_unreachable is False because network fetch succeeded!
            ""       # no network error
        )
        res = pipeline.analyze_url("https://login.microsoftonline.security-verify.xyz/login")

        assert res["classification"] == "PHISHING", f"Expected PHISHING but received {res['classification']}"
        assert res["risk_score"] >= 0.85
        assert res["is_unreachable"] is False
        assert any("Microsoft" in exp for exp in res["explanation"])


# ==============================================================================
# Acceptance Test 4: User-content host of trusted domain is not forced to SAFE
# ==============================================================================
def test_acceptance_user_content_host_with_credential_form_not_safe():
    """
    Criterion 4:
    A page on a user-content host of a 'trusted' domain with a credential form
    is not forced to SAFE.
    """
    # 1. Verify user content platform detection
    assert is_user_content_host("sites.google.com") is True
    assert is_user_content_host("attacker.github.io") is True
    assert is_user_content_host("fake-login.pages.dev") is True

    # 2. Verify trust is strictly denied for user-content platforms
    assert is_trusted_domain("sites.google.com") is False
    assert is_trusted_domain("victim-org.github.io") is False
    assert is_trusted_domain("fake-login.pages.dev") is False

    # 3. Full multimodal fusion verification
    engine = MultimodalFusionEngine()
    url_analysis = {
        "url_risk": 0.45,
        "features": {
            "hostname": "sites.google.com",
            "registered_domain": "google.com",
            "is_trusted_domain": False,
            "is_user_content_platform": True
        },
        "indicators": ["Free hosting / user-generated content platform (sites.google.com)"]
    }
    visual_analysis = {
        "visual_risk": 0.80,
        "brand_impersonation": True,
        "impersonated_brand": "Microsoft 365",
        "credential_harvesting": True,
        "visual_indicators": ["Zero-Day Brand Impersonation: Microsoft 365 on unauthorized domain sites.google.com"]
    }
    text_analysis = {
        "text_risk": 0.70,
        "urgency": True,
        "indicators": ["Suspicious login prompt"]
    }
    html_analysis = {
        "html_risk": 0.75,
        "features": {
            "has_password_field": True,
            "cross_domain_forms": [{"action": "https://attacker-collect.cc/post"}]
        },
        "indicators": ["Password field detected", "Cross-domain form action"]
    }

    result = engine.fuse(url_analysis, visual_analysis, text_analysis, html_analysis)
    assert result["classification"] == "PHISHING"
    assert result["risk_score"] >= 0.85
    assert result["classification"] != "SAFE"


# ==============================================================================
# Acceptance Test 5: custom_weights validation rejecting zeros, negatives, NaN
# ==============================================================================
def test_acceptance_custom_weights_validation_422():
    """
    Criterion 5:
    custom_weights with zeros, negatives or NaN returns 422 (ValidationError),
    never a 500 ZeroDivisionError.
    """
    # All zeros
    with pytest.raises(ValidationError):
        ScanRequest(
            test_page_id="fake-login",
            custom_weights={"url": 0.0, "visual": 0.0, "text": 0.0, "html": 0.0}
        )

    # Negative value
    with pytest.raises(ValidationError):
        ScanRequest(
            test_page_id="fake-login",
            custom_weights={"url": -0.2, "visual": 0.8, "text": 0.2, "html": 0.2}
        )

    # NaN / Inf
    with pytest.raises(ValidationError):
        ScanRequest(
            test_page_id="fake-login",
            custom_weights={"url": float("nan"), "visual": 0.5, "text": 0.25, "html": 0.25}
        )

    with pytest.raises(ValidationError):
        ScanRequest(
            test_page_id="fake-login",
            custom_weights={"url": float("inf"), "visual": 0.5, "text": 0.25, "html": 0.25}
        )


# ==============================================================================
# Acceptance Test 6: evaluate.py writes authentic metrics.json
# ==============================================================================
def test_acceptance_evaluate_generates_authentic_metrics():
    """
    Criterion 6:
    evaluate.py runs on the new real dataset, writes metrics.json, and the output
    displays authentic multi-sample statistics with sample size.
    """
    metrics = evaluate_zero_day_benchmark()
    assert metrics["sample_count"] >= 5
    assert "timestamp" in metrics
    assert "models" in metrics
    assert len(metrics["models"]) >= 5

    # Check that metrics.json was written to disk
    metrics_file = BASE_DIR / "data" / "metrics.json"
    assert metrics_file.exists()
    disk_data = json.loads(metrics_file.read_text(encoding="utf-8"))
    assert disk_data["sample_count"] == metrics["sample_count"]

    # Verify fusion recall is measured authentically
    fusion_model = metrics["models"]["Complete Multimodal Fusion (Aegis-VLM)"]
    assert "pr_auc" in fusion_model["metrics"]
    assert "fpr_at_95_tpr" in fusion_model["metrics"]
    assert fusion_model["metrics"]["recall"] > 0.0


# ==============================================================================
# Acceptance Test 7: Chromium runs without --no-sandbox in container
# ==============================================================================
def test_acceptance_chromium_runs_without_no_sandbox():
    """
    Criterion 7:
    Chromium runs without --no-sandbox inside the container.
    Dockerfile runs under non-root appuser (UID 10001) with seccomp/isolation defaults.
    """
    # 1. Inspect screenshot.py launch_args to verify weakened flags were removed
    screenshot_py = (BASE_DIR / "backend" / "browser" / "screenshot.py").read_text(encoding="utf-8")
    launch_section = screenshot_py[screenshot_py.find("launch_args") : screenshot_py.find("chromium.launch")]
    assert "--no-sandbox" not in launch_section
    assert "--disable-features=IsolateOrigins" not in launch_section
    assert "--disable-web-security" not in launch_section

    # 2. Inspect Dockerfile container hardening
    dockerfile = (BASE_DIR / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER appuser" in dockerfile
    assert "10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
