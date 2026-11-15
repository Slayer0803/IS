"""
End-to-End Multimodal Phishing Detection Pipeline.
Coordinates URL validation, screenshot capture, DOM parsing, visual VLM reasoning,
textual semantic analysis, feature fusion, and explainable reporting.
Supports safe offline demonstration analysis of authorized local test pages without network calls.
"""
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from backend.analyzer.fusion import MultimodalFusionEngine
from backend.analyzer.text_analyzer import TextSemanticAnalyzer
from backend.analyzer.vlm_analyzer import get_vlm_analyzer
from backend.browser.screenshot import capture_webpage, generate_fallback_screenshot
from backend.config import BACKEND_DIR
from backend.security.html_features import extract_html_features
from backend.security.ssrf_guard import validate_url_security
from backend.security.url_features import extract_url_features

logger = logging.getLogger(__name__)

TEST_PAGES_DIR = (BACKEND_DIR / "test_pages").resolve()

# Strict allow-list of authorized local test page identifiers
AUTHORIZED_TEST_PAGES = {
    "legit-portal": {
        "filename": "legitimate_portal.html",
        "mock_url": "https://portal.secure-enterprise.net/dashboard",
        "name": "Legitimate Enterprise Portal"
    },
    "fake-login": {
        "filename": "fake_login_page.html",
        "mock_url": "https://login.microsoftonline.security-verify.xyz/login",
        "name": "Zero-Day Microsoft 365 Phishing"
    },
    "fake-bank": {
        "filename": "fake_bank_login.html",
        "mock_url": "https://chase-security-update.com/online/banking",
        "name": "Zero-Day Chase Online Banking Phishing"
    },
    "fake-account": {
        "filename": "fake_account_verify.html",
        "mock_url": "https://paypal-resolution-center.sbs/verify",
        "name": "Zero-Day PayPal Verification Phishing"
    }
}


class PhishingDetectionPipeline:
    """
    Main detection pipeline implementing zero-day multimodal phishing analysis.
    """

    def __init__(self):
        self.vlm_analyzer = get_vlm_analyzer()
        self.text_analyzer = TextSemanticAnalyzer()
        self.fusion_engine = MultimodalFusionEngine()

    def analyze_url(
        self,
        url: str,
        custom_weights: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Executes complete multimodal analysis pipeline on the given URL.
        """
        url = url.strip()

        # 1. URL Security Validation (Defense-in-depth / SSRF Protection)
        is_safe, sec_reason = validate_url_security(url)
        if not is_safe:
            if "UNREACHABLE" in sec_reason:
                # DNS failure / NXDOMAIN: mark unreachable immediately
                pass
            else:
                raise ValueError(f"Security Policy Block: {sec_reason}")

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or ""

        # 2. Webpage Fetching and Rendering
        logger.info(f"Analyzing webpage: {url}")
        pil_image, html_content, screenshot_preview, redirect_count, is_unreachable, unreachable_reason = capture_webpage(url)

        # 3. URL Lexical & Heuristic Feature Extraction
        url_analysis = extract_url_features(url, redirect_count=redirect_count)

        # 4. HTML DOM & Technical Security Feature Extraction
        html_analysis = extract_html_features(html_content, base_url=url)
        html_analysis["is_unreachable"] = is_unreachable
        html_analysis["unreachable_reason"] = unreachable_reason
        if is_unreachable:
            html_analysis["indicators"] = [
                f"⚠️ Target Host Unreachable: Server connection failed ({unreachable_reason[:80] if unreachable_reason else 'DNS/Network Timeout'})",
                "⚠️ Real-time DOM inspection unavailable: Live forms and scripts could not be retrieved"
            ]

        visible_text = html_analysis["features"]["visible_text"]

        # 5. Semantic / NLP Text Analysis
        text_analysis = self.text_analyzer.analyze(visible_text)
        if is_unreachable:
            text_analysis["indicators"] = ["⚠️ Webpage text unavailable: Host offline"]

        # 6. Visual / Vision-Language Model Analysis
        visual_analysis = self.vlm_analyzer.analyze(
            image=pil_image,
            webpage_text=visible_text,
            domain_context=hostname,
            html_features=html_analysis["features"],
            url_context=url,
            url_features=url_analysis
        )
        if is_unreachable:
            visual_analysis["visual_indicators"] = [
                "⚠️ Live browser canvas could not be rendered: Target host offline",
                "⚠️ Visual zero-day verification inconclusive for offline endpoint"
            ]

        # 7. Multimodal Feature Fusion
        if custom_weights:
            fusion_engine = MultimodalFusionEngine(
                w_url=custom_weights.get("url", 0.20),
                w_visual=custom_weights.get("visual", 0.40),
                w_text=custom_weights.get("text", 0.25),
                w_html=custom_weights.get("html", 0.15)
            )
        else:
            fusion_engine = self.fusion_engine

        fusion_result = fusion_engine.fuse(
            url_analysis=url_analysis,
            visual_analysis=visual_analysis,
            text_analysis=text_analysis,
            html_analysis=html_analysis,
            is_unreachable=is_unreachable,
            unreachable_reason=unreachable_reason
        )

        # 8. Assemble Unified Result Payload
        result = {
            "url": url,
            "hostname": hostname,
            "classification": fusion_result["classification"],
            "risk_score": fusion_result["risk_score"],
            "confidence": fusion_result["confidence"],
            "is_unreachable": is_unreachable,
            "unreachable_reason": unreachable_reason,
            "screenshot_preview": screenshot_preview,
            "analysis": {
                "url": url_analysis,
                "visual": visual_analysis,
                "text": text_analysis,
                "html": {
                    "html_risk": html_analysis["html_risk"],
                    "indicators": html_analysis["indicators"],
                    "title": html_analysis["features"]["title"],
                    "headings": html_analysis["features"]["headings"],
                    "has_login_form": html_analysis["features"]["has_login_form"],
                    "has_password_field": html_analysis["features"]["has_password_field"],
                    "num_forms": html_analysis["features"]["num_forms"],
                    "num_links": html_analysis["features"]["num_links"],
                    "empty_link_ratio": html_analysis["features"]["empty_link_ratio"],
                    "external_link_ratio": html_analysis["features"]["external_link_ratio"],
                    "cross_domain_forms": html_analysis["features"]["cross_domain_forms"],
                }
            },
            "sub_scores": fusion_result["sub_scores"],
            "categorized_indicators": fusion_result["categorized_indicators"],
            "explanation": fusion_result["explanation_summary"],
            "meta": {
                "vlm_backend": visual_analysis.get("backend", "heuristic"),
                "redirects": redirect_count,
            }
        }

        return result

    def analyze_test_page(
        self,
        test_page_id: str,
        custom_weights: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Safely executes analysis on an authorized local test page without network access
        or path traversal vulnerabilities.
        """
        if test_page_id not in AUTHORIZED_TEST_PAGES:
            raise ValueError(
                f"Unknown test page ID '{test_page_id}'. Allowed IDs: {list(AUTHORIZED_TEST_PAGES.keys())}"
            )

        spec = AUTHORIZED_TEST_PAGES[test_page_id]
        filename = spec["filename"]
        mock_url = spec["mock_url"]

        # Strict containment verification
        file_path = (TEST_PAGES_DIR / filename).resolve()
        if not file_path.is_relative_to(TEST_PAGES_DIR) or not file_path.is_file():
            raise ValueError("Test page file resolution failed safety containment check.")
        if file_path.is_symlink():
            raise ValueError("Symlink test pages are strictly prohibited.")

        html_content = file_path.read_text(encoding="utf-8")

        # Extract features safely
        url_analysis = extract_url_features(mock_url, redirect_count=0)
        html_analysis = extract_html_features(html_content, base_url=mock_url)
        visible_text = html_analysis["features"]["visible_text"]
        text_analysis = self.text_analyzer.analyze(visible_text)

        title = html_analysis["features"]["title"]
        has_login = html_analysis["features"]["has_login_form"] or html_analysis["features"]["has_password_field"]
        pil_image = generate_fallback_screenshot(mock_url, title, visible_text, has_login=has_login)

        parsed_url = urlparse(mock_url)
        hostname = parsed_url.hostname or ""

        visual_analysis = self.vlm_analyzer.analyze(
            image=pil_image,
            webpage_text=visible_text,
            domain_context=hostname,
            html_features=html_analysis["features"],
            url_context=mock_url,
            url_features=url_analysis
        )

        if custom_weights:
            fusion_engine = MultimodalFusionEngine(
                w_url=custom_weights.get("url", 0.20),
                w_visual=custom_weights.get("visual", 0.40),
                w_text=custom_weights.get("text", 0.25),
                w_html=custom_weights.get("html", 0.15)
            )
        else:
            fusion_engine = self.fusion_engine

        fusion_result = fusion_engine.fuse(
            url_analysis=url_analysis,
            visual_analysis=visual_analysis,
            text_analysis=text_analysis,
            html_analysis=html_analysis,
            is_unreachable=False,
            unreachable_reason=""
        )

        import base64, io
        buffered = io.BytesIO()
        pil_image.save(buffered, format="PNG")
        screenshot_preview = f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"

        return {
            "url": mock_url,
            "hostname": hostname,
            "classification": fusion_result["classification"],
            "risk_score": fusion_result["risk_score"],
            "confidence": fusion_result["confidence"],
            "is_unreachable": False,
            "unreachable_reason": "",
            "screenshot_preview": screenshot_preview,
            "analysis": {
                "url": url_analysis,
                "visual": visual_analysis,
                "text": text_analysis,
                "html": {
                    "html_risk": html_analysis["html_risk"],
                    "indicators": html_analysis["indicators"],
                    "title": html_analysis["features"]["title"],
                    "headings": html_analysis["features"]["headings"],
                    "has_login_form": html_analysis["features"]["has_login_form"],
                    "has_password_field": html_analysis["features"]["has_password_field"],
                    "num_forms": html_analysis["features"]["num_forms"],
                    "num_links": html_analysis["features"]["num_links"],
                    "empty_link_ratio": html_analysis["features"]["empty_link_ratio"],
                    "external_link_ratio": html_analysis["features"]["external_link_ratio"],
                    "cross_domain_forms": html_analysis["features"]["cross_domain_forms"],
                }
            },
            "sub_scores": fusion_result["sub_scores"],
            "categorized_indicators": fusion_result["categorized_indicators"],
            "explanation": fusion_result["explanation_summary"],
            "meta": {
                "vlm_backend": visual_analysis.get("backend", "heuristic"),
                "redirects": 0,
                "test_page_id": test_page_id
            }
        }
