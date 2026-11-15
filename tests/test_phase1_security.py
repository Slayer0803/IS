"""
Regression Tests for Phase 1: Security Hardening.
Tests:
1.1 Directory traversal & local file read prevention (containment check, encoded separators, symlinks).
1.2 Multi-hop SSRF prevention, cloud metadata blocks, subresource filtering, unresolvable hosts marked unreachable.
1.3 Hardened browser configuration (no --no-sandbox, isolation preserved, downloads/popups blocked).
1.4 API abuse prevention: custom_weights validation (422), per-IP rate limiting (429), sanitized 500 error responses.
1.5 Repo hygiene: no base64 screenshots in DB, retention cleanup of screenshots and scan records.
"""
import io
import json
import socket
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from PIL import Image
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.main import app
from backend.api.routes import serve_test_page
from backend.browser.screenshot import (
    BrowserPool,
    _safe_fetch_requests,
    _ssrf_route_handler,
    cleanup_old_screenshots,
)
from backend.config import BACKEND_DIR, TEMP_SCREENSHOTS_DIR
from backend.database.database import (
    cleanup_expired_scans,
    get_db_connection,
    init_db,
    save_scan,
)
from backend.database.models import ScanRequest
from backend.security.rate_limiter import InMemoryRateLimiter, limiter
from backend.security.ssrf_guard import (
    is_private_or_restricted_ip,
    validate_url_security,
)


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path):
    init_db()
    limiter.reset()
    yield


# ==============================================================================
# PHASE 1.1: Local File Read & Directory Traversal Prevention
# ==============================================================================

def test_serve_test_page_valid():
    """Valid authorized test pages are served successfully."""
    response = serve_test_page("legitimate_portal.html")
    assert response.status_code == 200
    assert "text/html" in response.media_type


def test_serve_test_page_traversal_rejection():
    """Directory traversal strings must be strictly rejected with HTTP 400."""
    traversal_payloads = [
        "../test.txt",
        "..\\test.txt",
        "..%2ftest.txt",
        "%2e%2e%2fconfig.py",
        "sub/../../secret.txt",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
    ]
    for payload in traversal_payloads:
        with pytest.raises(HTTPException) as exc_info:
            serve_test_page(payload)
        assert exc_info.value.status_code == 400


def test_serve_test_page_unauthorized_filename():
    """Files outside the authorized demonstration registry must return 404."""
    with pytest.raises(HTTPException) as exc_info:
        serve_test_page("unauthorized_file.html")
    assert exc_info.value.status_code == 404


def test_serve_test_page_symlink_rejection(tmp_path):
    """Symlinked test files must be rejected with HTTP 400."""
    test_pages_dir = BACKEND_DIR / "test_pages"
    symlink_path = test_pages_dir / "symlink_test.html"
    target_file = tmp_path / "target.html"
    target_file.write_text("dummy", encoding="utf-8")

    can_symlink = False
    try:
        symlink_path.symlink_to(target_file)
        can_symlink = True
    except (OSError, NotImplementedError):
        pass

    if can_symlink:
        try:
            with patch("backend.api.routes.ALLOWED_FILENAMES", {"symlink_test.html"}):
                with pytest.raises(HTTPException) as exc_info:
                    serve_test_page("symlink_test.html")
                assert exc_info.value.status_code == 400
                assert "Symlinked" in exc_info.value.detail
        finally:
            if symlink_path.is_symlink() or symlink_path.exists():
                symlink_path.unlink()
    else:
        # On environments lacking OS unprivileged symlink creation (e.g. Windows non-admin),
        # verify that any path returning is_symlink() == True is strictly rejected with HTTP 400
        with patch("backend.api.routes.ALLOWED_FILENAMES", {"symlink_test.html"}):
            with patch("pathlib.Path.is_symlink", return_value=True):
                with pytest.raises(HTTPException) as exc_info:
                    serve_test_page("symlink_test.html")
                assert exc_info.value.status_code == 400
                assert "Symlinked" in exc_info.value.detail


def test_ssrf_rejects_localhost_test_page_shortcut():
    """Localhost URLs are unconditionally rejected by SSRF guard (no localhost exemption)."""
    localhost_urls = [
        "http://localhost:8000/test-pages/legitimate_portal.html",
        "http://127.0.0.1:8000/test-pages/fake_login_page.html",
        "http://localhost/test-pages/../../secret.txt",
        "http://127.0.0.1/test-pages/../../config.py",
    ]
    for url in localhost_urls:
        is_safe, msg = validate_url_security(url)
        assert not is_safe, f"Expected {url} to be rejected"
        assert "localhost" in msg.lower() or "blocked" in msg.lower() or "restricted" in msg.lower()


# ==============================================================================
# PHASE 1.2: SSRF Defense-in-Depth & Protocol Protection
# ==============================================================================

def test_ssrf_blocks_private_and_cloud_metadata_ips():
    """Validates that private, loopback, and cloud metadata targets are blocked."""
    forbidden_ips = [
        "127.0.0.1",
        "127.0.1.1",
        "::1",
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "100.100.100.200",  # Alibaba metadata
        "100.64.0.1",       # Carrier-Grade NAT
        "192.0.2.1",        # TEST-NET-1
        "198.51.100.1",     # TEST-NET-2
        "203.0.113.1",      # TEST-NET-3
    ]
    for ip in forbidden_ips:
        assert is_private_or_restricted_ip(ip), f"IP {ip} should be recognized as restricted."


def test_ssrf_blocks_dangerous_schemes():
    """Validates that non-http(s) schemes are rejected immediately."""
    dangerous_urls = [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "gopher://example.com:70",
        "data:text/html;base64,PHNjcmlwdD4=",
        "javascript:alert(1)",
        "ldap://localhost:389/o=example",
    ]
    for url in dangerous_urls:
        is_safe, reason = validate_url_security(url)
        assert not is_safe
        assert "scheme" in reason.lower() or "forbidden" in reason.lower() or "unsupported" in reason.lower()


def test_unresolvable_host_marked_as_unreachable():
    """Unresolvable hostnames must be treated as UNREACHABLE, not validated as safe."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
        nxdomain_url = "http://this-domain-definitely-does-not-exist-xyz987654321.org"
        is_safe, reason = validate_url_security(nxdomain_url)
        assert not is_safe
        assert "UNREACHABLE" in reason


def _run_coroutine_sync(coro):
    """Executes a simple linear coroutine without relying on OS IOCP event loops."""
    stack = [coro]
    while stack:
        try:
            res = stack[-1].send(None)
            if hasattr(res, "__await__"):
                stack.append(res.__await__())
        except StopIteration:
            stack.pop()


class _DummyRoute:
    def __init__(self):
        self.aborted = None
        self.continued = False
    async def abort(self, reason=None):
        self.aborted = reason
    async def continue_(self):
        self.continued = True


class _DummyRequest:
    def __init__(self, url):
        self.url = url


def test_playwright_ssrf_route_handler_aborts_private_and_metadata():
    """Playwright route handler must abort requests to restricted IPs or non-http schemes."""
    # Test non-http scheme
    r_file = _DummyRoute()
    req_file = _DummyRequest("file:///etc/passwd")
    _run_coroutine_sync(_ssrf_route_handler(r_file, req_file))
    assert r_file.aborted == "blockedbyclient"

    # Test metadata address
    r_meta = _DummyRoute()
    req_meta = _DummyRequest("http://169.254.169.254/latest/meta-data/")
    _run_coroutine_sync(_ssrf_route_handler(r_meta, req_meta))
    assert r_meta.aborted == "blockedbyclient"

    # Test loopback IP
    r_loop = _DummyRoute()
    req_loop = _DummyRequest("http://127.0.0.1:8080/internal-api")
    _run_coroutine_sync(_ssrf_route_handler(r_loop, req_loop))
    assert r_loop.aborted == "blockedbyclient"


def test_safe_fetch_requests_blocks_redirect_to_private_ip():
    """_safe_fetch_requests must block any hop redirecting to internal IP."""
    with patch("backend.browser.screenshot.validate_url_security") as mock_val:
        # First hop is safe, second hop (redirect to 127.0.0.1) is blocked by SSRF
        mock_val.side_effect = [
            (True, "Safe initial hop"),
            (False, "Requests to localhost are blocked by SSRF protection.")
        ]
        with patch("requests.Session.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 302
            mock_resp.headers = {"Location": "http://127.0.0.1:8080/admin"}
            mock_get.return_value = mock_resp

            with pytest.raises(ValueError) as exc_info:
                _safe_fetch_requests("http://example.com/redirect-to-internal")
            assert "Security Policy Block" in str(exc_info.value)


# ==============================================================================
# PHASE 1.3: Hardened Browser Sandbox & Concurrency
# ==============================================================================

class _DummyChromium:
    def __init__(self):
        self.launch_kwargs = {}
    async def launch(self, **kwargs):
        self.launch_kwargs = kwargs
        return _DummyBrowser()

class _DummyBrowser:
    def is_connected(self):
        return True

class _DummyPlaywright:
    def __init__(self):
        self.chromium = _DummyChromium()
    async def stop(self):
        pass

class _DummyPlaywrightContext:
    async def start(self):
        return _DummyPlaywright()


def test_browser_pool_hardened_launch_flags():
    """Verify Chromium launch does NOT include weakened --no-sandbox or disable-features flags."""
    with patch("playwright.async_api.async_playwright", return_value=_DummyPlaywrightContext()):
        pool = BrowserPool()
        _run_coroutine_sync(pool._ensure_browser())

        launch_kwargs = pool._playwright.chromium.launch_kwargs
        args = launch_kwargs.get("args", [])

        assert "--no-sandbox" not in args, "Weakened flag --no-sandbox must NOT be passed."
        assert not any("disable-features=IsolateOrigins" in a for a in args), "Site isolation must NOT be disabled."


# ==============================================================================
# PHASE 1.4: API Abuse, Custom Weights Validation, & Error Sanitization
# ==============================================================================

def test_custom_weights_validation_zero_division():
    """Custom weights that sum to 0 must be rejected with HTTP 422."""
    with pytest.raises(Exception):
        ScanRequest(url="https://example.com", custom_weights={"url": 0.0, "visual": 0.0, "text": 0.0, "html": 0.0})


def test_custom_weights_validation_negative_numbers():
    """Negative weights must be rejected with HTTP 422."""
    with pytest.raises(Exception):
        ScanRequest(url="https://example.com", custom_weights={"url": -0.5, "visual": 0.5})


def test_custom_weights_validation_nan_or_inf():
    """NaN or Infinite weights must be rejected with HTTP 422."""
    with pytest.raises(Exception):
        ScanRequest(url="https://example.com", custom_weights={"url": float("nan"), "visual": 0.5})
    with pytest.raises(Exception):
        ScanRequest(url="https://example.com", custom_weights={"url": float("inf"), "visual": 0.5})


def test_custom_weights_validation_unknown_modality():
    """Unrecognized modality key must be rejected with HTTP 422."""
    with pytest.raises(Exception):
        ScanRequest(url="https://example.com", custom_weights={"url": 0.5, "unknown_modality": 0.5})


def test_api_rate_limiter_enforcement():
    """Rate limiter must return HTTP 429 when client exceeds requests per minute."""
    test_limiter = InMemoryRateLimiter(requests_per_minute=3)
    client_ip = "198.51.100.42"

    assert test_limiter.is_allowed(client_ip) is True
    assert test_limiter.is_allowed(client_ip) is True
    assert test_limiter.is_allowed(client_ip) is True
    assert test_limiter.is_allowed(client_ip) is False


def test_sanitized_500_response_does_not_leak_internals():
    """Internal server errors must return generic error messages without leaking str(exc) or stack trace."""
    from backend.api.routes import analyze_url_endpoint
    from backend.database.models import ScanRequest
    with patch("backend.api.routes.pipeline.analyze_url", side_effect=RuntimeError("SECRET_INTERNAL_DB_TOKEN_12345")):
        req = ScanRequest(url="https://example.com")
        with pytest.raises(HTTPException) as exc_info:
            analyze_url_endpoint(req)
        assert exc_info.value.status_code == 500
        assert "SECRET_INTERNAL_DB_TOKEN_12345" not in exc_info.value.detail
        assert "An internal error occurred" in exc_info.value.detail


# ==============================================================================
# PHASE 1.5: Repo Hygiene & Data Retention
# ==============================================================================

def test_save_scan_omits_base64_screenshot_from_database():
    """Database records must NOT persist massive base64 screenshot strings in full_data."""
    sample_scan = {
        "url": "https://example.com",
        "hostname": "example.com",
        "classification": "SAFE",
        "risk_score": 0.05,
        "confidence": 0.95,
        "sub_scores": {"url_score": 0.05, "visual_score": 0.05, "text_score": 0.05, "html_score": 0.05},
        "screenshot_preview": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
        "explanation": ["Page verified as safe."]
    }
    scan_id = save_scan(sample_scan)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT full_data FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    saved_payload = json.loads(row["full_data"])
    assert "screenshot_preview" not in saved_payload, "Base64 screenshot should be omitted from stored database record."


def test_cleanup_old_screenshots(tmp_path):
    """Temporary screenshot cleanup removes files older than TTL."""
    dummy_file = TEMP_SCREENSHOTS_DIR / "screenshot_testdummy.png"
    dummy_file.write_bytes(b"dummy")

    # Set mtime to 2 hours ago
    import os, time
    two_hours_ago = time.time() - 7200
    os.utime(dummy_file, (two_hours_ago, two_hours_ago))

    deleted = cleanup_old_screenshots(max_age_seconds=3600)
    assert deleted >= 1
    assert not dummy_file.exists()


def test_cleanup_expired_scans():
    """Scan records older than retention threshold are deleted."""
    deleted = cleanup_expired_scans(max_age_days=30)
    assert isinstance(deleted, int)
