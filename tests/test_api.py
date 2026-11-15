"""
Integration and API endpoint tests verifying route handlers, scan lifecycle, and security responses.
"""
import pytest
from fastapi import HTTPException
from backend.api.routes import (
    analyze_url_endpoint,
    delete_scan_endpoint,
    get_scan_details_endpoint,
    get_scans_endpoint,
    get_stats_endpoint,
    health_check,
    list_test_pages,
)
from backend.database.models import ScanRequest


def test_health_endpoint():
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "vlm-phishing-detection"
    assert "version" in res


def test_test_pages_catalog():
    catalog = list_test_pages()
    assert len(catalog) >= 4
    assert any(p["id"] == "fake-login" for p in catalog)
    assert any(p["id"] == "legit-portal" for p in catalog)


def test_analyze_rejection_on_dangerous_scheme():
    req = ScanRequest(url="file:///etc/shadow")
    with pytest.raises(HTTPException) as exc_info:
        analyze_url_endpoint(req)
    assert exc_info.value.status_code == 400
    assert "Forbidden protocol scheme" in exc_info.value.detail


def test_analyze_safe_local_test_page():
    req = ScanRequest(url="http://localhost:8000/test-pages/legitimate_portal.html")
    res = analyze_url_endpoint(req)
    assert res["classification"] == "SAFE"
    assert res["risk_score"] < 0.35
    assert "analysis" in res
    assert "explanation" in res
    assert "id" in res


def test_analyze_phishing_local_test_page():
    req = ScanRequest(url="http://localhost:8000/test-pages/fake_login_page.html")
    res = analyze_url_endpoint(req)
    assert res["classification"] == "PHISHING"
    assert res["risk_score"] >= 0.65
    assert "explanation" in res
    assert any("Microsoft" in exp or "impersonation" in exp.lower() or "credentials" in exp.lower() for exp in res["explanation"])


def test_scan_crud_lifecycle():
    # 1. Trigger an analysis to create a record
    req = ScanRequest(url="http://localhost:8000/test-pages/legitimate_portal.html")
    res = analyze_url_endpoint(req)
    scan_id = res["id"]
    assert scan_id is not None

    # 2. Retrieve recent scans
    scans_list = get_scans_endpoint(limit=50, offset=0)
    assert any(s["id"] == scan_id for s in scans_list)

    # 3. Retrieve single scan by ID
    single_scan = get_scan_details_endpoint(scan_id)
    assert single_scan["id"] == scan_id

    # 4. Delete the scan
    del_res = delete_scan_endpoint(scan_id)
    assert del_res["status"] == "success"

    # 5. Verify deletion
    with pytest.raises(HTTPException) as exc_info:
        get_scan_details_endpoint(scan_id)
    assert exc_info.value.status_code == 404


def test_dashboard_stats():
    stats = get_stats_endpoint()
    assert "total_scans" in stats
    assert "phishing_count" in stats
    assert "safe_count" in stats
    assert "average_risk_score" in stats
