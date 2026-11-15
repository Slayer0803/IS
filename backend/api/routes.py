"""
FastAPI Route Handlers for VLM Phishing Detection System.
Provides endpoints for synchronous URL analysis, test-page demonstration, scan history CRUD,
and dashboard analytics with rate limiting and strict path traversal protections.
"""
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, HTMLResponse

from backend.analyzer.pipeline import AUTHORIZED_TEST_PAGES, PhishingDetectionPipeline
from backend.config import BACKEND_DIR
from backend.database.database import (
    delete_scan_by_id,
    get_all_scans,
    get_dashboard_stats,
    get_scan_by_id,
    save_scan,
)
from backend.database.models import DashboardStats, ScanRequest, ScanResponse, ScanSummary
from backend.security.rate_limiter import check_rate_limit_and_auth

logger = logging.getLogger(__name__)

router = APIRouter()
pipeline = PhishingDetectionPipeline()
TEST_PAGES_DIR = (BACKEND_DIR / "test_pages").resolve()
ALLOWED_FILENAMES = {spec["filename"] for spec in AUTHORIZED_TEST_PAGES.values()}


@router.get("/health", tags=["System"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "vlm-phishing-detection",
        "version": "1.0.0",
        "vlm_backend": pipeline.vlm_analyzer.__class__.__name__,
    }


@router.post(
    "/api/analyze",
    response_model=Dict[str, Any],
    tags=["Analysis"],
    dependencies=[Depends(check_rate_limit_and_auth)]
)
def analyze_url_endpoint(request: ScanRequest):
    """
    Submits a webpage URL or authorized test page ID for multimodal zero-day phishing detection.
    Analyzes visual layout, text, URL features, and applies multimodal fusion.
    """
    try:
        if request.test_page_id:
            result = pipeline.analyze_test_page(
                test_page_id=request.test_page_id,
                custom_weights=request.custom_weights
            )
        elif request.url:
            result = pipeline.analyze_url(
                url=request.url,
                custom_weights=request.custom_weights
            )
        else:
            raise ValueError("Either 'url' or 'test_page_id' must be specified.")

        scan_id = save_scan(result)
        result["id"] = scan_id
        return result
    except ValueError as ve:
        logger.warning(f"Analysis validation error: {ve}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except HTTPException:
        raise
    except Exception as exc:
        # Sanitize 500 responses: Log full details server-side without leaking internals to client
        logger.error(f"Internal analysis failure: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while processing the analysis request. Details have been logged."
        )


@router.post(
    "/api/test-pages/{page_id}/analyze",
    response_model=Dict[str, Any],
    tags=["Demonstration"],
    dependencies=[Depends(check_rate_limit_and_auth)]
)
def analyze_test_page_endpoint(page_id: str, request: Optional[ScanRequest] = None):
    """Safely analyzes an authorized local test page by ID without network requests."""
    try:
        custom_weights = request.custom_weights if request else None
        result = pipeline.analyze_test_page(test_page_id=page_id, custom_weights=custom_weights)
        scan_id = save_scan(result)
        result["id"] = scan_id
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as exc:
        logger.error(f"Test page analysis error: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while processing the test page."
        )


@router.get("/api/scans", response_model=List[ScanSummary], tags=["History"])
def get_scans_endpoint(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Retrieves recent scan records."""
    return get_all_scans(limit=limit, offset=offset)


@router.get("/api/scans/{scan_id}", response_model=Dict[str, Any], tags=["History"])
def get_scan_details_endpoint(scan_id: int):
    """Retrieves detailed multimodal analysis for a specific scan ID."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan #{scan_id} not found.")
    return scan


@router.delete("/api/scans/{scan_id}", tags=["History"])
def delete_scan_endpoint(scan_id: int):
    """Deletes a scan record from history."""
    deleted = delete_scan_by_id(scan_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan #{scan_id} not found.")
    return {"status": "success", "message": f"Scan #{scan_id} deleted."}


@router.get("/api/stats", response_model=DashboardStats, tags=["Analytics"])
def get_stats_endpoint():
    """Returns aggregated scan metrics and detection rates."""
    return get_dashboard_stats()


@router.get("/api/metrics", tags=["Analytics"])
def get_benchmark_metrics():
    """
    Returns authentic empirical evaluation metrics computed across strictly
    partitioned zero-day campaigns without domain leakage.
    """
    import json
    metrics_file = BACKEND_DIR.parent / "data" / "metrics.json"
    if metrics_file.exists():
        try:
            return json.loads(metrics_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning(f"Failed to read metrics file: {exc}")

    from training.evaluate import evaluate_zero_day_benchmark
    return evaluate_zero_day_benchmark()


@router.get("/api/test-pages", tags=["Demonstration"])
def list_test_pages():
    """Lists available local test pages for safe zero-day demonstration."""
    return [
        {
            "id": "legit-portal",
            "name": "Legitimate Cloud Architecture Portal",
            "category": "SAFE",
            "filename": "legitimate_portal.html",
            "expected": "SAFE (Risk ~0.04)",
            "description": "Legitimate enterprise technology portal with standard navigation and no credential collection."
        },
        {
            "id": "fake-login",
            "name": "Zero-Day Microsoft 365 Phishing",
            "category": "PHISHING",
            "filename": "fake_login_page.html",
            "expected": "PHISHING (Risk ~0.88)",
            "description": "Zero-day phishing masquerading as Microsoft 365 login, featuring urgency notices and cross-domain credential harvesting."
        },
        {
            "id": "fake-bank",
            "name": "Zero-Day Chase Online Banking Phishing",
            "category": "PHISHING",
            "filename": "fake_bank_login.html",
            "expected": "PHISHING (Risk ~0.88)",
            "description": "Impersonates Chase Online Banking requesting SSN and password due to fake fraudulent wire transfers."
        },
        {
            "id": "fake-account",
            "name": "Zero-Day PayPal Verification Phishing",
            "category": "PHISHING",
            "filename": "fake_account_verify.html",
            "expected": "PHISHING (Risk ~0.88)",
            "description": "Deceptive account suspension warning with credit card and password capture fields."
        }
    ]


@router.get("/test-pages/{filename}", response_class=HTMLResponse, tags=["Demonstration"])
def serve_test_page(filename: str):
    """
    Serves controlled test pages locally for safe demonstration.
    Enforces strict path containment, rejects path traversal segments, encoded separators,
    and symlinks.
    """
    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename required.")

    # Reject traversal sequences and separators
    if ".." in filename or "/" in filename or "\\" in filename or "%" in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Directory traversal characters are not permitted."
        )

    # Restrict strictly to authorized filenames
    if filename not in ALLOWED_FILENAMES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requested test page is not in the authorized demonstration registry."
        )

    resolved_path = (TEST_PAGES_DIR / filename).resolve()

    # Verify containment within TEST_PAGES_DIR
    if not resolved_path.is_relative_to(TEST_PAGES_DIR) or not resolved_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File containment check failed.")

    # Reject symlinks
    if resolved_path.is_symlink():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Symlinked test files are prohibited."
        )

    return FileResponse(resolved_path, media_type="text/html")
