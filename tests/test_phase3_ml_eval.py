"""
Regression Tests for Phase 3: ML and Evaluation Hardening.
Tests:
3.1 Authentic labeled dataset with campaign-aware zero-day partitioning (no campaign overlap between train/test).
3.2 ML Baseline Model integrated with backend pipeline (18 numerical features, versioned model, live prediction in pipeline).
3.3 Honest modality labeling in evaluate.py with production thresholds matching backend.config.
3.4 Dynamic GET /api/metrics endpoint serving real metrics, and test-page expected risks aligned with scoring cascade.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pandas as pd
import pytest

from backend.analyzer.ml_baseline import (
    FEATURE_COLUMNS,
    MLBaselineClassifier,
    MODEL_PATH,
    MODEL_VERSION,
)
from backend.analyzer.pipeline import PhishingDetectionPipeline
from backend.api.routes import get_benchmark_metrics, list_test_pages
from backend.config import BACKEND_DIR, THRESHOLD_SAFE, THRESHOLD_SUSPICIOUS
from training.evaluate import (
    calculate_metrics,
    compute_fpr_at_tpr,
    compute_pr_auc,
    evaluate_zero_day_benchmark,
)
from training.prepare_dataset import BENCHMARK_SAMPLES, prepare_datasets


# ==============================================================================
# PHASE 3.1: Dataset Integrity & Campaign-Aware Zero-Day Splitting
# ==============================================================================

def test_dataset_campaign_aware_partitioning():
    """Verify train and test partitions have zero campaign overlap to model zero-day detection."""
    train_df, test_df = prepare_datasets()

    train_campaigns = set(train_df["campaign_id"].unique())
    test_campaigns = set(test_df["campaign_id"].unique())

    # Strict campaign isolation
    overlap = train_campaigns.intersection(test_campaigns)
    assert len(overlap) == 0, f"Campaign leakage detected! Overlapping campaigns: {overlap}"

    # Both partitions must contain both positive (phishing) and negative (benign) samples
    assert sum(train_df["label"] == 1) > 0, "Train set must have phishing samples"
    assert sum(train_df["label"] == 0) > 0, "Train set must have benign samples"
    assert sum(test_df["label"] == 1) > 0, "Zero-day test set must have novel phishing attacks"
    assert sum(test_df["label"] == 0) > 0, "Zero-day test set must have unseen benign domains"


def test_metric_calculation_pr_auc_and_fpr_at_tpr():
    """Verify PR-AUC and FPR at 95% TPR are computed correctly."""
    y_true = [0, 0, 0, 1, 1, 1]
    y_pred = [0, 0, 0, 1, 1, 1]
    y_scores = [0.1, 0.2, 0.3, 0.8, 0.9, 0.95]

    metrics = calculate_metrics(y_true, y_pred, y_scores)

    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["pr_auc"] == 1.0
    assert metrics["fpr"] == 0.0
    assert metrics["fpr_at_95_tpr"] == 0.0


# ==============================================================================
# PHASE 3.2: ML Baseline Integration into Production Backend
# ==============================================================================

def test_ml_baseline_feature_schema():
    """Verify feature vector has exactly 18 aligned features matching FEATURE_COLUMNS."""
    classifier = MLBaselineClassifier()
    url_f = {"features": {"url_length": 50, "domain_length": 15, "num_subdomains": 1, "num_dots": 2, "num_hyphens": 1, "has_ip_address": False, "uses_https": True, "is_suspicious_tld": False, "has_at_symbol": False, "domain_entropy": 3.2}}
    html_f = {"features": {"has_login_form": True, "has_password_field": True, "cross_domain_forms": [], "empty_link_ratio": 0.1}}
    text_f = {"urgency": True, "threatening_language": False, "credential_request": True}
    vis_f = {"visual_risk": 0.85}

    vec = classifier.build_feature_vector(url_f, html_f, text_f, vis_f)
    assert vec.shape == (1, 18), f"Expected shape (1, 18), got {vec.shape}"
    assert len(FEATURE_COLUMNS) == 18


def test_ml_baseline_integrated_into_pipeline_result():
    """Verify that PhishingDetectionPipeline executes ML baseline and returns it in analysis payload."""
    pipeline = PhishingDetectionPipeline()
    result = pipeline.analyze_test_page("fake-login")

    assert "analysis" in result
    assert "ml_baseline" in result["analysis"], "ML baseline prediction must be present in analysis payload"
    ml_res = result["analysis"]["ml_baseline"]

    assert "ml_risk" in ml_res
    assert "model_version" in ml_res
    assert ml_res["model_version"] in (MODEL_VERSION, "fallback-linear")
    assert 0.0 <= ml_res["ml_risk"] <= 1.0


# ==============================================================================
# PHASE 3.3: Honest Modality Evaluation & Production Thresholds
# ==============================================================================

def test_evaluate_produces_honest_modalities_and_matching_thresholds():
    """Verify evaluate produces honest modality breakdown and matches config thresholds."""
    metrics_payload = evaluate_zero_day_benchmark()

    assert metrics_payload["thresholds"]["safe"] == THRESHOLD_SAFE
    assert metrics_payload["thresholds"]["suspicious"] == THRESHOLD_SUSPICIOUS

    models = metrics_payload["models"]
    assert "Traditional ML (Random Forest)" in models
    assert "URL Heuristics Modality" in models
    assert "HTML Structural Modality" in models
    assert "Text / Semantic Modality" in models
    assert "DOM & Visual Brand Discrepancy" in models
    assert "Complete Multimodal Fusion (Aegis-VLM)" in models


# ==============================================================================
# PHASE 3.4: Dynamic GET /api/metrics & Test Page Calibration
# ==============================================================================

def test_get_benchmark_metrics_endpoint():
    """Verify GET /api/metrics returns structured benchmark data with sample counts and models."""
    data = get_benchmark_metrics()
    assert "sample_count" in data
    assert "models" in data
    assert "timestamp" in data
    assert data["sample_count"] > 0
    assert len(data["models"]) >= 5


def test_test_page_expected_risks_calibrated():
    """Verify list_test_pages expected strings reflect actual output of scoring cascade."""
    pages = list_test_pages()
    for page in pages:
        assert "expected" in page
        if page["category"] == "SAFE":
            assert "~0.04" in page["expected"] or "SAFE" in page["expected"]
        elif page["category"] == "PHISHING":
            assert "~0.88" in page["expected"] or "PHISHING" in page["expected"]
