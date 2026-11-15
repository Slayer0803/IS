"""
ML Baseline Classifier Module.
Integrates trained Random Forest and structural classifier models into the production pipeline.
Serves as an independent ML modality comparing traditional feature engineering
against zero-day multimodal VLM reasoning.
"""
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import joblib
import numpy as np

from backend.config import BACKEND_DIR

logger = logging.getLogger(__name__)

MODEL_VERSION = "v1.0-rf"
MODEL_PATH = BACKEND_DIR / "data" / "baseline_model_v1.joblib"

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "has_ip_address",
    "uses_https",
    "is_suspicious_tld",
    "has_at_symbol",
    "domain_entropy",
    "has_login_form",
    "has_password_field",
    "cross_domain_forms_count",
    "empty_link_ratio",
    "has_urgency",
    "has_threats",
    "has_credential_request",
    "visual_risk",
]


class MLBaselineClassifier:
    """
    Evaluates traditional machine-learning models against extracted multimodal feature vectors.
    """

    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self):
        try:
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
                logger.info(f"Loaded ML baseline classifier: {self.model_path.name}")
        except Exception as exc:
            logger.warning(f"Could not load ML baseline model from {self.model_path}: {exc}")
            self.model = None

    def build_feature_vector(
        self,
        url_features: Dict[str, Any],
        html_features: Dict[str, Any],
        text_features: Dict[str, Any],
        visual_features: Dict[str, Any]
    ) -> np.ndarray:
        """Constructs an aligned 18-dimensional numerical feature vector matching the training schema."""
        uf = url_features.get("features", {})
        hf = html_features.get("features", {})

        row = [
            float(uf.get("url_length", 0)),
            float(uf.get("domain_length", 0)),
            float(uf.get("num_subdomains", 0)),
            float(uf.get("num_dots", 0)),
            float(uf.get("num_hyphens", 0)),
            1.0 if uf.get("has_ip_address") else 0.0,
            1.0 if uf.get("uses_https") else 0.0,
            1.0 if uf.get("is_suspicious_tld") else 0.0,
            1.0 if uf.get("has_at_symbol") else 0.0,
            float(uf.get("domain_entropy", 0.0)),
            1.0 if hf.get("has_login_form") else 0.0,
            1.0 if hf.get("has_password_field") else 0.0,
            float(len(hf.get("cross_domain_forms", []))),
            float(hf.get("empty_link_ratio", 0.0)),
            1.0 if text_features.get("urgency") else 0.0,
            1.0 if text_features.get("threatening_language") else 0.0,
            1.0 if text_features.get("credential_request") else 0.0,
            float(visual_features.get("visual_risk", 0.0)),
        ]
        return np.array([row], dtype=np.float32)

    def predict(
        self,
        url_features: Dict[str, Any],
        html_features: Dict[str, Any],
        text_features: Dict[str, Any],
        visual_features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executes ML baseline prediction.
        Returns:
            Dict containing ml_risk [0.0 - 1.0], classification, confidence, and feature schema version.
        """
        vec = self.build_feature_vector(url_features, html_features, text_features, visual_features)

        if self.model is not None:
            try:
                import pandas as pd
                df_vec = pd.DataFrame(vec, columns=FEATURE_COLUMNS)
                proba = self.model.predict_proba(df_vec)[0][1]
                pred = int(self.model.predict(df_vec)[0])
                classification = "PHISHING" if proba >= 0.50 else "SAFE"
                confidence = round(max(proba, 1.0 - proba), 3)
                return {
                    "ml_risk": round(float(proba), 3),
                    "classification": classification,
                    "confidence": confidence,
                    "is_active": True,
                    "model_version": MODEL_VERSION,
                    "model_type": self.model.__class__.__name__
                }
            except Exception as exc:
                logger.error(f"ML baseline inference failure: {exc}")

        # Fallback logistic decision function when weights file is not yet built
        # Heuristic linear baseline based on feature weights
        w = np.array([
            0.02, 0.01, 0.08, 0.05, 0.06, 0.20, -0.10, 0.15, 0.25, 0.10,
            0.12, 0.25, 0.25, 0.10, 0.15, 0.15, 0.20, 0.35
        ], dtype=np.float32)
        score = float(1.0 / (1.0 + np.exp(- (np.dot(vec[0], w) - 2.5))))
        score = min(1.0, max(0.0, round(score, 3)))
        return {
            "ml_risk": score,
            "classification": "PHISHING" if score >= 0.50 else "SAFE",
            "confidence": 0.75,
            "is_active": False,
            "model_version": "fallback-linear",
            "model_type": "LogisticFallback"
        }
