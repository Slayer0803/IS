"""
Feature Extraction for Baseline Traditional ML Models and Multimodal Pipelines.
Transforms raw webpage samples into numerical vectors across URL, HTML, NLP, and Visual dimensions.
"""
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pandas as pd

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.analyzer.text_analyzer import TextSemanticAnalyzer
from backend.analyzer.vlm_analyzer import get_vlm_analyzer
from backend.security.html_features import extract_html_features
from backend.security.url_features import extract_url_features

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


def extract_features_from_sample(
    url: str,
    html: str,
    text: str,
    text_analyzer: TextSemanticAnalyzer,
    vlm_analyzer: Any
) -> Dict[str, float]:
    """Extracts a comprehensive numerical feature dictionary from a single sample."""
    url_res = extract_url_features(url)
    html_res = extract_html_features(html, base_url=url)
    text_res = text_analyzer.analyze(text)
    vis_res = vlm_analyzer.analyze(image=None, webpage_text=text, domain_context=url_res["features"]["hostname"])

    f = url_res["features"]
    hf = html_res["features"]

    return {
        "url_length": float(f["url_length"]),
        "domain_length": float(f["domain_length"]),
        "num_subdomains": float(f["num_subdomains"]),
        "num_dots": float(f["num_dots"]),
        "num_hyphens": float(f["num_hyphens"]),
        "has_ip_address": 1.0 if f["has_ip_address"] else 0.0,
        "uses_https": 1.0 if f["uses_https"] else 0.0,
        "is_suspicious_tld": 1.0 if f["is_suspicious_tld"] else 0.0,
        "has_at_symbol": 1.0 if f["has_at_symbol"] else 0.0,
        "domain_entropy": float(f["domain_entropy"]),
        "has_login_form": 1.0 if hf["has_login_form"] else 0.0,
        "has_password_field": 1.0 if hf["has_password_field"] else 0.0,
        "cross_domain_forms_count": float(len(hf["cross_domain_forms"])),
        "empty_link_ratio": float(hf["empty_link_ratio"]),
        "has_urgency": 1.0 if text_res["urgency"] else 0.0,
        "has_threats": 1.0 if text_res["threatening_language"] else 0.0,
        "has_credential_request": 1.0 if text_res["credential_request"] else 0.0,
        "visual_risk": float(vis_res["visual_risk"]),
    }


def process_dataset(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Processes DataFrame of samples into X feature matrix and y labels."""
    text_analyzer = TextSemanticAnalyzer()
    vlm_analyzer = get_vlm_analyzer()

    feature_rows = []
    labels = []

    for _, row in df.iterrows():
        feat = extract_features_from_sample(
            url=row["url"],
            html=row.get("html", ""),
            text=row.get("text", ""),
            text_analyzer=text_analyzer,
            vlm_analyzer=vlm_analyzer
        )
        feature_rows.append(feat)
        labels.append(int(row["label"]))

    X = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
    y = pd.Series(labels, name="label")
    return X, y


if __name__ == "__main__":
    PROCESSED_DIR = BASE_DIR / "data" / "processed"
    train_path = PROCESSED_DIR / "train_domain_aware.json"

    if train_path.exists():
        train_df = pd.read_json(train_path)
        X, y = process_dataset(train_df)
        print(f"[+] Feature matrix shape: {X.shape}, labels: {y.shape}")
        print(f"[+] Feature columns: {FEATURE_COLUMNS}")
    else:
        print(f"[-] Training data not found at {train_path}. Run prepare_dataset.py first.")

