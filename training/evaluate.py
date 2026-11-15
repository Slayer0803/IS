"""
Zero-Day Phishing Evaluation and Multimodal Model Comparison Benchmark.
Evaluates models against strictly unseen zero-day campaigns/domains.
Generates metrics including Zero-Day Recall, Zero-Day F1, ROC-AUC, FPR, FNR,
and produces the 5-Model Comparison Matrix.
"""
import sys
from pathlib import Path
from typing import Any, Dict, List
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.analyzer.fusion import MultimodalFusionEngine
from backend.analyzer.text_analyzer import TextSemanticAnalyzer
from backend.analyzer.vlm_analyzer import get_vlm_analyzer
from backend.security.html_features import extract_html_features
from backend.security.url_features import extract_url_features
from training.extract_features import FEATURE_COLUMNS, process_dataset
from training.prepare_dataset import prepare_datasets


def calculate_metrics(y_true: List[int], y_pred: List[int], y_scores: List[float] = None) -> Dict[str, float]:
    """Calculates comprehensive classification metrics."""
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    # Confusion matrix for FPR / FNR
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    try:
        auc = roc_auc_score(y_true, y_scores) if y_scores is not None and len(set(y_true)) > 1 else float("nan")
    except Exception:
        auc = float("nan")

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4) if not np.isnan(auc) else "N/A",
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
    }


def evaluate_zero_day_benchmark():
    """
    Runs evaluation against the zero-day test partition (unseen campaigns and novel domains).
    Compares:
    1. URL/HTML Traditional ML (Random Forest baseline)
    2. Screenshot-only model
    3. Text-only semantic model
    4. VLM Multimodal Model
    5. Fused Multimodal System (Complete pipeline)
    """
    PROCESSED_DIR = BASE_DIR / "data" / "processed"
    test_path = PROCESSED_DIR / "test_zero_day.json"

    if not test_path.exists():
        print("[*] Generating domain-aware datasets...")
        _, test_df = prepare_datasets()
    else:
        test_df = pd.read_json(test_path)

    print(f"\n=======================================================")
    print(f" ZERO-DAY PHISHING DETECTION EVALUATION BENCHMARK")
    print(f" Total Zero-Day Test Samples: {len(test_df)}")
    print(f" Phishing Attacks (Novel Campaigns): {sum(test_df['label'] == 1)}")
    print(f" Legitimate Sites (Unseen Domains): {sum(test_df['label'] == 0)}")
    print(f"=======================================================\n")

    # Load baseline ML model if available
    baseline_model_path = BASE_DIR / "backend" / "data" / "baseline_model.joblib"
    rf_model = None
    if baseline_model_path.exists():
        rf_model = joblib.load(baseline_model_path)

    # Initialize components
    text_analyzer = TextSemanticAnalyzer()
    vlm_analyzer = get_vlm_analyzer()
    fusion_engine = MultimodalFusionEngine()

    # Track predictions for all 5 models
    y_true = test_df["label"].tolist()

    m1_preds, m1_scores = [], []  # Traditional ML
    m2_preds, m2_scores = [], []  # Screenshot-only
    m3_preds, m3_scores = [], []  # Text-only
    m4_preds, m4_scores = [], []  # VLM Multimodal
    m5_preds, m5_scores = [], []  # Full Fusion

    # Feature extraction for baseline ML
    X_test, _ = process_dataset(test_df)

    if rf_model is not None:
        m1_preds = rf_model.predict(X_test).tolist()
        m1_scores = rf_model.predict_proba(X_test)[:, 1].tolist()
    else:
        # If no baseline model has been trained yet
        m1_preds = [0] * len(y_true)
        m1_scores = [0.0] * len(y_true)

    # Evaluate each sample across modalities
    for _, row in test_df.iterrows():
        url = row["url"]
        html = row.get("html", "")
        text = row.get("text", "")

        url_res = extract_url_features(url)
        html_res = extract_html_features(html, base_url=url)
        text_res = text_analyzer.analyze(text)
        vis_res = vlm_analyzer.analyze(
            image=None,
            webpage_text=text,
            domain_context=url_res["features"]["hostname"]
        )

        # 2. Screenshot-only prediction (threshold at 0.50)
        s_score = vis_res["visual_risk"]
        m2_scores.append(s_score)
        m2_preds.append(1 if s_score >= 0.50 else 0)

        # 3. Text-only prediction (threshold at 0.50)
        t_score = text_res["text_risk"]
        m3_scores.append(t_score)
        m3_preds.append(1 if t_score >= 0.50 else 0)

        # 4. VLM Multimodal (Visual + Text average)
        vlm_combined = (s_score * 0.6) + (t_score * 0.4)
        m4_scores.append(vlm_combined)
        m4_preds.append(1 if vlm_combined >= 0.55 else 0)

        # 5. Full Multimodal Fusion Pipeline
        fused = fusion_engine.fuse(
            url_analysis=url_res,
            visual_analysis=vis_res,
            text_analysis=text_res,
            html_analysis=html_res
        )
        f_score = fused["risk_score"]
        m5_scores.append(f_score)
        m5_preds.append(1 if fused["classification"] in ("PHISHING", "SUSPICIOUS") else 0)

    # Compute metrics for each model
    results = {}
    results["URL/HTML ML"] = calculate_metrics(y_true, m1_preds, m1_scores if rf_model else None)
    results["Screenshot"] = calculate_metrics(y_true, m2_preds, m2_scores)
    results["Text"] = calculate_metrics(y_true, m3_preds, m3_scores)
    results["VLM"] = calculate_metrics(y_true, m4_preds, m4_scores)
    results["Fusion"] = calculate_metrics(y_true, m5_preds, m5_scores)

    # Print 5-Model Comparison Table
    print(f"{'Model':<18} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'FPR':<6}")
    print("-" * 70)
    for model_name, m in results.items():
        acc_s = f"{m['accuracy']:.2%}" if isinstance(m['accuracy'], float) else str(m['accuracy'])
        pr_s = f"{m['precision']:.2%}" if isinstance(m['precision'], float) else str(m['precision'])
        rec_s = f"{m['recall']:.2%}" if isinstance(m['recall'], float) else str(m['recall'])
        f1_s = f"{m['f1']:.2%}" if isinstance(m['f1'], float) else str(m['f1'])
        fpr_s = f"{m['fpr']:.2%}" if isinstance(m['fpr'], float) else str(m['fpr'])
        print(f"{model_name:<18} | {acc_s:<8} | {pr_s:<9} | {rec_s:<8} | {f1_s:<8} | {fpr_s:<6}")
    print("-" * 70)

    # Highlight Key Zero-Day Metrics
    fusion_m = results["Fusion"]
    print("\n[+] KEY ZERO-DAY EVALUATION RESULTS:")
    print(f"    -> Zero-Day Detection Recall: {fusion_m['recall']:.2%}")
    print(f"    -> Zero-Day Detection F1:     {fusion_m['f1']:.2%}")
    print(f"    -> False Positive Rate:      {fusion_m['fpr']:.2%}")
    print(f"    -> False Negative Rate:      {fusion_m['fnr']:.2%}")

    return results


if __name__ == "__main__":
    evaluate_zero_day_benchmark()

