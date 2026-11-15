"""
Traditional Machine Learning Baseline Trainer.
Trains Random Forest and Logistic Regression classifiers on URL and HTML structural features,
providing a baseline to compare against zero-day multimodal VLM detection.
"""
import sys
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from training.extract_features import process_dataset
from training.prepare_dataset import prepare_datasets


def train_baseline_models(save_model: bool = True):
    """Trains traditional ML models on the domain-aware training partition."""
    PROCESSED_DIR = BASE_DIR / "data" / "processed"
    train_path = PROCESSED_DIR / "train_domain_aware.json"

    if not train_path.exists():
        print("[*] Generating domain-aware datasets...")
        train_df, _ = prepare_datasets()
    else:
        train_df = pd.read_json(train_path)

    print(f"[*] Extracting feature representations for {len(train_df)} training samples...")
    X_train, y_train = process_dataset(train_df)

    # 1. Train Random Forest Classifier
    print("[*] Training Random Forest Baseline Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf_model.fit(X_train, y_train)

    train_preds = rf_model.predict(X_train)
    train_acc = accuracy_score(y_train, train_preds)
    train_f1 = f1_score(y_train, train_preds, zero_division=0)

    print(f"[+] Random Forest Training Accuracy: {train_acc:.2%}, F1: {train_f1:.2%}")

    # Inspect Feature Importances
    importances = sorted(
        zip(X_train.columns, rf_model.feature_importances_),
        key=lambda x: x[1],
        reverse=True
    )
    print("\n--- Top Traditional Feature Importances ---")
    for feat_name, imp in importances[:6]:
        print(f"  {feat_name:25s}: {imp:.4f}")

    if save_model:
        model_out_path = BASE_DIR / "backend" / "data" / "baseline_model.joblib"
        model_out_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(rf_model, model_out_path)
        print(f"\n[+] Saved baseline model to {model_out_path}")

    return rf_model


if __name__ == "__main__":
    train_baseline_models()

