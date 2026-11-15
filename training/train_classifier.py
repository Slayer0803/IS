"""
Traditional Machine Learning Baseline Trainer.
Trains Random Forest classifiers on URL, HTML, text, and visual structural features.
Saves versioned model file backend/data/baseline_model_v1.joblib for production ML comparison.
"""
import sys
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.analyzer.ml_baseline import MODEL_PATH, MODEL_VERSION
from training.extract_features import process_dataset
from training.prepare_dataset import prepare_datasets


def train_baseline_models(save_model: bool = True):
    """Trains traditional ML model on the domain-aware training partition."""
    PROCESSED_DIR = BASE_DIR / "data" / "processed"
    train_path = PROCESSED_DIR / "train_domain_aware.json"

    if not train_path.exists():
        print("[*] Generating domain-aware datasets...")
        train_df, _ = prepare_datasets()
    else:
        train_df = pd.read_json(train_path)

    print(f"[*] Extracting feature representations for {len(train_df)} training samples...")
    X_train, y_train = process_dataset(train_df)

    # Train Random Forest Classifier
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
    print("\n--- Feature Importances ---")
    for feat_name, imp in importances[:8]:
        print(f"  {feat_name:25s}: {imp:.4f}")

    if save_model:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(rf_model, MODEL_PATH)
        print(f"\n[+] Saved versioned baseline model ({MODEL_VERSION}) to {MODEL_PATH}")

    return rf_model


if __name__ == "__main__":
    train_baseline_models()
