"""
train_model.py
─────────────────────────────────────────────
Train the WinPE-ScanML malware detection model from:
  • The EMBER 2018 dataset (JSONL format), OR
  • The provided sample Excel file (data/sample_database.csv.xlsx)

Usage:
    # From sample Excel (included in repo):
    python train_model.py --data data/sample_database.csv.xlsx

    # From EMBER 2018 full dataset:
    python train_model.py --train data/train_features_X.npy --labels data/train_labels_y.npy

    # From raw EMBER JSONL:
    python train_model.py --ember /path/to/ember_dataset_2018_2 --limit 50000
"""

import os
import sys
import argparse
import warnings
import json

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    accuracy_score, precision_score, recall_score, f1_score
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model_artifacts")
os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLUMNS = [
    "FileSize", "FileEntropy",
    "SizeOfOptionalHeader", "Characteristics",
    "MajorLinkerVersion", "MinorLinkerVersion",
    "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
    "AddressOfEntryPoint", "BaseOfCode", "ImageBase",
    "SectionAlignment", "FileAlignment",
    "MajorOSVersion", "MinorOSVersion",
    "SizeOfImage", "SizeOfHeaders",
    "Subsystem", "TimeDateStamp",
    "NumberOfSections", "AvgSectionEntropy", "MaxSectionEntropy", "AvgVsizeRatio",
    "NumberOfImports", "NumberOfImportDLLs", "SuspiciousImports",
    "NumberOfExports",
    "HasASLR", "HasDEP", "HasSEH", "HasCFG",
    "NumberOfResources",
]

# ── EMBER columns that map to our features (best effort) ──
EMBER_COLUMN_MAP = {
    "SizeOfOptionalHeader": "optional_header_size",
    "Characteristics": "file_header_characteristics",
    "SizeOfCode": "code_size",
    "SizeOfInitializedData": "initialized_size",
    "SizeOfUninitializedData": "uninitialized_size",
    "AddressOfEntryPoint": "entry_point",
    "SizeOfImage": "virtual_size",
    "SizeOfHeaders": "headers_size",
    "NumberOfSections": "num_sections",
    "NumberOfImports": "num_imports",
    "NumberOfExports": "num_exports",
    "FileEntropy": "byte_entropy",
}


def load_from_excel(path: str):
    print(f"[*] Loading data from: {path}")
    df = pd.read_excel(path)
    print(f"    Rows: {len(df)}, Columns: {list(df.columns)[:10]}…")

    # Auto-detect label column
    label_col = None
    for candidate in ["label", "Label", "malware", "class", "y"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if not label_col:
        raise ValueError(f"Could not find a label column. Available: {list(df.columns)}")

    y = df[label_col].astype(int)
    X = df.drop(columns=[label_col])

    # Map available features
    available = [c for c in FEATURE_COLUMNS if c in X.columns]
    missing = [c for c in FEATURE_COLUMNS if c not in X.columns]
    if missing:
        print(f"    [!] Missing features (will zero-fill): {missing}")
        for m in missing:
            X[m] = 0

    return X[FEATURE_COLUMNS], y


def load_from_ember_jsonl(data_dir: str, limit: int = None):
    print(f"[*] Loading EMBER JSONL from: {data_dir}")
    all_rows, all_labels = [], []

    for split in ("train", "test"):
        for i in range(6):
            path = os.path.join(data_dir, f"{split}_features_{i}.jsonl")
            if not os.path.isfile(path):
                continue
            with open(path) as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    label = obj.get("label", -1)
                    if label == -1:
                        continue
                    row = {col: 0 for col in FEATURE_COLUMNS}
                    for our_col, ember_col in EMBER_COLUMN_MAP.items():
                        row[our_col] = obj.get(ember_col, 0) or 0

                    # Entropy from byte histogram
                    if "histogram" in obj:
                        hist = np.array(obj["histogram"], dtype=float)
                        hist /= hist.sum() + 1e-9
                        row["FileEntropy"] = float(-np.sum(hist * np.log2(hist + 1e-9)))

                    all_rows.append(row)
                    all_labels.append(label)

                    if limit and len(all_rows) >= limit:
                        break
            if limit and len(all_rows) >= limit:
                break

    df = pd.DataFrame(all_rows)
    y = pd.Series(all_labels)
    print(f"    Loaded {len(df)} samples | label distribution: {y.value_counts().to_dict()}")
    return df[FEATURE_COLUMNS], y


def train_and_evaluate(X: pd.DataFrame, y: pd.Series, args):
    print(f"\n[*] Dataset: {len(X)} rows, {len(FEATURE_COLUMNS)} features")
    print(f"    Label balance — Benign: {(y==0).sum()} | Malicious: {(y==1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2,
                                                          random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    print("\n[*] Training models…")
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=20, min_samples_leaf=2,
        n_jobs=-1, random_state=42, class_weight="balanced"
    )
    lr = LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced", random_state=42)

    rf.fit(X_train_s, y_train)
    lr.fit(X_train_s, y_train)

    # Ensemble (soft voting)
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("lr", lr)],
        voting="soft", weights=[3, 1]
    )
    ensemble.fit(X_train_s, y_train)

    # Evaluate
    model = ensemble
    y_pred = model.predict(X_test_s)
    y_prob = model.predict_proba(X_test_s)[:, 1]

    print("\n" + "─" * 55)
    print("  EVALUATION RESULTS")
    print("─" * 55)
    print(f"  Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
    print(f"  Precision : {precision_score(y_test, y_pred):.4f}")
    print(f"  Recall    : {recall_score(y_test, y_pred):.4f}")
    print(f"  F1 Score  : {f1_score(y_test, y_pred):.4f}")
    print(f"  ROC-AUC   : {roc_auc_score(y_test, y_prob):.4f}")
    print("─" * 55)
    print("\n" + classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

    # Feature importance from RF
    importances = sorted(zip(FEATURE_COLUMNS, rf.feature_importances_),
                          key=lambda x: x[1], reverse=True)
    print("\n── Top 10 Features (Random Forest) ──")
    for feat, imp in importances[:10]:
        bar = "█" * int(imp * 50)
        print(f"  {feat:<30} {bar} {imp:.4f}")

    # Save
    joblib.dump(model, os.path.join(MODEL_DIR, "model.pkl"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(FEATURE_COLUMNS, os.path.join(MODEL_DIR, "features_columns.pkl"))

    with open(os.path.join(MODEL_DIR, "feature_info.txt"), "w") as f:
        f.write("Feature importances (Random Forest component)\n")
        f.write("=" * 50 + "\n")
        for feat, imp in importances:
            f.write(f"{feat:<35} {imp:.6f}\n")

    print(f"\n[✓] Model saved to: {MODEL_DIR}")
    print("[✓] Run: python malware_detector.py")


def main():
    parser = argparse.ArgumentParser(
        description="Train WinPE-ScanML malware detection model"
    )
    parser.add_argument("--data", type=str, default=None,
                        help="Path to Excel/CSV dataset (any format with a label column)")
    parser.add_argument("--ember", type=str, default=None,
                        help="Path to EMBER 2018 dataset directory (JSONL files)")
    parser.add_argument("--limit", type=int, default=50000,
                        help="Max samples to load from EMBER (default: 50000)")
    args = parser.parse_args()

    if args.data:
        if args.data.endswith(".xlsx") or args.data.endswith(".xls"):
            X, y = load_from_excel(args.data)
        elif args.data.endswith(".csv"):
            df = pd.read_csv(args.data)
            y = df.pop(df.columns[-1]).astype(int)
            X = df
            for col in FEATURE_COLUMNS:
                if col not in X.columns:
                    X[col] = 0
            X = X[FEATURE_COLUMNS]
        else:
            print("Unsupported file type. Use .xlsx, .xls, or .csv")
            sys.exit(1)
    elif args.ember:
        X, y = load_from_ember_jsonl(args.ember, limit=args.limit)
    else:
        print("No data source specified. Using sample data…")
        sample = os.path.join(BASE_DIR, "data", "sample_database.csv.xlsx")
        if os.path.isfile(sample):
            X, y = load_from_excel(sample)
        else:
            print(f"Sample file not found at: {sample}")
            print("Run: python demo_model_generator.py  (creates synthetic model)")
            sys.exit(1)

    train_and_evaluate(X, y, args)


if __name__ == "__main__":
    main()
