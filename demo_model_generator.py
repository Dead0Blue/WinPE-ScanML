"""
demo_model_generator.py
─────────────────────────────────────────────
Generates a working Random Forest model trained on synthetic PE-like data.
Run this once so malware_detector.py can launch immediately without the EMBER dataset.

Usage:
    python demo_model_generator.py
"""

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model_artifacts")
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Feature list (must match malware_detector.py extract_features) ──
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

N = 10000  # samples
rng = np.random.default_rng(42)

print(f"[*] Generating {N} synthetic PE samples…")

# Benign samples (label 0)
b = N // 2
benign = {
    "FileSize":               rng.integers(50_000, 5_000_000, b),
    "FileEntropy":            rng.uniform(4.5, 6.8, b),
    "SizeOfOptionalHeader":   rng.choice([224, 240], b),
    "Characteristics":        rng.integers(256, 8192, b),
    "MajorLinkerVersion":     rng.integers(6, 14, b),
    "MinorLinkerVersion":     rng.integers(0, 3, b),
    "SizeOfCode":             rng.integers(10_000, 2_000_000, b),
    "SizeOfInitializedData":  rng.integers(1_000, 500_000, b),
    "SizeOfUninitializedData":rng.integers(0, 5_000, b),
    "AddressOfEntryPoint":    rng.integers(0x1000, 0x100000, b),
    "BaseOfCode":             rng.choice([0x1000], b),
    "ImageBase":              rng.choice([0x400000, 0x10000000], b),
    "SectionAlignment":       rng.choice([0x1000], b),
    "FileAlignment":          rng.choice([0x200, 0x1000], b),
    "MajorOSVersion":         rng.choice([5, 6, 10], b),
    "MinorOSVersion":         rng.choice([0, 1, 2], b),
    "SizeOfImage":            rng.integers(100_000, 10_000_000, b),
    "SizeOfHeaders":          rng.choice([0x400, 0x1000], b),
    "Subsystem":              rng.choice([2, 3], b),
    "TimeDateStamp":          rng.integers(1_000_000_000, 1_700_000_000, b),
    "NumberOfSections":       rng.integers(3, 8, b),
    "AvgSectionEntropy":      rng.uniform(4.0, 6.5, b),
    "MaxSectionEntropy":      rng.uniform(5.0, 7.0, b),
    "AvgVsizeRatio":          rng.uniform(0.8, 2.0, b),
    "NumberOfImports":        rng.integers(20, 300, b),
    "NumberOfImportDLLs":     rng.integers(2, 20, b),
    "SuspiciousImports":      rng.integers(0, 3, b),
    "NumberOfExports":        rng.integers(0, 10, b),
    "HasASLR":                rng.integers(0, 2, b),
    "HasDEP":                 rng.integers(0, 2, b),
    "HasSEH":                 rng.integers(0, 2, b),
    "HasCFG":                 rng.integers(0, 2, b),
    "NumberOfResources":      rng.integers(0, 50, b),
}

# Malicious samples (label 1) — higher entropy, more suspicious imports, odd section counts
m = N - b
malicious = {
    "FileSize":               rng.integers(5_000, 500_000, m),
    "FileEntropy":            rng.uniform(6.5, 8.0, m),
    "SizeOfOptionalHeader":   rng.choice([224, 240], m),
    "Characteristics":        rng.integers(256, 8192, m),
    "MajorLinkerVersion":     rng.integers(2, 10, m),
    "MinorLinkerVersion":     rng.integers(0, 10, m),
    "SizeOfCode":             rng.integers(1_000, 200_000, m),
    "SizeOfInitializedData":  rng.integers(100, 100_000, m),
    "SizeOfUninitializedData":rng.integers(0, 50_000, m),
    "AddressOfEntryPoint":    rng.integers(0x100, 0x5000, m),
    "BaseOfCode":             rng.integers(0x100, 0x2000, m),
    "ImageBase":              rng.choice([0x400000, 0x1000000], m),
    "SectionAlignment":       rng.choice([0x1000], m),
    "FileAlignment":          rng.choice([0x200, 0x1000], m),
    "MajorOSVersion":         rng.choice([4, 5, 6], m),
    "MinorOSVersion":         rng.choice([0, 1], m),
    "SizeOfImage":            rng.integers(10_000, 1_000_000, m),
    "SizeOfHeaders":          rng.choice([0x400, 0x1000], m),
    "Subsystem":              rng.choice([1, 2, 3], m),
    "TimeDateStamp":          rng.integers(0, 500_000_000, m),
    "NumberOfSections":       rng.integers(1, 4, m),
    "AvgSectionEntropy":      rng.uniform(6.5, 8.0, m),
    "MaxSectionEntropy":      rng.uniform(7.0, 8.0, m),
    "AvgVsizeRatio":          rng.uniform(3.0, 20.0, m),
    "NumberOfImports":        rng.integers(1, 30, m),
    "NumberOfImportDLLs":     rng.integers(1, 5, m),
    "SuspiciousImports":      rng.integers(3, 15, m),
    "NumberOfExports":        rng.integers(0, 5, m),
    "HasASLR":                rng.integers(0, 2, m),
    "HasDEP":                 rng.integers(0, 2, m),
    "HasSEH":                 rng.integers(0, 2, m),
    "HasCFG":                 rng.integers(0, 2, m),
    "NumberOfResources":      rng.integers(0, 5, m),
}

df_benign = pd.DataFrame(benign)
df_benign["label"] = 0
df_malicious = pd.DataFrame(malicious)
df_malicious["label"] = 1

df = pd.concat([df_benign, df_malicious], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

X = df[FEATURE_COLUMNS]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train Random Forest
print("[*] Training Random Forest classifier…")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=2,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced",
)
model.fit(X_train_scaled, y_train)

# Evaluate
y_pred = model.predict(X_test_scaled)
print("\n── Classification Report ──")
print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

# Save
joblib.dump(model, os.path.join(MODEL_DIR, "model.pkl"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
joblib.dump(FEATURE_COLUMNS, os.path.join(MODEL_DIR, "features_columns.pkl"))

# Feature importance report
print("\n── Top 10 Most Important Features ──")
importances = sorted(zip(FEATURE_COLUMNS, model.feature_importances_),
                     key=lambda x: x[1], reverse=True)
for feat, imp in importances[:10]:
    bar = "█" * int(imp * 60)
    print(f"  {feat:<30} {bar} {imp:.4f}")

with open(os.path.join(MODEL_DIR, "feature_info.txt"), "w") as f:
    f.write("Feature importances (Random Forest)\n")
    f.write("=" * 50 + "\n")
    for feat, imp in importances:
        f.write(f"{feat:<35} {imp:.6f}\n")

print(f"\n[✓] Model files saved to: {MODEL_DIR}")
print("[✓] You can now run: python malware_detector.py")
