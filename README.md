# 🛡️ WinPE-ScanML — Advanced PE Malware Detector

> ML-powered Windows PE file malware detection with a modern dark-mode GUI.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![ML](https://img.shields.io/badge/Model-Random%20Forest-green)
![Dataset](https://img.shields.io/badge/Dataset-EMBER%202018-orange)

---

## ✨ Features (v2.0)

| Feature | Details |
|---|---|
| **30+ PE Features** | Header fields, section entropy, imports, exports, security flags |
| **Random Forest** | Ensemble model, far superior to simple logistic regression |
| **4 Functional Pages** | Dashboard · Analyse · History · Settings |
| **Drag & Drop** | Drop `.exe`/`.dll` files directly onto the app (requires `tkinterdnd2`) |
| **Batch Scanning** | Select multiple files at once — all scanned in parallel |
| **Scan History** | Persistent across sessions, saved to `scan_history.json` |
| **Export** | Export history to CSV or JSON |
| **Threat Gauge** | Semi-circular threat score visualizer |
| **Suspicious Import Detection** | Flags VirtualAlloc, CreateRemoteThread, URLDownloadToFile, etc. |
| **Dark / Light Themes** | Switchable in Settings |
| **Copy Hashes** | One-click copy SHA256 / MD5 to clipboard |

---

## 📦 Prerequisites

- Python 3.8+
- Windows (optimized), macOS, Linux

---

## 🔧 Quick Start

### Option A — PowerShell (recommended)

```powershell
git clone https://github.com/Dead0Blue/WinPE-ScanML.git
cd WinPE-ScanML
.\setup.ps1
python malware_detector.py
```

### Option B — Manual

```bash
git clone https://github.com/Dead0Blue/WinPE-ScanML.git
cd WinPE-ScanML
pip install -r requirements.txt
python demo_model_generator.py   # Creates model_artifacts/*.pkl
python malware_detector.py
```

The `setup.ps1` script will:
1. Install all Python dependencies
2. Auto-generate demo model files (no EMBER dataset needed)
3. Print the launch command

---

## 🧠 Retraining the Model

### With the included sample dataset
```bash
python train_model.py --data data/sample_database.csv.xlsx
```

### With EMBER 2018 (full dataset)
```bash
wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xvf ember_dataset_2018_2.tar.bz2
python train_model.py --ember /path/to/ember_dataset_2018_2 --limit 100000
```

The training script produces a detailed evaluation report:
- Accuracy, Precision, Recall, F1, ROC-AUC
- Confusion matrix
- Top feature importances

---

## 🛠️ Project Structure

```
WinPE-ScanML/
│
├── malware_detector.py        # Main GUI application
├── demo_model_generator.py    # Generates demo model (synthetic data)
├── train_model.py             # Full training script (EMBER/Excel/CSV)
├── requirements.txt
├── setup.ps1
│
├── model_artifacts/           # ML model files (generated at setup)
│   ├── model.pkl
│   ├── scaler.pkl
│   ├── features_columns.pkl
│   └── feature_info.txt
│
├── data/
│   ├── sample_database.csv.xlsx
│   └── jsonl_to_excel.py
│
├── scan_history.json          # Auto-created on first scan
├── settings.json              # Auto-created on save in Settings
└── README.md
```

---

## 🔬 Features Extracted from PE Files

| Category | Features |
|---|---|
| **File** | FileSize, FileEntropy |
| **PE Header** | SizeOfOptionalHeader, Characteristics, LinkerVersion, Subsystem, TimeDateStamp |
| **Code** | SizeOfCode, AddressOfEntryPoint, BaseOfCode, ImageBase |
| **Data** | SizeOfInitializedData, SizeOfUninitializedData, SizeOfImage, SizeOfHeaders |
| **Sections** | NumberOfSections, AvgSectionEntropy, MaxSectionEntropy, AvgVsizeRatio |
| **Imports** | NumberOfImports, NumberOfImportDLLs, SuspiciousImports |
| **Exports** | NumberOfExports |
| **Security** | HasASLR, HasDEP, HasSEH, HasCFG |
| **Resources** | NumberOfResources |

---

## ✨ Customization

- **Detection threshold**: Adjust in **Settings** page (default 0.50)
- **Theme**: Switch between Dark/Light in Settings
- **Model**: Replace `.pkl` files with your own trained model
- **Suspicious imports list**: Edit `SUSPICIOUS` set in `malware_detector.py`

---

## ⚠️ Disclaimer

This tool is intended for **educational and research purposes only**. Always follow applicable laws when analyzing files. The demo model is trained on synthetic data and is not suitable for production security use. Retrain with EMBER 2018 for real-world accuracy.
