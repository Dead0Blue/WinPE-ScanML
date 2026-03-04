# WinPE-ScanML Setup Script
# Run in PowerShell: .\setup.ps1

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║        WinPE-ScanML — Setup              ║" -ForegroundColor Cyan
Write-Host "  ║   Advanced PE Malware Detector v2.0      ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Check Python ──────────────────────────────
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Python not found. Install Python 3.8+ from https://python.org" -ForegroundColor Red
    exit 1
}
Write-Host "[✓] Found: $pythonVersion" -ForegroundColor Green

# ── Install dependencies ──────────────────────
Write-Host ""
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[!] Some packages may have failed. Trying individual installs..." -ForegroundColor Yellow
    pip install pandas numpy scikit-learn joblib pefile pillow tqdm
    # tkinterdnd2 can be tricky — try wheel first
    python -m pip install tkinterdnd2 --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] tkinterdnd2 install failed — drag-and-drop will be disabled (click still works)." -ForegroundColor Yellow
    } else {
        Write-Host "[✓] tkinterdnd2 installed — drag-and-drop enabled." -ForegroundColor Green
    }
}

# ── Create directories ────────────────────────
Write-Host ""
Write-Host "[*] Setting up directory structure..." -ForegroundColor Yellow

$dirs = @("model_artifacts", "data")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "[✓] Created: $dir" -ForegroundColor Green
    } else {
        Write-Host "[✓] Exists:  $dir" -ForegroundColor Green
    }
}

# ── Generate demo model ───────────────────────
$modelExists = (Test-Path "model_artifacts\model.pkl") -or (Test-Path "model_artifacts\modele_regression_logistique.pkl")

if (-not $modelExists) {
    Write-Host ""
    Write-Host "[*] No model found. Generating demo model from synthetic data..." -ForegroundColor Yellow
    Write-Host "    (This may take 30-60 seconds)" -ForegroundColor DarkGray
    python demo_model_generator.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[✓] Demo model generated successfully!" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to generate demo model. Check Python dependencies." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[✓] Model files already exist — skipping generation." -ForegroundColor Green
}

# ── Done ──────────────────────────────────────
Write-Host ""
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Setup complete! Launch the app with:" -ForegroundColor White
Write-Host ""
Write-Host "    python malware_detector.py" -ForegroundColor Green
Write-Host ""
Write-Host "  To retrain with your own data:" -ForegroundColor White
Write-Host "    python train_model.py --data data/your_dataset.xlsx" -ForegroundColor DarkGray
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
