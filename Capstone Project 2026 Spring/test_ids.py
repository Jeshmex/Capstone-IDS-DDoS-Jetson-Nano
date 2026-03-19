# =============================================================
# test_ids.py
# Run this on the Jetson BEFORE starting the full IDS
# to verify everything is set up correctly
#
#   python3 test_ids.py
# =============================================================

import os
import sys
import numpy as np

PASS = "PASS"
FAIL = "FAIL"

results = []

def check(name, fn):
    try:
        fn()
        print(f"  [{PASS}] {name}")
        results.append(True)
    except Exception as e:
        print(f"  [{FAIL}] {name}")
        print(f"         Error: {e}")
        results.append(False)

print("")
print("=" * 50)
print("  AI DDoS IDS - System Check")
print("=" * 50)
print("")

# ── Check 1: Python version ───────────────────────────────
print("[1] Python Version")
check("Python 3.7+", lambda: (
    None if sys.version_info >= (3, 7)
    else (_ for _ in ()).throw(Exception(
        f"Need Python 3.7+, got {sys.version}"))
))
print(f"       Version: {sys.version.split()[0]}")
print("")

# ── Check 2: Imports ──────────────────────────────────────
print("[2] Required Packages")
check("flask",      __import__('flask'))
check("sklearn",    __import__('sklearn'))
check("numpy",      __import__('numpy'))
check("scapy",      __import__('scapy'))
check("joblib",     __import__('joblib'))
check("requests",   __import__('requests'))
print("")

# ── Check 3: Model files ──────────────────────────────────
print("[3] Model Files")
base  = os.path.dirname(os.path.abspath(__file__))
files = [
    'best_model.pkl',
    'scaler.pkl',
    'imputer.pkl',
    'label_encoder.pkl',
    'feature_columns.pkl',
]

for f in files:
    path = os.path.join(base, f)
    size = os.path.getsize(path) / 1024 if os.path.exists(path) else 0
    check(f"{f} ({size:.0f} KB)",
          lambda p=path: None if os.path.exists(p)
          else (_ for _ in ()).throw(Exception("File not found")))
print("")

# ── Check 4: Load models ──────────────────────────────────
print("[4] Load Models")
import joblib

model = scaler = imputer = le = feat_cols = None

def load_all():
    global model, scaler, imputer, le, feat_cols
    model     = joblib.load(os.path.join(base, 'best_model.pkl'))
    scaler    = joblib.load(os.path.join(base, 'scaler.pkl'))
    imputer   = joblib.load(os.path.join(base, 'imputer.pkl'))
    le        = joblib.load(os.path.join(base, 'label_encoder.pkl'))
    feat_cols = joblib.load(os.path.join(base, 'feature_columns.pkl'))

check("Load all pkl files", load_all)

if model is not None:
    print(f"       Model type:  {type(model).__name__}")
    print(f"       Features:    {len(feat_cols)}")
    print(f"       Classes:     {le.classes_.tolist()}")
print("")

# ── Check 5: Test prediction ──────────────────────────────
print("[5] Test Prediction")

def test_predict():
    X    = np.zeros((1, len(feat_cols)))
    X    = imputer.transform(X)
    X    = scaler.transform(X)
    pred = model.predict(X)[0]
    lbl  = le.inverse_transform([pred])[0]
    print(f"       Test output: {lbl}")
    if hasattr(model, 'predict_proba'):
        prob = model.predict_proba(X)[0]
        conf = float(prob[pred])
        print(f"       Confidence:  {conf:.2%}")

check("Run inference on dummy data", test_predict)
print("")

# ── Check 6: Network interface ────────────────────────────
print("[6] Network Interface")

def check_interfaces():
    import subprocess
    result = subprocess.run(
        ['ip', 'link', 'show'],
        capture_output=True, text=True
    )
    print("       Available interfaces:")
    for line in result.stdout.split('\n'):
        if ': ' in line and 'link' not in line.lower():
            iface = line.split(': ')[1].split(':')[0]
            print(f"         - {iface}")

check("List network interfaces", check_interfaces)
print("")

# ── Check 7: Scapy capture permission ─────────────────────
print("[7] Scapy Permissions")

def check_scapy_perms():
    if os.geteuid() != 0:
        raise Exception(
            "Not running as root. "
            "ids_engine.py must be run with sudo"
        )

check("Running as root (needed for capture)", check_scapy_perms)
print("       Note: test_ids.py itself does not need sudo")
print("       But ids_engine.py MUST be run with: sudo python3 ids_engine.py")
print("")

# ── Check 8: Dashboard reachable ──────────────────────────
print("[8] Dashboard Connection")

def check_dashboard():
    import requests as req
    resp = req.get('http://localhost:5000/', timeout=2)
    if resp.status_code != 200:
        raise Exception(f"HTTP {resp.status_code}")

try:
    check("Dashboard at http://localhost:5000", check_dashboard)
except Exception:
    print("  [INFO] Dashboard not running yet - start app.py first")
print("")

# ── Summary ───────────────────────────────────────────────
passed = sum(results)
total  = len(results)

print("=" * 50)
print(f"  Results: {passed}/{total} checks passed")
print("=" * 50)

if passed == total:
    print("")
    print("  All checks passed. Ready to run IDS.")
    print("")
    print("  Start in two terminals:")
    print("    Terminal 1:  python3 app.py")
    print("    Terminal 2:  sudo python3 ids_engine.py")
    print("")
else:
    print("")
    print("  Some checks failed. Fix the issues above")
    print("  then run this script again.")
    print("")
