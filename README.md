# SSH Login Anomaly Detector
## Unsupervised - IsolationForest
## Jayden Aung - MSc in Cyber Security

Detect suspicious and abnormal SSH logins from Linux `auth.log` / `secure` (or `journald`) using an unsupervised ML approach (**IsolationForest**).  
This repo is designed to be **copy‑run‑demo** friendly.

![status](https://img.shields.io/badge/status-MVP-brightgreen) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![ml](https://img.shields.io/badge/ML-IsolationForest-orange)

---

## ✨ What it does

- Parses SSH auth events (Accepted/Failed password, publickey)
- Builds explainable features (time-of-day, day-of-week, rarity of `user@ip`, frequency counts, success/fail)
- Trains a **baseline model** on your “normal period”
- Scores new logs and outputs **ranked anomalies** to `findings.json`

---

## 🧠 What this aims to do

- Shows **ML-driven security though process**: clean data pipeline → explainable features → unsupervised detection → simple triage output
- Demonstrates **hands-on ML** in a real security problem 
- Clear extensibility: GeoIP/ASN novelty, “impossible travel,” Slack alerts, SIEM export

---

## 🔧 Quickstart

### 1) Clone & set up

```bash
git clone https://github.com/jaydenaung/ssh-login-anomaly-ml.git
cd ssh-login-anomaly-ml

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Demo
```bash
python ssh_anomaly.py peek --in sample_auth.log
``` 

### 3) Train a baseline model
Use a timeframe representative of normal behavior.
```bash
# Example (Ubuntu/Debian via journald)
sudo journalctl -u ssh -S "2025-08-15" -U "2025-08-20" > my_auth_train.log

python ssh_anomaly.py train --in my_auth_train.log --model models/ssh_isoforest.pkl
```

### 4) Detect anomalies on new logs

```bash
# Example: next day’s logs
sudo journalctl -u ssh -S "2025-08-20" -U "2025-08-21" > my_auth_detect.log

python ssh_anomaly.py detect --in my_auth_detect.log --model models/ssh_isoforest.pkl --out findings.json --q 0.97
cat findings.json
```
\
Tip: Adjust --q (quantile threshold) for sensitivity.
Lower (e.g., 0.95) 👉 more alerts. Higher (e.g., 0.99) 👉 fewer, more extreme anomalies.

### Repo Structure

```bash
ssh-login-anomaly-ml/
├─ ssh_anomaly.py        # CLI: train / detect / peek
├─ requirements.txt      # pandas, scikit-learn, joblib
├─ sample_auth.log       # optional demo data
├─ README.md
└─ .gitignore
```

### CLI Usage

```bash
# Parse preview (debug)
python ssh_anomaly.py peek --in <logfile>

# Train baseline model
python ssh_anomaly.py train --in <logfile> --model models/ssh_isoforest.pkl

# Detect anomalies
python ssh_anomaly.py detect --in <logfile> --model models/ssh_isoforest.pkl --out findings.json --q 0.97
```
