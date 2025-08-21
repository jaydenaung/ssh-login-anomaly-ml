# SSH Login Anomaly Detector
# Jayden Aung (MSc in Cyber Security)
#!/usr/bin/env python3
import argparse, os, re, json, math, datetime as dt
from typing import Iterator, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# ------- Parsing -------

SSH_PATTERNS = [
    # Accepted/Failed password (Ubuntu/Debian style)
    re.compile(
        r'(?P<ts>^\w{3}\s+\d+\s[\d:]+)\s[\w\-\d]+ sshd\[\d+\]: '
        r'(?P<action>Accepted|Failed) password for (?:(?:invalid user )?)(?P<user>[\w\-\.\$]+) '
        r'from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
    ),
    # Accepted publickey
    re.compile(
        r'(?P<ts>^\w{3}\s+\d+\s[\d:]+)\s[\w\-\d]+ sshd\[\d+\]: '
        r'Accepted publickey for (?P<user>[\w\-\.\$]+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
    ),
    # Failed publickey
    re.compile(
        r'(?P<ts>^\w{3}\s+\d+\s[\d:]+)\s[\w\-\d]+ sshd\[\d+\]: '
        r'Failed publickey for (?:(?:invalid user )?)(?P<user>[\w\-\.\$]+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
    ),
]

def parse_syslog_timestamp(s: str) -> dt.datetime:
    # Syslog lacks year → assume current year (good enough for lab/portfolio)
    return dt.datetime.strptime(f"{dt.datetime.now().year} {s}", "%Y %b %d %H:%M:%S")

def iter_events(lines: Iterator[str]) -> Iterator[Dict]:
    for line in lines:
        for pat in SSH_PATTERNS:
            m = pat.search(line)
            if m:
                gd = m.groupdict()
                ts = parse_syslog_timestamp(gd["ts"])
                yield {
                    "ts": ts.isoformat(timespec="seconds"),
                    "action": gd.get("action") or ("Accepted" if "Accepted" in line else "Failed"),
                    "user": gd.get("user") or "",
                    "ip": gd.get("ip") or "",
                    "port": int(gd.get("port") or 0),
                    "raw": line.rstrip(),
                }
                break

def load_events_from_file(path: str) -> List[Dict]:
    with open(path, "r", errors="ignore") as f:
        return list(iter_events(f))

# ------- Features -------

def add_time_features(df: pd.DataFrame) -> pd.DataFrame:
    df["dt"] = pd.to_datetime(df["ts"])
    df["hour"] = df["dt"].dt.hour
    df["dow"] = df["dt"].dt.dayofweek
    df["hour_sin"] = df["hour"].apply(lambda h: math.sin(2 * math.pi * h / 24.0))
    df["hour_cos"] = df["hour"].apply(lambda h: math.cos(2 * math.pi * h / 24.0))
    return df

def add_rarity_counts(df: pd.DataFrame) -> pd.DataFrame:
    seen_user_ip = set()
    is_new = []
    ip_seen = {}
    ip_seen_count = []
    user_seen = {}
    user_seen_count = []

    for _, r in df.iterrows():
        key = (r["user"], r["ip"])
        is_new.append(0 if key in seen_user_ip else 1)
        seen_user_ip.add(key)

        ip_seen[r["ip"]] = ip_seen.get(r["ip"], 0) + 1
        ip_seen_count.append(ip_seen[r["ip"]])

        user_seen[r["user"]] = user_seen.get(r["user"], 0) + 1
        user_seen_count.append(user_seen[r["user"]])

    df["is_new_user_ip"] = is_new
    df["ip_seen_count"] = ip_seen_count
    df["user_seen_count"] = user_seen_count
    return df

def build_feature_frame(events: List[Dict]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    if not events:
        raise ValueError("No SSH events parsed. Check your log format or file path.")
    df = pd.DataFrame(events)
    df = add_time_features(df)
    df = add_rarity_counts(df)
    df["is_success"] = (df["action"].str.contains("Accepted")).astype(int)
    # Minimal, robust feature set
    feat_cols = ["hour_sin","hour_cos","dow","is_new_user_ip","ip_seen_count","user_seen_count","is_success"]
    X = df[feat_cols].astype(float)
    return df, X

# ------- Model -------

def train_isolation_forest(X: pd.DataFrame) -> IsolationForest:
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    return model

def save_model(model, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)

def load_model(path: str):
    return joblib.load(path)

# ------- Scoring -------

def score_events(model_path: str, events: List[Dict], out_path: str, quantile: float = 0.97) -> Dict:
    model = load_model(model_path)
    df, X = build_feature_frame(events)
    # decision_function: higher = more normal → invert for "anomaly_score"
    normal_score = model.decision_function(X)
    df["anomaly_score"] = -normal_score
    cutoff = float(np.quantile(df["anomaly_score"].values, quantile))
    df["is_anomaly"] = (df["anomaly_score"] >= cutoff).astype(int)

    anomalies = df[df["is_anomaly"] == 1].copy()
    # Select useful fields for triage
    out_records = anomalies[["ts","user","ip","port","action","anomaly_score","raw"]] \
        .sort_values("anomaly_score", ascending=False) \
        .to_dict(orient="records")

    with open(out_path, "w") as f:
        json.dump(out_records, f, indent=2)

    return {
        "total_events": int(len(df)),
        "flagged": int(len(out_records)),
        "cutoff": cutoff,
        "out_file": out_path
    }

# ------- CLI -------

def main():
    ap = argparse.ArgumentParser(description="SSH Login Anomaly Detector (IsolationForest)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="Train baseline model on a log file")
    p_train.add_argument("--in", dest="infile", required=True, help="Path to auth.log/secure dump")
    p_train.add_argument("--model", default="models/ssh_isoforest.pkl", help="Path to save model")

    p_detect = sub.add_parser("detect", help="Score a log file and output anomalies")
    p_detect.add_argument("--in", dest="infile", required=True, help="Path to log to score")
    p_detect.add_argument("--model", default="models/ssh_isoforest.pkl", help="Path to trained model")
    p_detect.add_argument("--out", default="findings.json", help="Path to write anomalies JSON")
    p_detect.add_argument("--q", type=float, default=0.97, help="Quantile threshold (0-1), default 0.97")

    p_peek = sub.add_parser("peek", help="Parse a file and show parsed rows (debug)")
    p_peek.add_argument("--in", dest="infile", required=True)

    args = ap.parse_args()

    if args.cmd == "train":
        events = load_events_from_file(args.infile)
        df, X = build_feature_frame(events)
        model = train_isolation_forest(X)
        save_model(model, args.model)
        print(f"[train] parsed={len(df)} events → saved model: {args.model}")

    elif args.cmd == "detect":
        events = load_events_from_file(args.infile)
        result = score_events(args.model, events, args.out, quantile=args.q)
        print(f"[detect] total={result['total_events']} flagged={result['flagged']} "
              f"cutoff={result['cutoff']:.4f} → {result['out_file']}")

    elif args.cmd == "peek":
        events = load_events_from_file(args.infile)
        for r in events[:20]:
            print(r)
        print(f"[peek] shown {min(20, len(events))}/{len(events)} parsed rows")

if __name__ == "__main__":
    main()
