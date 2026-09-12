"""
dashboard/analyzer.py
AI Firewall — Analysis pipeline.

Called by the dashboard after packet capture stops.
Runs the full pipeline:
    Raw packets
        -> Flow aggregation       (flow_tracker.build_flows)
        -> Feature preparation    (pandas DataFrame)
        -> RF model prediction    (ai/firewall_model.pkl)
        -> Behavioural risk score (detection.risk_engine)
        -> Firewall decision      (detection.decision_engine)
        -> Structured results     (returned as dict)
        -> Write events file      (data/security_events.jsonl)
"""

import json
import os
import sys
import traceback
from collections import defaultdict
from datetime import datetime

import joblib
import pandas as pd

# Ensure the project root is on sys.path so we can import sibling packages
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from detection.flow_tracker  import build_flows
from detection.risk_engine   import RiskEngine
from detection.decision_engine import DecisionEngine

# ── paths (relative to project root / CWD) ────────────────────────────────────
MODEL_PATH   = "ai/firewall_model.pkl"
DATASET_PATH = "data/network_flows.csv"
PACKET_LOG   = "logs/security.jsonl"
FLOWS_FILE   = "data/flows.jsonl"
EVENTS_FILE  = "data/security_events.jsonl"

FEATURES = [
    "duration",
    "packet_count",
    "total_bytes",
    "min_packet_size",
    "max_packet_size",
    "average_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
]


# ── model helpers ──────────────────────────────────────────────────────────────

def _get_model():
    """Load the trained RF model, or train + save it on first run."""
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Model not found at '{MODEL_PATH}' and training dataset "
            f"not found at '{DATASET_PATH}'. "
            f"Run  python ai/train_model.py  first."
        )

    # Auto-train on first analysis
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split

    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=FEATURES + ["label"])
    X  = df[FEATURES]
    y  = df["label"]
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.3, random_state=42)

    model = RandomForestClassifier(
        n_estimators=100, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model


# ── packet-log helpers ─────────────────────────────────────────────────────────

def _count_lines(path: str) -> int:
    """Count non-empty lines efficiently (no JSON parsing)."""
    if not os.path.exists(path):
        return 0
    count = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            count += chunk.count(b"\n")
    return count


def _capture_timestamps(path: str):
    """Return (first_ts, last_ts) as datetime objects from the packet log."""
    if not os.path.exists(path):
        return None, None

    FMT = "%Y-%m-%d %H:%M:%S.%f"
    first_ts = last_ts = None

    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ts_str = json.loads(line).get("timestamp", "")
                ts     = datetime.strptime(ts_str, FMT)
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
            except (json.JSONDecodeError, ValueError):
                continue

    return first_ts, last_ts


# ── attack-type heuristics ─────────────────────────────────────────────────────

def _classify_attack(flow: dict, rf_prediction: int, risk_score: float) -> str:
    """Map flow statistics to a human-readable attack-type label."""
    if rf_prediction == 0 and risk_score < 0.40:
        return "Normal"

    syn  = flow.get("syn_count", 0)
    rst  = flow.get("rst_count", 0)
    pps  = flow.get("packets_per_second", 0)
    pkts = flow.get("packet_count", 0)

    if syn >= 20 and pps >= 20:
        return "SYN Flood"
    if syn >= 10 and pkts > 0 and (syn / pkts) > 0.5:
        return "TCP Port Scan"
    if rst >= 15:
        return "RST Attack"
    if pps >= 100:
        return "High-Rate Traffic"
    if rf_prediction == 1:
        return "Network Attack"
    return "Suspicious Flow"


# ── main pipeline ──────────────────────────────────────────────────────────────

def run_analysis(packet_log_path: str = PACKET_LOG) -> dict:
    """
    Execute the full analysis pipeline.

    Returns
    -------
    dict with keys:
        error            : str or None
        total_packets    : int
        total_flows      : int
        total_bytes      : int
        capture_duration : float  (seconds)
        avg_pps          : float
        normal_count     : int
        suspicious_count : int   (MONITOR decisions)
        malicious_count  : int   (BLOCK decisions)
        overall_risk_score : float  0.0-1.0
        overall_risk_label : str  LOW | MEDIUM | HIGH | CRITICAL
        events           : list[dict]
        blocked_ips      : list[str]
        monitored_ips    : list[str]
        source_ip_stats  : list[dict]
    """
    result = {
        "error":              None,
        "total_packets":      0,
        "total_flows":        0,
        "total_bytes":        0,
        "capture_duration":   0.0,
        "avg_pps":            0.0,
        "normal_count":       0,
        "suspicious_count":   0,
        "malicious_count":    0,
        "overall_risk_score": 0.0,
        "overall_risk_label": "LOW",
        "events":             [],
        "blocked_ips":        [],
        "monitored_ips":      [],
        "source_ip_stats":    [],
    }

    try:
        # ── 1. Quick packet count ──────────────────────────────────────────────
        result["total_packets"] = _count_lines(packet_log_path)
        if result["total_packets"] == 0:
            result["error"] = (
                "No packets found in the log file.  "
                "Start packet capture, capture some traffic, then stop and analyze."
            )
            return result

        # ── 2. Capture duration ────────────────────────────────────────────────
        first_ts, last_ts = _capture_timestamps(packet_log_path)
        if first_ts and last_ts:
            result["capture_duration"] = (last_ts - first_ts).total_seconds()
        if result["capture_duration"] > 0:
            result["avg_pps"] = result["total_packets"] / result["capture_duration"]

        # ── 3. Build flows ─────────────────────────────────────────────────────
        flows = build_flows(packet_log_path)
        result["total_flows"] = len(flows)
        result["total_bytes"] = sum(f.get("total_bytes", 0) for f in flows)

        if not flows:
            result["error"] = (
                "Could not extract any network flows from the captured packets.  "
                "Capture traffic for at least a few seconds before analyzing."
            )
            return result

        # Write flows file for offline compatibility
        os.makedirs(os.path.dirname(FLOWS_FILE), exist_ok=True)
        with open(FLOWS_FILE, "w", encoding="utf-8") as fh:
            for flow in flows:
                # Remove non-JSON-serialisable keys before writing
                safe = {k: v for k, v in flow.items() if not isinstance(v, set)}
                fh.write(json.dumps(safe) + "\n")

        # ── 4. Load model ──────────────────────────────────────────────────────
        model = _get_model()

        # ── 5. Predict + risk + decision per flow ─────────────────────────────
        risk_engine     = RiskEngine()
        decision_engine = DecisionEngine()
        events          = []
        src_ip_data     = defaultdict(lambda: {
            "packet_count": 0,
            "syn_count":    0,
            "flows":        0,
            "max_risk":     0.0,
            "worst_decision": "ALLOW",
            "ports":        set(),
        })

        for flow in flows:
            # Build feature vector
            feature_vec = {feat: float(flow.get(feat, 0) or 0) for feat in FEATURES}
            X = pd.DataFrame([feature_vec])

            # Model is trained with binary labels (0 = benign, 1 = attack)
            rf_pred = int(model.predict(X)[0])
            if hasattr(model, "predict_proba"):
                rf_conf = float(max(model.predict_proba(X)[0]))
            else:
                rf_conf = 1.0 if rf_pred == 1 else 0.0


            # Behavioural risk
            risk_score = risk_engine.calculate_risk(
                syn_count=int(flow.get("syn_count", 0)),
                unique_ports=1,          # flow_tracker doesn't track unique ports
                packets_per_second=float(flow.get("packets_per_second", 0) or 0),
                rst_count=int(flow.get("rst_count", 0)),
            )

            decision    = decision_engine.decide(rf_pred, risk_score)
            attack_type = _classify_attack(flow, rf_pred, risk_score)

            if decision == "BLOCK":
                result["malicious_count"] += 1
            elif decision == "MONITOR":
                result["suspicious_count"] += 1
            else:
                result["normal_count"] += 1

            event = {
                "timestamp":       flow.get("start_time", ""),
                "source_ip":       flow.get("source_ip", ""),
                "destination_ip":  flow.get("destination_ip", ""),
                "source_port":     flow.get("source_port"),
                "destination_port": flow.get("destination_port"),
                "protocol":        flow.get("protocol", ""),
                "packet_count":    flow.get("packet_count", 0),
                "total_bytes":     flow.get("total_bytes", 0),
                "duration":        round(flow.get("duration", 0), 3),
                "syn_count":       flow.get("syn_count", 0),
                "packets_per_second": round(flow.get("packets_per_second", 0), 2),
                "risk_score":      round(risk_score, 3),
                "rf_prediction":   rf_pred,
                "rf_confidence":   round(rf_conf, 3),
                "attack_type":     attack_type,
                "decision":        decision,
            }
            events.append(event)

            # Per-source-IP aggregation
            src = flow.get("source_ip", "")
            d   = src_ip_data[src]
            d["packet_count"] += flow.get("packet_count", 0)
            d["syn_count"]    += flow.get("syn_count", 0)
            d["flows"]        += 1
            d["max_risk"]      = max(d["max_risk"], risk_score)
            dport = flow.get("destination_port")
            if dport:
                d["ports"].add(dport)
            # Track worst decision
            if decision == "BLOCK":
                d["worst_decision"] = "BLOCK"
            elif decision == "MONITOR" and d["worst_decision"] != "BLOCK":
                d["worst_decision"] = "MONITOR"

        result["events"] = events

        # ── 6. Overall risk ────────────────────────────────────────────────────
        total_flows = result["total_flows"]
        if total_flows > 0 and events:
            mal_ratio = result["malicious_count"] / total_flows
            sus_ratio = result["suspicious_count"] / total_flows
            max_risk  = max(e["risk_score"] for e in events)
            score     = round(0.50 * mal_ratio + 0.30 * sus_ratio + 0.20 * max_risk, 3)
            result["overall_risk_score"] = score

            if score >= 0.60 or mal_ratio >= 0.20:
                result["overall_risk_label"] = "CRITICAL"
            elif score >= 0.35 or mal_ratio >= 0.05:
                result["overall_risk_label"] = "HIGH"
            elif score >= 0.15:
                result["overall_risk_label"] = "MEDIUM"
            else:
                result["overall_risk_label"] = "LOW"

        # ── 7. Blocked / monitored IPs ─────────────────────────────────────────
        result["blocked_ips"]   = sorted(set(
            e["source_ip"] for e in events if e["decision"] == "BLOCK"
        ))
        result["monitored_ips"] = sorted(set(
            e["source_ip"] for e in events if e["decision"] == "MONITOR"
        ))

        # ── 8. Per-source-IP stats ─────────────────────────────────────────────
        src_stats = []
        for ip, d in src_ip_data.items():
            src_stats.append({
                "ip":           ip,
                "packet_count": d["packet_count"],
                "syn_count":    d["syn_count"],
                "flows":        d["flows"],
                "unique_ports": len(d["ports"]),
                "risk_score":   round(d["max_risk"], 3),
                "status":       d["worst_decision"],
            })
        src_stats.sort(key=lambda x: x["risk_score"], reverse=True)
        result["source_ip_stats"] = src_stats[:25]

        # ── 9. Write events file ───────────────────────────────────────────────
        os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
        with open(EVENTS_FILE, "w", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event) + "\n")

    except Exception:
        result["error"] = traceback.format_exc()

    return result
