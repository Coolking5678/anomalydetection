"""
run_cli.py
----------
Headless terminal runner for the anomaly detection pipeline.
No GUI needed. Just:  py run_cli.py

Optional flags:
  --contamination 0.05   (default: 0.05)
  --export               save threats to threats.csv
  --metrics              print precision/recall estimates
"""

import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.WARNING,          # keep it quiet by default
    format="%(levelname)s: %(message)s",
)

from src.ingestion import download_log, parse_log_file
from src.features import build_features, FAILURE_EVENTS
from src.model import AnomalyDetector
from src.explainer import explain_anomalies


def run(contamination: float, export: bool, metrics: bool) -> None:
    # ── 1. Load data ────────────────────────────────────────────────────────
    print("\n[1/4] Loading log file...")
    dest = download_log()
    df = parse_log_file(dest)
    print(f"      {len(df):,} entries parsed from '{dest.name}'")

    # ── 2. Features ──────────────────────────────────────────────────────────
    print("[2/4] Engineering features...")
    enriched, X = build_features(df)

    # ── 3. Detect ────────────────────────────────────────────────────────────
    print(f"[3/4] Running Isolation Forest (contamination={contamination:.0%})...")
    detector = AnomalyDetector(contamination=contamination)
    is_anomaly = detector.train_and_predict(X)
    scores = detector.anomaly_scores(X)

    enriched["is_anomaly"] = is_anomaly.values
    enriched["anomaly_score"] = scores
    reasons = explain_anomalies(enriched, is_anomaly)
    enriched["reason"] = reasons.values

    # ── 4. Results ───────────────────────────────────────────────────────────
    print("[4/4] Results\n")
    threats = enriched[enriched["is_anomaly"]]
    normal  = enriched[~enriched["is_anomaly"]]

    n_total    = len(enriched)
    n_threats  = len(threats)
    n_normal   = len(normal)
    n_ips      = threats["source_ip"].nunique()

    print("=" * 60)
    print(f"  Total log entries      : {n_total:,}")
    print(f"  Anomalies flagged      : {n_threats:,}  ({n_threats/n_total:.1%})")
    print(f"  Normal entries         : {n_normal:,}  ({n_normal/n_total:.1%})")
    print(f"  Unique attacker IPs    : {n_ips}")
    print("=" * 60)

    # Event type breakdown inside threats
    print("\n  Threat breakdown by event type:")
    for etype, count in threats["event_type"].value_counts().items():
        print(f"    {etype:<20} {count:>5}  ({count/n_threats:.0%})")

    # Top attacker IPs
    print("\n  Top 5 attacker IPs:")
    top_ips = (
        threats.groupby("source_ip")["is_anomaly"]
        .count()
        .nlargest(5)
    )
    for ip, count in top_ips.items():
        print(f"    {ip:<20} {count:>4} flagged events")

    # Sample threat rows
    print("\n  Sample flagged entries:")
    cols = ["timestamp", "source_ip", "username", "event_type", "rolling_fail_5m", "reason"]
    print(threats[cols].head(8).to_string(index=False))

    # ── Optional: pseudo-metrics ─────────────────────────────────────────────
    if metrics:
        _print_metrics(enriched, threats)

    # ── Optional: export ─────────────────────────────────────────────────────
    if export:
        out_path = Path("threats.csv")
        threats.to_csv(out_path, index=False)
        print(f"\n  Threats saved to: {out_path.resolve()}")

    print()


def _print_metrics(enriched, threats):
    """
    Since this dataset has no ground-truth labels, we create pseudo-labels
    using a conservative rule: any source_ip responsible for >= 10 failed
    attempts in the dataset is considered a 'known attacker'.
    This lets us compute proxy precision/recall figures.
    """
    FAIL_THRESHOLD = 10

    # Build pseudo-labels
    ip_fail_counts = (
        enriched[enriched["event_type"].isin({"FAILED_LOGIN", "INVALID_USER"})]
        .groupby("source_ip")
        .size()
    )
    known_attacker_ips = set(ip_fail_counts[ip_fail_counts >= FAIL_THRESHOLD].index)

    enriched["pseudo_label"] = enriched["source_ip"].isin(known_attacker_ips)

    TP = int(( enriched["is_anomaly"] &  enriched["pseudo_label"]).sum())
    FP = int(( enriched["is_anomaly"] & ~enriched["pseudo_label"]).sum())
    FN = int((~enriched["is_anomaly"] &  enriched["pseudo_label"]).sum())
    TN = int((~enriched["is_anomaly"] & ~enriched["pseudo_label"]).sum())

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall    = TP / (TP + FN) if (TP + FN) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr       = FP / (FP + TN) if (FP + TN) else 0

    print("\n" + "=" * 60)
    print(f"  PSEUDO-METRICS (attacker IP = >=10 failures in dataset)")
    print("=" * 60)
    print(f"  Known attacker IPs      : {len(known_attacker_ips)}")
    print(f"  True  Positives  (TP)   : {TP:>5}  (attack flagged correctly)")
    print(f"  False Positives  (FP)   : {FP:>5}  (normal traffic flagged)")
    print(f"  False Negatives  (FN)   : {FN:>5}  (attack missed)")
    print(f"  True  Negatives  (TN)   : {TN:>5}  (normal, correctly ignored)")
    print(f"  ---")
    print(f"  Precision               : {precision:.1%}")
    print(f"  Recall                  : {recall:.1%}")
    print(f"  F1 Score                : {f1:.3f}")
    print(f"  False Positive Rate     : {fpr:.1%}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI Security Log Anomaly Detector — CLI mode"
    )
    parser.add_argument(
        "--contamination", type=float, default=0.05,
        help="Fraction of data expected to be anomalous (default: 0.05)"
    )
    parser.add_argument(
        "--export", action="store_true",
        help="Export flagged threats to threats.csv"
    )
    parser.add_argument(
        "--metrics", action="store_true",
        help="Print pseudo precision/recall metrics"
    )
    args = parser.parse_args()
    run(args.contamination, args.export, args.metrics)
