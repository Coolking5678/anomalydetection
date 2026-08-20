"""
src/explainer.py
----------------
Produces human-readable explanations for why a particular log entry was
flagged as anomalous by the Isolation Forest model.

Each anomalous row receives a ranked list of contributing reason strings
derived from its feature values vs. the dataset-level baselines.
"""

import logging
from typing import List

# pyrefly: ignore [missing-import]
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds / labels used when generating reason strings
# ---------------------------------------------------------------------------

_NIGHT_HOURS = set(range(0, 6)) | set(range(23, 24))
_HIGH_FAIL_THRESHOLD = 3       # rolling 5-min failures considered high
_HIGH_IP_FREQ_PERCENTILE = 90  # top-N% IP frequency treated as suspicious


def _reason_night_access(row: pd.Series) -> str | None:
    """Flag off-hours login attempts."""
    if row.get("is_night_access", 0) == 1:
        return f"Off-hours access at {int(row['hour']):02d}:00"
    return None


def _reason_high_failure_rate(row: pd.Series, threshold: float) -> str | None:
    """Flag high rolling failure count within 5 minutes."""
    val = row.get("rolling_fail_5m", 0)
    if val >= threshold:
        return f"High failure rate: {int(val)} failed attempts in 5 min"
    return None


def _reason_admin_target(row: pd.Series) -> str | None:
    """Flag attempts against privileged accounts."""
    if row.get("is_admin_target", 0) == 1:
        user = row.get("username", "unknown")
        return f"Privileged account targeted: '{user}'"
    return None


def _reason_rare_ip(row: pd.Series, low_freq_threshold: float) -> str | None:
    """Flag source IPs that appear very rarely in the dataset."""
    freq = row.get("ip_freq", 0.0)
    ip = row.get("source_ip", "")
    if ip and freq <= low_freq_threshold and freq > 0:
        return f"Rare source IP '{ip}' (freq={freq:.4f})"
    return None


def _reason_event_type(row: pd.Series) -> str | None:
    """Flag inherently suspicious event types."""
    etype = row.get("event_type", "")
    if etype in ("FAILED_LOGIN", "INVALID_USER"):
        return f"Suspicious event: {etype.replace('_', ' ').title()}"
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def explain_anomalies(
    enriched_df: pd.DataFrame,
    is_anomaly: pd.Series,
) -> pd.Series:
    """
    Generate a concise explanation string for every row in *enriched_df*.

    For anomalous rows the explanation lists the top contributing signals
    (separated by  "  |  ").  Normal rows receive an empty string.

    Parameters
    ----------
    enriched_df : Feature-enriched DataFrame from ``features.build_features``.
    is_anomaly  : Boolean Series of the same length (True = anomaly).

    Returns
    -------
    pd.Series of str – one explanation per row, aligned to ``enriched_df``.
    """
    if len(enriched_df) != len(is_anomaly):
        raise ValueError(
            "enriched_df and is_anomaly must have the same number of rows."
        )

    # Compute dataset-level baselines for adaptive thresholds
    fail_p75 = enriched_df["rolling_fail_5m"].quantile(0.75)
    high_fail_thresh = max(fail_p75, _HIGH_FAIL_THRESHOLD)

    freq_low_thresh = enriched_df["ip_freq"].quantile(
        1.0 - _HIGH_IP_FREQ_PERCENTILE / 100.0
    )

    explanations: List[str] = []

    for idx, row in enriched_df.iterrows():
        if not is_anomaly.iloc[idx] if isinstance(idx, int) else not is_anomaly[idx]:
            explanations.append("")
            continue

        reasons: List[str] = []

        r = _reason_high_failure_rate(row, high_fail_thresh)
        if r:
            reasons.append(r)

        r = _reason_admin_target(row)
        if r:
            reasons.append(r)

        r = _reason_night_access(row)
        if r:
            reasons.append(r)

        r = _reason_event_type(row)
        if r:
            reasons.append(r)

        r = _reason_rare_ip(row, freq_low_thresh)
        if r:
            reasons.append(r)

        explanations.append("  |  ".join(reasons) if reasons else "Anomalous pattern")

    result = pd.Series(explanations, index=enriched_df.index)
    n_explained = (result != "").sum()
    logger.info("Generated explanations for %d anomalous entries.", n_explained)
    return result
