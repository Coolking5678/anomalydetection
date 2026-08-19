"""
src/features.py
---------------
Feature engineering pipeline that transforms the raw parsed SSH-log DataFrame
into a numerical matrix suitable for Isolation Forest anomaly detection.

Features produced
-----------------
hour               int   – Hour of the event (0-23)
is_night_access    int   – 1 if hour < 6 or hour > 22
rolling_fail_5m    float – Count of FAILED/INVALID events per source_ip
                           in the preceding 5-minute rolling window
is_admin_target    int   – 1 if username is a high-value target account
ip_freq            float – Frequency-encoded source_ip (proportion of rows)
"""

import logging
from typing import Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

ADMIN_TARGETS = {"root", "admin", "test", "administrator", "ubuntu", "ec2-user"}
FAILURE_EVENTS = {"FAILED_LOGIN", "INVALID_USER"}
ROLLING_WINDOW = "5min"   # pandas-compatible offset string


# ---------------------------------------------------------------------------
# Individual feature constructors
# ---------------------------------------------------------------------------

def _temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add *hour* and *is_night_access* columns in-place and return df."""
    df["hour"] = df["timestamp"].dt.hour
    df["is_night_access"] = (
        (df["hour"] < 6) | (df["hour"] > 22)
    ).astype(int)
    return df


def _rolling_failure_count(df: pd.DataFrame) -> pd.DataFrame:
    """
    For each row, compute the number of FAILED_LOGIN / INVALID_USER events
    originating from the *same* source_ip within the preceding 5-minute window.

    The DataFrame must be sorted by timestamp before this is called.
    """
    # Binary flag: 1 for failure events, 0 otherwise
    is_failure = df["event_type"].isin(FAILURE_EVENTS).astype(float)
    df["is_failure_flag"] = is_failure

    rolling_counts = []

    for ip, group in df.groupby("source_ip", sort=False):
        if ip == "":
            # No IP available – assign a neutral count of 0
            rolling_counts.append(
                pd.Series(0.0, index=group.index, name="rolling_fail_5m")
            )
            continue

        # Set timestamp as index for time-based rolling
        ts_series = group.set_index("timestamp")["is_failure_flag"]

        # Rolling sum over the preceding 5 minutes (min_periods=1)
        rolled = (
            ts_series
            .rolling(ROLLING_WINDOW, min_periods=1)
            .sum()
            .reset_index(drop=True)
        )
        rolled.index = group.index
        rolled.name = "rolling_fail_5m"
        rolling_counts.append(rolled)

    df["rolling_fail_5m"] = pd.concat(rolling_counts).sort_index()
    df.drop(columns=["is_failure_flag"], inplace=True)
    return df


def _admin_target_flag(df: pd.DataFrame) -> pd.DataFrame:
    """Add *is_admin_target* column: 1 if username is a privileged account."""
    df["is_admin_target"] = (
        df["username"].str.lower().isin(ADMIN_TARGETS)
    ).astype(int)
    return df


def _ip_frequency_encoding(df: pd.DataFrame) -> pd.DataFrame:
    """
    Frequency-encode *source_ip* as the proportion of rows it occupies.
    Unknown / empty IPs receive a frequency of 0.
    """
    freq_map = df["source_ip"].value_counts(normalize=True)
    df["ip_freq"] = df["source_ip"].map(freq_map).fillna(0.0)
    return df


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_features(raw_df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Transform the raw parsed log DataFrame into ML-ready features.

    Parameters
    ----------
    raw_df : Output of ``ingestion.parse_log_file``.

    Returns
    -------
    enriched_df : The original DataFrame augmented with feature columns.
    X           : numpy float64 matrix of shape (n_rows, n_features).
                  Column order: [hour, is_night_access, rolling_fail_5m,
                                 is_admin_target, ip_freq]
    """
    if raw_df.empty:
        raise ValueError("Cannot build features from an empty DataFrame.")

    df = raw_df.copy()

    # Ensure chronological order for rolling window correctness
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    # Apply feature constructors
    df = _temporal_features(df)
    df = _rolling_failure_count(df)
    df = _admin_target_flag(df)
    df = _ip_frequency_encoding(df)

    feature_cols = [
        "hour",
        "is_night_access",
        "rolling_fail_5m",
        "is_admin_target",
        "ip_freq",
    ]

    X = df[feature_cols].values.astype(np.float64)

    logger.info(
        "Feature matrix built: %d rows × %d features.", X.shape[0], X.shape[1]
    )
    return df, X
