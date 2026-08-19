"""
src/model.py
------------
Wraps scikit-learn's IsolationForest in a clean, re-usable class for
unsupervised anomaly detection on SSH log feature matrices.
"""

import logging
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector.

    The detector optionally applies StandardScaler before training so that
    features with different magnitudes (e.g. rolling counts vs binary flags)
    do not unfairly dominate the split selection.

    Parameters
    ----------
    contamination : float
        Expected proportion of anomalies in the dataset (0.01–0.15).
        Passed directly to IsolationForest.
    n_estimators : int
        Number of base estimators (trees) in the ensemble.
    random_state : int
        Seed for reproducibility.
    scale_features : bool
        If True, apply StandardScaler before fitting.
    """

    def __init__(
        self,
        contamination: float = 0.03,
        n_estimators: int = 200,
        random_state: int = 42,
        scale_features: bool = True,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.scale_features = scale_features

        self._scaler: Optional[StandardScaler] = None
        self._model: Optional[IsolationForest] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train_and_predict(self, X: np.ndarray) -> pd.Series:
        """
        Fit the Isolation Forest on *X* and return anomaly predictions.

        Parameters
        ----------
        X : Feature matrix of shape (n_samples, n_features).

        Returns
        -------
        pd.Series of bool, same length as X.
            True  → anomaly / THREAT
            False → normal behaviour
        """
        if X.shape[0] == 0:
            raise ValueError("Feature matrix X must have at least one row.")

        X_fit = self._scale(X, fit=True)

        logger.info(
            "Training IsolationForest (n_estimators=%d, contamination=%.3f) "
            "on %d samples …",
            self.n_estimators,
            self.contamination,
            X_fit.shape[0],
        )

        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        raw_predictions = self._model.fit_predict(X_fit)

        # IsolationForest returns -1 for outliers, 1 for inliers
        is_anomaly = pd.Series(raw_predictions == -1, dtype=bool)

        n_anomalies = is_anomaly.sum()
        logger.info(
            "Detection complete: %d / %d entries flagged as anomalies (%.1f%%).",
            n_anomalies,
            len(is_anomaly),
            100.0 * n_anomalies / len(is_anomaly),
        )
        return is_anomaly

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Return the raw anomaly score for each sample (lower = more anomalous).

        Requires that ``train_and_predict`` has already been called.
        """
        if self._model is None:
            raise RuntimeError("Call train_and_predict() before anomaly_scores().")
        X_fit = self._scale(X, fit=False)
        return self._model.decision_function(X_fit)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _scale(self, X: np.ndarray, *, fit: bool) -> np.ndarray:
        """Apply (or fit-then-apply) StandardScaler when requested."""
        if not self.scale_features:
            return X
        if fit:
            self._scaler = StandardScaler()
            return self._scaler.fit_transform(X)
        if self._scaler is None:
            raise RuntimeError("Scaler not fitted yet; call with fit=True first.")
        return self._scaler.transform(X)
