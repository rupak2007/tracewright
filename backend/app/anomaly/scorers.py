"""Window scorers (architecture §8): `robust_z`, `iforest`, and `random` (evaluation baseline only).

All scorers are deterministic under their fixed seed and score on a feature matrix whose columns
are `features.FEATURES`. A higher score means "more unusual relative to this capture". The
explanation of a window is the same for every scorer: its top features by |modified z| against the
fitted population's median (no SHAP).
"""

from dataclasses import dataclass
from typing import Protocol

import numpy as np
from numpy.typing import NDArray
from sklearn.ensemble import IsolationForest

from app.anomaly.config import AnomalyConfig
from app.anomaly.features import FEATURES

_MAD_SCALE = 0.6745
_MEAN_AD_SCALE = 1.2533  # Iglewicz-Hoaglin fallback when MAD is 0

Matrix = NDArray[np.float64]


class Scorer(Protocol):
    name: str

    def fit(self, x: Matrix) -> None: ...

    def score(self, x: Matrix) -> Matrix: ...


@dataclass
class RobustStats:
    median: Matrix
    scale: Matrix  # 0 where a feature is constant (skipped)


def robust_stats(x: Matrix) -> RobustStats:
    median = np.median(x, axis=0)
    deviations = np.abs(x - median)
    mad = np.median(deviations, axis=0)
    mean_ad = np.mean(deviations, axis=0)
    scale = np.where(mad > 0, mad / _MAD_SCALE, mean_ad * _MEAN_AD_SCALE)
    return RobustStats(median=median, scale=scale)


def modified_z(x: Matrix, stats: RobustStats) -> Matrix:
    """Signed modified z per cell; constant features (scale 0) contribute 0."""
    safe = np.where(stats.scale > 0, stats.scale, 1.0)
    z = (x - stats.median) / safe
    return np.where(stats.scale > 0, z, 0.0)


class RobustZScorer:
    name = "robust_z"

    def __init__(self) -> None:
        self.stats: RobustStats | None = None

    def fit(self, x: Matrix) -> None:
        self.stats = robust_stats(x)

    def score(self, x: Matrix) -> Matrix:
        if self.stats is None:
            raise RuntimeError("scorer is not fitted")
        return np.asarray(np.max(np.abs(modified_z(x, self.stats)), axis=1), dtype=np.float64)


class IForestScorer:
    name = "iforest"

    def __init__(self, cfg: AnomalyConfig) -> None:
        max_samples = cfg.iforest.max_samples
        self.model = IsolationForest(
            n_estimators=cfg.iforest.n_estimators,
            max_samples=max_samples if max_samples == "auto" else int(max_samples),
            random_state=cfg.iforest.seed,
        )
        self.fitted = False

    def fit(self, x: Matrix) -> None:
        self.model.fit(x)
        self.fitted = True

    def score(self, x: Matrix) -> Matrix:
        if not self.fitted:
            raise RuntimeError("scorer is not fitted")
        return np.asarray(-self.model.score_samples(x), dtype=np.float64)


class RandomScorer:
    """Seeded random scores: the chance baseline for evaluation. Never shipped."""

    name = "random"

    def __init__(self, seed: int) -> None:
        self.seed = seed

    def fit(self, x: Matrix) -> None:
        return None

    def score(self, x: Matrix) -> Matrix:
        return np.random.default_rng(self.seed).random(len(x))


def make_scorer(name: str, cfg: AnomalyConfig) -> Scorer:
    if name == "robust_z":
        return RobustZScorer()
    if name == "iforest":
        return IForestScorer(cfg)
    if name == "random":
        return RandomScorer(cfg.iforest.seed)
    raise ValueError(f"unknown scorer {name!r}")


@dataclass(frozen=True)
class FeatureDeviation:
    feature: str
    z: float
    value: float
    median: float


def top_deviations(row: Matrix, stats: RobustStats, k: int = 3) -> list[FeatureDeviation]:
    """Top-k features of one window by |modified z| (ties: feature order), with value and median."""
    z = modified_z(row.reshape(1, -1), stats)[0]
    order = sorted(range(len(FEATURES)), key=lambda j: (-abs(z[j]), j))[:k]
    return [
        FeatureDeviation(
            FEATURES[j],
            round(float(z[j]), 4),
            round(float(row[j]), 4),
            round(float(stats.median[j]), 4),
        )
        for j in order
    ]
