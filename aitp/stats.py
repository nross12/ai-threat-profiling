"""Similarity measures, prevalence and ranking, and the Mantel test of RQ4 (scikit-bio)."""

from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from skbio.stats.distance import DistanceMatrix, mantel

# --------------------------------------------------------------------------------------------
# Similarity
# --------------------------------------------------------------------------------------------


def jaccard(a: Iterable, b: Iterable) -> float:
    """Jaccard index of two sets (NaN if both are empty)."""
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb) if sa | sb else float("nan")


def _jaccard_vec(x, y) -> float:
    xb, yb = np.asarray(x) > 0, np.asarray(y) > 0
    u = np.logical_or(xb, yb).sum()
    return float(np.logical_and(xb, yb).sum() / u) if u else float("nan")


def _cosine(x, y) -> float:
    x, y = np.asarray(x, float), np.asarray(y, float)
    nx, ny = np.linalg.norm(x), np.linalg.norm(y)
    return float(x @ y / (nx * ny)) if nx and ny else float("nan")


MEASURES = {"jaccard": _jaccard_vec, "cosine": _cosine}


def pairwise(m: pd.DataFrame, measure: str) -> pd.DataFrame:
    """Square similarity matrix over the rows of ``m``."""
    f, v = MEASURES[measure], m.to_numpy(float)
    out = np.eye(len(v))
    for i in range(len(v)):
        for j in range(i + 1, len(v)):
            out[i, j] = out[j, i] = f(v[i], v[j])
    return pd.DataFrame(out, index=m.index, columns=m.index)


def shared_counts(m: pd.DataFrame) -> pd.DataFrame:
    """Techniques present in both units (diagonal: each unit's own count)."""
    b = (m.to_numpy(float) > 0).astype(int)
    return pd.DataFrame(b @ b.T, index=m.index, columns=m.index)


def prevalence(sets: Mapping[str, Iterable[str]]) -> Tuple[pd.Series, int]:
    """Share of non-empty sets containing each item, and the number of non-empty sets."""
    counts: Dict[str, int] = {}
    n = 0
    for s in sets.values():
        s = {t for t in s if t}
        if s:
            n += 1
            for t in s:
                counts[t] = counts.get(t, 0) + 1
    if not n:
        return pd.Series(dtype=float), 0
    return (pd.Series(counts, dtype=float).sort_index() / n).sort_values(ascending=False, kind="mergesort"), n


def ranked(prev: pd.Series) -> pd.DataFrame:
    """Prevalence table sorted by prevalence then ID; tied items share the lowest rank."""
    df = prev.rename("prevalence").rename_axis("technique").reset_index()
    df = df.sort_values(["prevalence", "technique"], ascending=[False, True], kind="mergesort").reset_index(drop=True)
    df["rank"] = df["prevalence"].rank(ascending=False, method="min").astype(int)
    return df


# --------------------------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------------------------


def sim_to_distance(sim: pd.DataFrame) -> DistanceMatrix:
    d = 1.0 - sim.to_numpy(float)
    d = (d + d.T) / 2
    np.fill_diagonal(d, 0.0)
    d[np.abs(d) < 1e-12] = 0.0
    return DistanceMatrix(d, ids=[str(i) for i in sim.index])


def mantel_test(x: pd.DataFrame, y: pd.DataFrame, permutations: int, seed: int) -> Dict:
    r, p, n = mantel(sim_to_distance(x), sim_to_distance(y), method="pearson", permutations=permutations, seed=seed)
    return {"r": float(r), "p": float(p), "n": int(n)}


def percentile_of(value: float, ref: np.ndarray) -> float:
    """Percent of reference values <= value."""
    ref = np.asarray(ref, float)
    ref = ref[~np.isnan(ref)]
    return float(100 * (ref <= value + 1e-12).mean()) if len(ref) and not np.isnan(value) else float("nan")
