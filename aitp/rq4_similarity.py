"""RQ4: how similar are AI-assisted families to one another?

Pairwise similarity of AI-assisted units: binary Jaccard (with shared-technique counts),
cosine of prevalence vectors. Each AI pair is placed in the
distribution of the same measure over pairs of conventional families. Mantel test between the
Jaccard and cosine matrices.

Outputs: tables/rq4_pairs.csv, rq4_summary.csv, rq4_unit_counts.csv, rq4_mantel.csv,
figures/rq4_jaccard_<variant>, rq4_cosine_<variant> (PDF, PNG)
"""

from typing import Dict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from aitp import config as C
from aitp import dataset as D
from aitp import plotting as P
from aitp import stats as S

MEASURES = ("jaccard", "cosine")
LABELS = {"VibeWare": "Vibeware", "LameHug": "LAMEHUG", "Evil AI": "EvilAI"}   # spelling on the figure axes


def _upper(m: pd.DataFrame) -> np.ndarray:
    a = m.to_numpy(float)
    return a[np.triu_indices(len(a), 1)]


def _summ(x: np.ndarray) -> Dict:
    x = x[~np.isnan(x)]
    return {"n_pairs": len(x), "median": float(np.median(x)), "q25": float(np.percentile(x, 25)),
            "q75": float(np.percentile(x, 75)), "share_in_0.25_0.45": float(((x >= 0.25) & (x <= 0.45)).mean())}


def compute(cfg: Dict, v: D.Variant) -> Dict:
    ds = D.load(cfg, v)
    ai, ctl = ds.units(D.AI), ds.units(D.CTL)
    sa = {m: S.pairwise(ds.prev.loc[ai], m) for m in MEASURES}
    ref = {m: _upper(S.pairwise(ds.prev.loc[ctl], m)) for m in MEASURES}
    shared = S.shared_counts(ds.prev.loc[ai])
    rows = []
    for i, a in enumerate(ai):
        for b in ai[i + 1:]:
            r = {"variant": v.name, "unit_a": D.display(a), "unit_b": D.display(b), "n_a": int(ds.n_lab[a]),
                 "n_b": int(ds.n_lab[b]), "shared_techniques": int(shared.loc[a, b])}
            for m in MEASURES:
                r[m] = float(sa[m].loc[a, b])
                r[f"{m}_percentile_in_conventional"] = S.percentile_of(r[m], ref[m])
            rows.append(r)
    pairs = pd.DataFrame(rows)
    summ = []
    for m in MEASURES:
        summ.append({"variant": v.name, "measure": m, "pairs": "AI-assisted", **_summ(_upper(sa[m]))})
        summ.append({"variant": v.name, "measure": m, "pairs": "conventional (reference)", **_summ(ref[m])})
    mt = S.mantel_test(sa["jaccard"], sa["cosine"], int(cfg["permutations"]), int(cfg["seed"]))
    counts = pd.DataFrame({"variant": v.name, "unit": [D.display(u) for u in ai],
                           "n_labelled": [int(ds.n_lab[u]) for u in ai],
                           "n_techniques": [int((ds.prev.loc[u] > 0).sum()) for u in ai]})
    return {"pairs": pairs, "summary": pd.DataFrame(summ), "counts": counts, "sims": sa, "shared": shared,
            "n_lab": ds.n_lab, "mantel": {"variant": v.name, **mt}}


def heatmap(cfg: Dict, sim: pd.DataFrame, shared: pd.DataFrame, n_lab: pd.Series, stem: str, with_k: bool) -> None:
    P.style()
    labels = [f"{LABELS.get(D.display(u), D.display(u))} (n={int(n_lab[u])})" for u in sim.index]
    n = len(sim)
    fig, ax = plt.subplots(figsize=(0.62 * n + 2.5, 0.55 * n + 1.8))
    im = ax.imshow(sim.to_numpy(float), cmap="YlOrRd", vmin=0, vmax=1)
    for i in range(n):
        for j in range(n):
            val = sim.iat[i, j]
            ax.text(j, i, f"{val:.2f}" + (f"\n({int(shared.iat[i, j])})" if with_k else ""), ha="center",
                    va="center", fontsize=5.5, color="white" if val > 0.6 else "black")
    ax.set_xticks(range(n), labels, rotation=60, ha="right", fontsize=7)
    ax.set_yticks(range(n), labels, fontsize=7)
    ax.spines[:].set_visible(False)
    fig.colorbar(im, ax=ax, shrink=0.7)
    P.save(cfg, fig, stem)


def run(cfg: Dict) -> None:
    v = D.analysis(cfg)
    res = {v.name: compute(cfg, v)}
    for key, name in (("pairs", "rq4_pairs"), ("summary", "rq4_summary"), ("counts", "rq4_unit_counts")):
        C.write(cfg, pd.concat([r[key] for r in res.values()]), name)
    C.write(cfg, pd.DataFrame([r["mantel"] for r in res.values()]), "rq4_mantel")
    for name, r in res.items():
        heatmap(cfg, r["sims"]["jaccard"], r["shared"], r["n_lab"], f"rq4_jaccard_{name}", True)
        heatmap(cfg, r["sims"]["cosine"], r["shared"], r["n_lab"], f"rq4_cosine_{name}", False)
        s = r["summary"]
        print(f"  {name}: Mantel r={r['mantel']['r']:.2f}; median Jaccard AI "
              f"{s.iloc[0]['median']:.2f} vs conventional {s.iloc[1]['median']:.2f}")
