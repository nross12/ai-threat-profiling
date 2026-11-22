"""RQ2: disproportionately prevalent techniques, by prominence scores.

The five published top-10 lists (Picus, Mandiant, Red Canary, MITRE CTID, Saccone et al.) are mapped
to ATT&CK v18.1 parent techniques; a parent that appears twice in one list keeps its first rank and
the list is re-ranked (aitp.descriptives.published_lists).

  CPS     Consensus Prominence Score: per list, rank 1 = 10 points ... rank 10 = 1, absent = 0, summed
          over the five lists.
  frequency ranking  techniques by the number of lists that contain them, ties by CPS.
  APS     AI-assisted Prominence Score: the same rank points for the AI-assisted top-10, at
          sample level and at family level; tied techniques keep the order.
  PD      Prominence Delta = APS - CPS, with its classification. APS is one list's rank points
          (at most 10) and CPS a sum over five lists (at most 50), so the table also gives two versions
          on the same scale: PD_mean = APS - CPS/5 (the mean points per list), and
          PD_consensus = APS - the rank points of the technique in the CPS ranking itself (10 for CPS rank 1
          ... 1 for rank 10, 0 below), i.e. the AI-assisted top-10 against the consensus top-10.

Internal comparison: every technique observed in the dataset, AI-assisted against
conventional samples. Sample level: samples showing it, prevalence and the difference in percentage
points, with the Newcombe (Wilson score) 95% interval of the difference and the same interval widened
for all techniques at once (Bonferroni, 1 - 0.05/m); also without HONESTCUE. Family level: the mean of
the family prevalences (AI-assisted families vs conventional families) and their difference. Ranks
within each group are given at both levels. The intervals describe the sampling uncertainty of
independent samples; samples of one family are not independent (HONESTCUE: 35 near-identical builds).

Outputs: tables/rq2_cps.csv (every technique in a list, ranked by CPS), rq2_frequency_ranking.csv,
rq2_prominence.csv (column ``level`` = sample / family), rq2_internal.csv
"""

from collections import Counter
from typing import Dict, Tuple

import numpy as np
import pandas as pd
from scipy.stats import norm

from aitp import attack as A
from aitp import config as C
from aitp import dataset as D
from aitp import descriptives as DS


def cps(cfg: Dict) -> pd.DataFrame:
    """CPS and list count per technique, with each list's rank."""
    lists = DS.published_lists(cfg)
    names = A.technique_names(cfg)
    score, count = Counter(), Counter()
    rows: Dict[str, Dict] = {}
    for lname, lst in lists.items():
        for i, t in enumerate(lst, 1):
            score[t] += 11 - i
            count[t] += 1
            rows.setdefault(t, {})[f"rank_{lname}"] = i
    out = pd.DataFrame([{"technique": t, "name": names.get(t, ""), "CPS": score[t], "n_lists": count[t], **rows[t]}
                        for t in score])
    out = out.sort_values(["CPS", "technique"], ascending=[False, True]).reset_index(drop=True)
    out.insert(0, "rank", out["CPS"].rank(method="min", ascending=False).astype(int))
    return out


def frequency_ranking(c: pd.DataFrame) -> pd.DataFrame:
    """Techniques by the number of lists containing them; ties broken by CPS, then by ID."""
    f = c.sort_values(["n_lists", "CPS", "technique"], ascending=[False, False, True]).reset_index(drop=True)
    f.insert(0, "position", range(1, len(f) + 1))
    return f[["position", "technique", "name", "n_lists", "CPS"]]


def classify(aps: int, cps_: int) -> str:
    if cps_ == 0:
        return "Absent from external top-10s"
    pd_ = aps - cps_
    return "Higher in AI top-10" if pd_ > 0 else ("Parity" if pd_ == 0 else "Higher in external baselines")


def prominence(cfg: Dict, c: pd.DataFrame, level: str = "sample") -> pd.DataFrame:
    """APS, CPS and PD for the AI-assisted top-10 at sample or family level."""
    ds = D.load(cfg, D.analysis(cfg))
    top = DS.ranked_lists(ds, level)["AI"]["table"].head(10).reset_index(drop=True)
    cmap = dict(zip(c["technique"], c["CPS"]))
    crank = dict(zip(c["technique"], c["rank"]))
    names = A.technique_names(cfg)
    rows = []
    for pos, r in enumerate(top.itertuples(), 1):
        aps, cp = 11 - pos, int(cmap.get(r.technique, 0))
        cons = 11 - int(crank[r.technique]) if r.technique in crank and crank[r.technique] <= 10 else 0
        rows.append({"level": level, "technique": r.technique, "name": names.get(r.technique, ""), "rank_table6": int(r.rank),
                     "prevalence": r.prevalence, "APS": aps, "CPS": cp, "PD": aps - cp, "classification": classify(aps, cp),
                     "CPS_over_5": cp / 5, "PD_mean": aps - cp / 5, "consensus_points": cons, "PD_consensus": aps - cons})
    return pd.DataFrame(rows)


def _wilson(k: int, n: int, z: float) -> Tuple[float, float]:
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def newcombe(k1: int, n1: int, k2: int, n2: int, z: float) -> Tuple[float, float]:
    """Newcombe hybrid score interval for p1 - p2 (his method 10)."""
    p1, p2 = k1 / n1, k2 / n2
    l1, u1 = _wilson(k1, n1, z)
    l2, u2 = _wilson(k2, n2, z)
    d = p1 - p2
    return d - np.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2), d + np.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)


def internal(cfg: Dict) -> pd.DataFrame:
    """Every technique: AI-assisted vs conventional prevalence at sample and family level."""
    ds = D.load(cfg, D.analysis(cfg))
    big = cfg["largest_ai_unit"]
    smp = ds.samples.set_index("sample_id")
    sets = ds.sample_sets()
    ai = [s for s in sets if smp.at[s, "set"] == D.AI]
    rest = [s for s in ai if smp.at[s, "family"] != big]
    ctl = [s for s in sets if smp.at[s, "set"] == D.CTL]
    techs = sorted(set().union(*sets.values()))
    m = len(techs)
    z95, zb = norm.ppf(0.975), norm.ppf(1 - 0.05 / (2 * m))
    fa, fc = ds.prev.loc[ds.units(D.AI)], ds.prev.loc[ds.units(D.CTL)]
    names = A.technique_names(cfg)
    rows = []
    for t in techs:
        ka, kr, kc = (sum(t in sets[s] for s in g) for g in (ai, rest, ctl))
        lo, hi = newcombe(ka, len(ai), kc, len(ctl), z95)
        blo, bhi = newcombe(ka, len(ai), kc, len(ctl), zb)
        rlo, rhi = newcombe(kr, len(rest), kc, len(ctl), z95)
        pa = fa[t].mean() if t in fa else 0.0
        pc = fc[t].mean() if t in fc else 0.0
        rows.append({"technique": t, "name": names.get(t, ""), "tactics": "|".join(A.tactics_for(cfg, t)),
                     "ai_samples": ka, "ai_n": len(ai), "ai_pct": 100 * ka / len(ai),
                     "conventional_samples": kc, "conventional_n": len(ctl), "conventional_pct": 100 * kc / len(ctl),
                     "diff_pp": 100 * (ka / len(ai) - kc / len(ctl)), "diff_ci95_low": 100 * lo, "diff_ci95_high": 100 * hi,
                     "diff_ci_bonferroni_low": 100 * blo, "diff_ci_bonferroni_high": 100 * bhi,
                     f"ai_without_{big}_samples": kr, f"ai_without_{big}_n": len(rest),
                     f"ai_without_{big}_pct": 100 * kr / len(rest),
                     f"diff_without_{big}_pp": 100 * (kr / len(rest) - kc / len(ctl)),
                     f"diff_without_{big}_ci95_low": 100 * rlo, f"diff_without_{big}_ci95_high": 100 * rhi,
                     "ai_family_mean_pct": 100 * pa, "ai_families": len(fa),
                     "conventional_family_mean_pct": 100 * pc, "conventional_families": len(fc),
                     "family_diff_pp": 100 * (pa - pc)})
    out = pd.DataFrame(rows)
    for col, src in (("ai_rank", "ai_pct"), ("conventional_rank", "conventional_pct"),
                     ("ai_family_rank", "ai_family_mean_pct"), ("conventional_family_rank", "conventional_family_mean_pct")):
        out[col] = out[src].rank(method="min", ascending=False).astype(int)
    out = out.sort_values("diff_pp", ascending=False).reset_index(drop=True)
    out.attrs["m"] = m
    return out


def run(cfg: Dict) -> None:
    c = cps(cfg)
    f = frequency_ranking(c)
    p = pd.concat([prominence(cfg, c, "sample"), prominence(cfg, c, "family")], ignore_index=True)
    C.write(cfg, c, "rq2_cps")
    C.write(cfg, f, "rq2_frequency_ranking")
    C.write(cfg, p, "rq2_prominence")
    it = internal(cfg)
    C.write(cfg, it, "rq2_internal")
    print("  CPS top-10:\n" + c.head(10)[["rank", "technique", "CPS", "n_lists"]].to_string(index=False))
    print("  frequency ranking: " + ", ".join(f.head(10)["technique"]))
    print("  prominence:\n" + p[["level", "technique", "APS", "CPS", "PD", "PD_mean", "consensus_points", "PD_consensus",
                                    "classification"]].to_string(index=False))
    cols = ["technique", "ai_samples", "ai_pct", "conventional_samples", "conventional_pct", "diff_pp", "diff_ci95_low",
            "diff_ci95_high", "diff_ci_bonferroni_low", "diff_ci_bonferroni_high", "diff_without_HONESTCUE_pp",
            "ai_family_mean_pct", "conventional_family_mean_pct", "family_diff_pp"]
    print(f"  internal comparison: {it.attrs['m']} techniques\n" + it[cols].round(1).to_string(index=False))
