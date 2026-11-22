"""RQ6: technique scores (CSS) of AI-assisted vs conventional tooling.

CSS, from ATT&CK v18.1 relationships (revoked or
deprecated objects excluded), over the pooled Enterprise techniques with a tactic observed in the
dataset (all platforms):
  C1 = 1 / (mitigations + 1); C2 = ln(groups + 1) + ln(campaigns + 1) + ln(software + 1);
  C3 = 1 / (data-component detections + 1)
  p_ij = C_ij / sum_i C_ij; entropy weights w_j; score = sum_j w_j p_ij, min-max scaled.
In v18.1 no technique has data-component detections, so C3 is constant and gets weight 0.

Per case study: mean CSS +/- SD over the unique techniques of the conventional corpus and of the
AI-assisted family, their differential, and the mean per tactic.
Also: CSS by tactic over all scored techniques, and Spearman's rho with each input.

Random subsets. Each AI-assisted family's techniques are a subset of its actor's
conventional techniques, so its mean CSS can only differ from the conventional mean by which subset it
holds. We therefore draw, config.subset_draws times (seeded), as many techniques as the AI family has
from the actor's conventional techniques, without replacement, and compute the differential (subset
mean - conventional mean); the same per tactic, drawing within the tactic. A second comparison draws
samples instead of techniques (as many conventional samples as the AI family has, as in the RQ5
rarefaction) and scores the techniques of each draw. For each, the table gives the observed differential,
the draws' median, SD and central 95% range, the share of draws below and above it, and whether the
observed value lies below, within or above that range. Descriptive: no test.

Outputs: tables/rq6_css_techniques.csv, rq6_css_means.csv, rq6_css_differentials.csv,
rq6_css_by_tactic_and_group.csv, rq6_css_by_tactic.csv, rq6_css_correlations.json, rq6_css_subsets.csv
"""

from typing import Dict, List

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from aitp import attack as A
from aitp import config as C
from aitp import dataset as D

REL = {("mitigates", "course-of-action"): "mitigations", ("uses", "intrusion-set"): "groups",
       ("uses", "campaign"): "campaigns", ("uses", "malware"): "software", ("uses", "tool"): "software",
       ("detects", "x-mitre-data-component"): "detections"}


def scores(cfg: Dict, pool: List[str]) -> pd.DataFrame:
    """Criteria, entropy weights and CSS for each technique of ``pool``."""
    idx = A.index(cfg, "enterprise_18_1")
    objs = {o["id"]: o for o in idx.bundle["objects"]}
    dead = lambda o: o.get("revoked") or o.get("x_mitre_deprecated")
    cnt: Dict[str, Dict[str, int]] = {k: {} for k in set(REL.values())}
    for r in idx.bundle["objects"]:
        if r.get("type") != "relationship" or dead(r):
            continue
        s, t = objs.get(r.get("source_ref")), objs.get(r.get("target_ref"))
        if s and t and not dead(s) and not dead(t) and t.get("type") == "attack-pattern":
            k = REL.get((r["relationship_type"], s["type"]))
            if k:
                cnt[k][t["id"]] = cnt[k].get(t["id"], 0) + 1
    rows = []
    for t in pool:
        sid = idx.techniques[t]["id"]
        g = {k: cnt[k].get(sid, 0) for k in cnt}
        rows.append({"technique": t, **g, "C1_mitigation": 1 / (g["mitigations"] + 1),
                     "C2_threat": np.log(g["groups"] + 1) + np.log(g["campaigns"] + 1) + np.log(g["software"] + 1),
                     "C3_detection": 1 / (g["detections"] + 1)})
    df = pd.DataFrame(rows).set_index("technique")
    X = df[["C1_mitigation", "C2_threat", "C3_detection"]]
    Pm = X / X.sum()
    with np.errstate(divide="ignore", invalid="ignore"):
        E = -(Pm * np.log(Pm.where(Pm > 0, 1))).sum() / np.log(len(X))
    w = (1 - E) / (1 - E).sum()
    s = (Pm * w).sum(axis=1)
    df["css"] = (s - s.min()) / (s.max() - s.min())
    for c in w.index:
        df[f"weight_{c}"] = w[c]
    df["tactics"] = ["|".join(A.tactics_for(cfg, t)) for t in df.index]
    return df


def compute(cfg: Dict, v: D.Variant) -> Dict:
    """CSS table, group means, differentials and tactic-level means."""
    ds = D.load(cfg, v)
    ent = A.index(cfg, "enterprise_18_1").techniques
    pool = sorted(t for t in set(ds.st["technique"]) if t in ent and not ent[t].get("revoked")
                  and not ent[t].get("x_mitre_deprecated") and A.tactics_for(cfg, t))
    tab = scores(cfg, pool)
    css = tab["css"]
    names = A.tactic_names(cfg)
    means, diffs, tac_rows = [], [], []
    for actor, c in D.case_study_sets(cfg, ds).items():
        a = sorted(t for t in set().union(*c["ai"].values()) if t in css.index)
        b = sorted(t for t in set().union(*c["control"].values()) if t in css.index)
        for grp, ts in ((f"{actor} conventional", b), (c["ai_family"], a)):
            means.append({"group": grp, "n_techniques": len(ts), "mean_css": css[ts].mean(), "sd_css": css[ts].std()})
        diffs.append({"pair": f"{actor} & {c['ai_family']}", "mean_ai": css[a].mean(), "mean_conventional": css[b].mean(),
                      "differential": css[a].mean() - css[b].mean(),
                      "differential_of_rounded_means": round(css[a].mean(), 2) - round(css[b].mean(), 2)})
        tac_of = {t: set(A.tactics_for(cfg, t)) for t in set(a) | set(b)}
        for tac in sorted({x for t in set(a) | set(b) for x in tac_of[t]}):
            a_t = [t for t in a if tac in tac_of[t]]
            b_t = [t for t in b if tac in tac_of[t]]
            tac_rows.append({"actor": actor, "ai_family": c["ai_family"], "tactic": tac, "tactic_name": names.get(tac, tac),
                             "n_ai": len(a_t), "n_conventional": len(b_t),
                             "mean_ai": css[a_t].mean() if a_t else np.nan,
                             "mean_conventional": css[b_t].mean() if b_t else np.nan,
                             "differential": (css[a_t].mean() - css[b_t].mean()) if a_t and b_t else np.nan})
    return {"tab": tab, "means": pd.DataFrame(means), "diffs": pd.DataFrame(diffs), "tactic": pd.DataFrame(tac_rows)}


def _row(actor, fam, method, tactic, name, n_ai, n_conv, obs, x) -> Dict:
    lo, med, hi = np.percentile(x, [2.5, 50, 97.5])
    return {"actor": actor, "ai_family": fam, "method": method, "tactic": tactic, "tactic_name": name,
            "n_ai_techniques": n_ai, "n_conventional_techniques": n_conv, "observed_differential": obs,
            "draw_median": med, "draw_sd": x.std(ddof=1), "draw_p2_5": lo, "draw_p97_5": hi,
            "share_draws_below": float((x < obs - 1e-12).mean()), "share_draws_above": float((x > obs + 1e-12).mean()),
            "observed_vs_draws": "above" if obs > hi + 1e-12 else ("below" if obs < lo - 1e-12 else "within")}


def subsets(cfg: Dict, v: D.Variant, css: pd.Series) -> pd.DataFrame:
    """Observed CSS differentials against random technique subsets and random sample draws."""
    ds = D.load(cfg, v)
    n_draws = int(cfg.get("subset_draws", 10000))
    names = A.tactic_names(cfg)
    rows = []
    for i, (actor, c) in enumerate(D.case_study_sets(cfg, ds).items()):
        rng = np.random.default_rng(int(cfg["seed"]) + 1600 + i)
        fam = c["ai_family"]
        a = sorted(t for t in set().union(*c["ai"].values()) if t in css.index)
        b = sorted(t for t in set().union(*c["control"].values()) if t in css.index)
        cb = css[b].to_numpy()
        obs = css[a].mean() - cb.mean()
        x = np.array([cb[rng.choice(len(b), len(a), replace=False)].mean() for _ in range(n_draws)]) - cb.mean()
        rows.append(_row(actor, fam, "technique_subsets", "all", "All tactics", len(a), len(b), obs, x))
        tac_of = {t: set(A.tactics_for(cfg, t)) for t in b}
        for tac in A.TACTIC_ORDER:
            a_t = [t for t in a if tac in tac_of.get(t, ())]
            b_t = [t for t in b if tac in tac_of[t]]
            if not a_t:
                continue
            cbt = css[b_t].to_numpy()
            xt = np.array([cbt[rng.choice(len(b_t), len(a_t), replace=False)].mean() for _ in range(n_draws)]) - cbt.mean()
            rows.append(_row(actor, fam, "technique_subsets", tac, names.get(tac, tac), len(a_t), len(b_t),
                             css[a_t].mean() - cbt.mean(), xt))
        ids = sorted(c["control"])
        k = len(c["ai"])
        xs = []
        for _ in range(n_draws):
            ts = [t for t in set().union(*(c["control"][ids[j]] for j in rng.choice(len(ids), k, replace=False))) if t in css.index]
            xs.append(css[ts].mean() - cb.mean())
        rows.append(_row(actor, fam, "sample_draws", "all", "All tactics", len(a), len(b), obs, np.array(xs)))
    return pd.DataFrame(rows)


def run(cfg: Dict) -> None:
    r = compute(cfg, D.analysis(cfg))
    sub = subsets(cfg, D.analysis(cfg), r["tab"]["css"])
    tab, means, diffs, tac_rows = r["tab"], r["means"], r["diffs"], r["tactic"]
    names = A.tactic_names(cfg)
    long = pd.DataFrame([{"tactic": x, "technique": t, "css": r.css, "mitigations": r.mitigations,
                          "groups": r.groups, "software": r.software}
                         for t, r in tab.iterrows() for x in r.tactics.split("|")])
    by = long.groupby("tactic").agg(n=("technique", "size"), mean_css=("css", "mean"), mean_mitigations=("mitigations", "mean"),
                                    mean_groups=("groups", "mean"), mean_software=("software", "mean")).reset_index()
    by.insert(1, "tactic_name", by["tactic"].map(names))
    rho = {c: float(spearmanr(tab["css"], tab[c]).statistic) for c in ("mitigations", "groups", "campaigns", "software",
                                                                     "C1_mitigation", "C2_threat")}
    C.write(cfg, tab.reset_index(), "rq6_css_techniques")
    C.write(cfg, pd.DataFrame(means), "rq6_css_means")
    C.write(cfg, diffs, "rq6_css_differentials")
    C.write(cfg, tac_rows, "rq6_css_by_tactic_and_group")
    C.write(cfg, by.sort_values("mean_css", ascending=False), "rq6_css_by_tactic")
    C.write(cfg, sub, "rq6_css_subsets")
    C.write_json(cfg, {"spearman_rho_css_vs": rho, "weights": tab.filter(like="weight_").iloc[0].to_dict(),
                       "n_techniques": len(tab)}, "rq6_css_correlations")
    print(pd.DataFrame(means).round(4).to_string(index=False))
    print(diffs.round(4).to_string(index=False))
    print(f"  weights {tab.filter(like='weight_').iloc[0].round(3).to_dict()}; rho {({k: round(v, 2) for k, v in rho.items()})}")
    print(sub.drop(columns=["ai_family"]).round(4).to_string(index=False))
