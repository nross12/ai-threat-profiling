"""RQ5: same-actor case studies, APT28 / LAMEHUG and APT36 / Vibeware.

Deltas: Retained (in both), Dropped (conventional only) and Introduced (AI-assisted only) techniques,
at parent and sub-technique level, and the same for MBC behaviours (objective IDs excluded).
Shares: tactic and kill-chain shares of the AI-assisted family and of the actor's full conventional
corpus = unique techniques with the tactic (stage) / unique techniques with any Enterprise tactic; a
technique counts under every tactic it belongs to and once per kill-chain stage it reaches. ATT&CK v18.1.
Retained in both case studies: the techniques in both families' Retained sets.
Rarefaction: the AI-assisted family has far fewer samples than its actor's
conventional corpus (11 vs 217, 3 vs 385), and a small draw holds fewer techniques, mostly common ones.
So we draw as many samples as the AI family has, without replacement, from the actor's ATT&CK-labelled
conventional samples (config.rarefaction_draws times, seeded) and compute, for each draw, the same
numbers as for the AI family: unique techniques, techniques with a tactic, and every tactic and
kill-chain share. For each number the table gives the AI-assisted value, the full-corpus value, the
draws' median and central 95% range (2.5th-97.5th percentile), the share of draws below and above the
AI value, and whether the AI value lies below, within or above the 95% range. Descriptive: no test.

Outputs: tables/rq5_deltas.csv, rq5_delta_items.csv, rq5_shares.csv, rq5_retained_in_both.csv,
rq5_rarefaction.csv,
figures/rq5_tactic_radar_<actor>_<variant>, rq5_kill_chain_<actor>_<variant> (PDF, PNG) = Figures 4-7
"""

from typing import Dict, List, Set, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from aitp import attack as A
from aitp import config as C
from aitp import dataset as D
from aitp import plotting as P
from aitp import stats as S

KEYS = [("tactic", k, A.TACTIC_NAMES[k]) for k in A.TACTIC_ORDER] +        [("kill_chain", k, A.KILL_CHAIN_LABELS[k]) for k in A.KILL_CHAIN_ORDER]


def mbc_sets(cfg: Dict) -> Dict[str, Set[str]]:
    """Sample -> MBC behaviour IDs (parent level, objective IDs excluded)."""
    m = D.derived(cfg, "report_mbc")
    m = m[~m["parent_id"].str.startswith(("OB", "OC"))]
    return m.groupby("sample_id")["parent_id"].apply(set).to_dict()


def mbc_case_sets(cfg: Dict, ds: D.Dataset) -> Dict[str, Dict]:
    """Per actor: MBC sets of the AI family's and the conventional samples (ATT&CK-labelled samples)."""
    ms = mbc_sets(cfg)
    out = {}
    for actor, c in D.case_study_sets(cfg, ds).items():
        out[actor] = {"ai_family": c["ai_family"], "ai": {s: ms[s] for s in c["ai"] if s in ms},
                      "control": {s: ms[s] for s in c["control"] if s in ms}}
    return out


def deltas(cfg: Dict, v: D.Variant) -> Tuple[List[Dict], List[Dict]]:
    """Retained / Dropped / Introduced counts and items for techniques, sub-techniques and MBC."""
    rows, items = [], []
    sources = {"technique": D.case_study_sets(cfg, D.load(cfg, v)),
               "sub_technique": D.case_study_sets(cfg, D.load(cfg, v.but(granularity="sub"))),
               "mbc_behaviour": mbc_case_sets(cfg, D.load(cfg, v))}
    for kind, cs in sources.items():
        for actor, c in cs.items():
            a, b = set().union(*c["ai"].values()), set().union(*c["control"].values())
            rows.append({"variant": v.name, "kind": kind, "actor": actor, "ai_family": c["ai_family"],
                         "n_ai_samples": len(c["ai"]), "n_conventional_samples": len(c["control"]),
                         "conventional": len(b), "ai": len(a), "retained": len(a & b), "dropped": len(b - a),
                         "introduced": len(a - b), "retained_share_of_conventional": len(a & b) / len(b) if b else np.nan})
            for name, ids in (("retained", a & b), ("dropped", b - a), ("introduced", a - b)):
                for t in sorted(ids):
                    items.append({"variant": v.name, "kind": kind, "actor": actor, "set": name, "id": t})
    return rows, items


def profile(tac_of, ts: Set[str]) -> Tuple[Dict, int]:
    """Tactic and kill-chain shares of a technique set: (kind, id) -> share, and the techniques with a tactic."""
    with_tactic = [t for t in ts if tac_of(t)]
    n = len(with_tactic)
    val = {}
    for kind, k, _ in KEYS:
        if kind == "tactic":
            hit = sum(k in tac_of(t) for t in with_tactic)
        else:
            hit = sum(k in {A.TACTIC_TO_KILL_CHAIN[x] for x in tac_of(t) if x in A.TACTIC_TO_KILL_CHAIN} for t in with_tactic)
        val[(kind, k)] = hit / n if n else 0.0
    return val, n


def tactic_lookup(cfg: Dict):
    cache: Dict[str, List[str]] = {}
    def tac_of(t: str) -> List[str]:
        if t not in cache:
            cache[t] = A.tactics_for(cfg, t)
        return cache[t]
    return tac_of


def shares(cfg: Dict, v: D.Variant) -> pd.DataFrame:
    """Tactic and kill-chain shares of each AI-assisted family and of its actor's full conventional corpus."""
    ds = D.load(cfg, v)
    tac_of = tactic_lookup(cfg)
    rows = []
    for actor, c in D.case_study_sets(cfg, ds).items():
        ai, n_ai = profile(tac_of, set().union(*c["ai"].values()))
        cv, n_cv = profile(tac_of, set().union(*c["control"].values()))
        for kind, k, name in KEYS:
            rows.append({"variant": v.name, "actor": actor, "ai_family": c["ai_family"], "n_ai": len(c["ai"]),
                         "n_conventional": len(c["control"]), "kind": kind, "id": k, "name": name,
                         "ai_share": ai[(kind, k)], "full_corpus_share": cv[(kind, k)],
                         "shift_pp": 100 * (ai[(kind, k)] - cv[(kind, k)]),
                         "ai_techniques_with_tactic": n_ai, "conventional_techniques_with_tactic": n_cv})
    return pd.DataFrame(rows)


def rarefaction(cfg: Dict, v: D.Variant) -> pd.DataFrame:
    """Draws of n_AI conventional samples per actor; the AI family's numbers against the draws' range."""
    ds = D.load(cfg, v)
    tac_of = tactic_lookup(cfg)
    n_draws = int(cfg.get("rarefaction_draws", 10000))
    rows = []
    for i, (actor, c) in enumerate(D.case_study_sets(cfg, ds).items()):
        rng = np.random.default_rng(int(cfg["seed"]) + 1500 + i)
        ids = sorted(c["control"])
        k = len(c["ai"])

        def numbers(ts: Set[str]) -> Dict:
            val, n = profile(tac_of, ts)
            return {("count", "techniques"): len(ts), ("count", "techniques_with_tactic"): n, **val}

        ai = numbers(set().union(*c["ai"].values()))
        full = numbers(set().union(*c["control"].values()))
        draws = [numbers(set().union(*(c["control"][ids[j]] for j in rng.choice(len(ids), k, replace=False))))
                 for _ in range(n_draws)]
        labels = [("count", "techniques", "Unique techniques"), ("count", "techniques_with_tactic", "Techniques with a tactic")] + KEYS
        for kind, key, name in labels:
            x = np.array([d[(kind, key)] for d in draws], dtype=float)
            a = ai[(kind, key)]
            lo, med, hi = np.percentile(x, [2.5, 50, 97.5])
            rows.append({"variant": v.name, "actor": actor, "ai_family": c["ai_family"], "n_drawn": k,
                         "n_conventional": len(ids), "draws": n_draws, "kind": kind, "id": key, "name": name,
                         "ai_value": a, "full_corpus_value": full[(kind, key)], "draw_median": med,
                         "draw_p2_5": lo, "draw_p97_5": hi, "draw_min": x.min(), "draw_max": x.max(),
                         "share_draws_below_ai": float((x < a).mean()), "share_draws_above_ai": float((x > a).mean()),
                         "ai_vs_draws": "above" if a > hi else ("below" if a < lo else "within")})
    return pd.DataFrame(rows)


PAPER_NAMES = {"LameHug": "LAMEHUG", "VibeWare": "Vibeware"}


def radar_and_kill_chain(cfg: Dict, df: pd.DataFrame, name: str) -> None:
    """Manuscript Figures 4-7: tactic radar and kill-chain bars of each AI family vs its actor's full corpus.

    Shares are % of techniques (as in ``shifts``); Reconnaissance and Resource Development get a radar
    axis only if a technique reaches them. 
    """
    for actor, d in df.groupby("actor", sort=False):
        fam = d["ai_family"].iloc[0]
        labels = {"full_corpus_share": f"{actor} conventional ({d['n_conventional'].iloc[0]} samples)",
                  "ai_share": f"{PAPER_NAMES.get(fam, fam)} ({d['n_ai'].iloc[0]} samples)"}
        styles = (("full_corpus_share", P.CONV_COLOUR, "o-"), ("ai_share", P.AI_COLOUR, "s-"))
        tac = d[d["kind"] == "tactic"].set_index("id")
        ids = [t for t in tac.index if t not in ("TA0043", "TA0042") or tac.at[t, "ai_share"] or tac.at[t, "full_corpus_share"]]
        ang = np.linspace(0, 2 * np.pi, len(ids), endpoint=False).tolist()
        P.style()
        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
        for col, colour, marker in styles:
            v = (100 * tac.loc[ids, col]).tolist()
            ax.plot(ang + ang[:1], v + v[:1], marker, lw=2, ms=4, color=colour, label=labels[col])
            ax.fill(ang + ang[:1], v + v[:1], alpha=0.12, color=colour)
        ax.set_xticks(ang, tac.loc[ids, "name"], size=8)
        ax.tick_params(axis="y", labelsize=7)
        ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.15), fontsize=9)
        P.save(cfg, fig, f"rq5_tactic_radar_{actor}_{name}")

        kc = d[d["kind"] == "kill_chain"].set_index("id").loc[A.KILL_CHAIN_ORDER]
        x, w = np.arange(len(kc)), 0.35
        fig, ax = plt.subplots(figsize=(10, 5))
        for (col, colour, _), off in zip(styles, (-w / 2, w / 2)):
            ax.bar(x + off, 100 * kc[col], w, color=colour, alpha=0.82, label=labels[col])
        ax.set_xticks(x, kc["name"], rotation=30, ha="right", fontsize=9)
        ax.set_ylabel("% of techniques")
        ax.legend(fontsize=9, frameon=False)
        P.save(cfg, fig, f"rq5_kill_chain_{actor}_{name}")


def retained_in_both(drows: List[Dict], items: List[Dict]) -> pd.DataFrame:
    """Techniques in the Retained set of both case studies, with their tactics."""
    it = pd.DataFrame(items)
    ret = it[(it["kind"] == "technique") & (it["set"] == "retained")]
    common = set.intersection(*[set(g["id"]) for _, g in ret.groupby("actor")]) if len(ret) else set()
    return pd.DataFrame({"technique": sorted(common)})


def run(cfg: Dict) -> None:
    v = D.analysis(cfg)
    drows, items = deltas(cfg, v)
    sh = shares(cfg, v)
    rare = rarefaction(cfg, v)
    radar_and_kill_chain(cfg, sh, v.name)
    both = retained_in_both(drows, items)
    names = A.technique_names(cfg)
    both["name"] = both["technique"].map(names)
    both["tactics"] = both["technique"].map(lambda t: "|".join(A.tactics_for(cfg, t)))
    C.write(cfg, pd.DataFrame(drows), "rq5_deltas")
    C.write(cfg, pd.DataFrame(items), "rq5_delta_items")
    C.write(cfg, sh, "rq5_shares")
    C.write(cfg, both, "rq5_retained_in_both")
    C.write(cfg, rare, "rq5_rarefaction")
    print(pd.DataFrame(drows)[["variant", "kind", "actor", "conventional", "ai", "retained", "dropped", "introduced"]].to_string(index=False))
    print(f"  retained in both case studies: {len(both)} techniques")
    r = rare[(rare["kind"] == "count") | (rare[["ai_value", "full_corpus_value"]].max(axis=1) > 0)].copy()
    for col in ("ai_value", "full_corpus_value", "draw_median", "draw_p2_5", "draw_p97_5"):
        r[col] = np.where(r["kind"] == "count", r[col], 100 * r[col])
    print("  rarefaction (shares in %):\n" + r[["actor", "name", "ai_value", "full_corpus_value", "draw_median",
                                               "draw_p2_5", "draw_p97_5", "ai_vs_draws"]].round(2).to_string(index=False))
