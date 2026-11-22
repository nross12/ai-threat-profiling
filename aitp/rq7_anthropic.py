"""RQ7: AI-assisted malware vs Anthropic's banned-account activity.

Observations: every entry of a sandbox report's ``mitre_attack_techniques`` list for the labelled
AI-assisted samples, with sub-techniques collapsed to their parent (report_attack_evidence). A
technique seen by several engines, or with several evidence lines, counts each time (the
"observations of techniques").

  tactic shares  per ATT&CK v18.1 Enterprise tactic, the observations of its techniques; a technique
                 counts under every tactic it belongs to. Mobile techniques have no Enterprise tactic,
                 and revoked or deprecated IDs (e.g. T1064 Scripting, T1063) are left out of the tactic
                 counts rather than remapped, as in the manuscript; they stay in the observation total.
                 Ours (%) = tactic observations / all tactic observations. Divergence (%) =
                 |Anthropic - ours| / mean(Anthropic, ours) x 100.
  top-25         our 25 techniques with the most observations; Jaccard with Anthropic's top-25,
                 after collapsing both lists to parent techniques; Anthropic's list is
                 data/published/anthropic_top25s.json.
  divergence     Jensen-Shannon divergence (base 2: 0 = identical, 1 = disjoint) between the tactic
                 distributions of Anthropic, the AI-assisted samples and, for scale, the conventional
                 samples (counted the same way), over all 14 tactics and over the 12 tactics a sandbox can
                 observe (Reconnaissance and Resource Development left out, shares renormalised).
                 Descriptive: no test.

Outputs: tables/rq7_tactic_shares.csv, rq7_top25.csv, rq7_top25_jaccard.json (with Anthropic's list),
rq7_divergence.csv
"""

import json
from typing import Dict

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon

from aitp import attack as A
from aitp import config as C
from aitp import dataset as D
from aitp import stats as S


PRE_COMPROMISE = ("TA0043", "TA0042")


def observations(cfg: Dict, which: str = D.AI) -> pd.DataFrame:
    """One row per (labelled sample of ``which``, report, evidence line) with its parent technique."""
    ds = D.load(cfg, D.analysis(cfg))
    ai = set(ds.samples.loc[ds.samples["set"] == which, "sample_id"])
    ev = D.derived(cfg, "report_attack_evidence")
    ev = ev[ev["sample_id"].isin(ai)].copy()
    ev["technique"] = ev["raw_id"].str.split(".").str[0]
    return ev


def tactic_counts(cfg: Dict, ev: pd.DataFrame) -> Dict[str, int]:
    """Observations per tactic; revoked or deprecated IDs and Mobile techniques count under none."""
    ent = A.index(cfg, "enterprise_18_1").techniques
    live = lambda t: t in ent and not ent[t].get("revoked") and not ent[t].get("x_mitre_deprecated")
    tac = {t: A.tactics_for(cfg, t) if live(t) else [] for t in ev["technique"].unique()}
    counts = {t: 0 for t in A.TACTIC_ORDER}
    for t, n in ev["technique"].value_counts().items():
        for x in tac[t]:
            counts[x] += int(n)
    return counts


def anthropic_shares(cfg: Dict) -> Dict[str, float]:
    return json.loads(C.path(cfg, "anthropic_tactic_shares").read_text(encoding="utf-8"))["shares"]


def divergence(dists: Dict[str, Dict[str, float]]) -> pd.DataFrame:
    """Jensen-Shannon divergence (base 2) between each pair of tactic distributions."""
    rows = []
    names = list(dists)
    for scope, keep in (("all 14 tactics", list(A.TACTIC_ORDER)),
                        ("12 tactics (without Reconnaissance, Resource Development)",
                         [t for t in A.TACTIC_ORDER if t not in PRE_COMPROMISE])):
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                p = np.array([dists[a].get(t, 0.0) for t in keep], float)
                q = np.array([dists[b].get(t, 0.0) for t in keep], float)
                rows.append({"scope": scope, "a": a, "b": b,
                             "jensen_shannon_divergence": float(jensenshannon(p / p.sum(), q / q.sum(), base=2) ** 2),
                             "a_share_in_scope": float(p.sum() / sum(dists[a].values())),
                             "b_share_in_scope": float(q.sum() / sum(dists[b].values()))})
    return pd.DataFrame(rows)


def tactic_shares(cfg: Dict, ev: pd.DataFrame, conv: Dict[str, int] = None) -> pd.DataFrame:
    anth = anthropic_shares(cfg)
    counts = tactic_counts(cfg, ev)
    total = sum(counts.values())
    ctot = sum(conv.values()) if conv else 0
    rows = []
    for t in sorted(anth, key=lambda k: -anth[k]):
        ours = 100 * counts.get(t, 0) / total
        a = float(anth[t])
        rows.append({"tactic": t, "tactic_name": A.TACTIC_NAMES.get(t, t), "anthropic_pct": a, "observations": counts.get(t, 0),
                     "ours_pct": ours, "divergence_pct": 100 * abs(a - ours) / ((a + ours) / 2) if a + ours else 0.0,
                     **({"conventional_observations": conv.get(t, 0), "conventional_pct": 100 * conv.get(t, 0) / ctot}
                        if conv else {})})
    out = pd.DataFrame(rows)
    out.attrs["total_tactic_observations"] = total
    return out


def run(cfg: Dict) -> None:
    ev = observations(cfg)
    names = A.technique_names(cfg)
    conv = tactic_counts(cfg, observations(cfg, D.CTL))
    shares = tactic_shares(cfg, ev, conv)
    div = divergence({"Anthropic": anthropic_shares(cfg), "AI-assisted": tactic_counts(cfg, ev), "conventional": conv})
    top = ev["technique"].value_counts().rename_axis("technique").reset_index(name="observations")
    top.insert(0, "rank", top["observations"].rank(method="min", ascending=False).astype(int))
    top["name"] = top["technique"].map(names)
    top25 = top.head(25)
    C.write(cfg, shares, "rq7_tactic_shares")
    C.write(cfg, top25, "rq7_top25")
    C.write(cfg, div, "rq7_divergence")
    print(f"  {len(ev)} technique observations, {shares.attrs['total_tactic_observations']} tactic observations, "
          f"{ev['sample_id'].nunique()} samples")
    print(shares.round(2).to_string(index=False))
    print(div.round(3).to_string(index=False))
    p = C.path(cfg, "anthropic_top25")
    if p.exists():
        raw = json.loads(p.read_text(encoding="utf-8"))
        items = raw["techniques"] if isinstance(raw, dict) else [r["technique"] for r in raw]
        theirs = [str(t).split(".")[0].upper() for t in items]
        j = S.jaccard(top25["technique"], theirs)
        C.write_json(cfg, {"jaccard": j, "ours": top25["technique"].tolist(), "anthropic_parents": sorted(set(theirs)),
                           "shared": sorted(set(top25["technique"]) & set(theirs))}, "rq7_top25_jaccard")
        print(f"  top-25 Jaccard with Anthropic: {j:.4f}")
    else:
        print(f"  {p.name} not found: Anthropic's top-25 list is needed for the Jaccard")
