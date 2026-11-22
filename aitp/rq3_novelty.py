"""RQ3: techniques in the AI-assisted top-10 that no published top-10 list has.

  candidates   techniques of the AI-assisted top-10 (sample level) absent from all five
               published lists (CPS = 0). For each: AI-assisted samples showing it, the share of those
               that are HONESTCUE, the AI-assisted samples without HONESTCUE showing it, and the
               conventional samples (all, APT28, APT36) showing it.
  tactics      for the AI-assisted and conventional top-10 (sample and family level) and each published
               list, the share of each ATT&CK v18.1 tactic among the list's (entry, tactic) pairs. An
               entry counts once under every tactic of its parent technique; two entries with the same
               parent (Red Canary's T1059.001 and T1059.003) count twice; a Mobile technique (T1406)
               counts under the Enterprise tactic of the same name.

Outputs: tables/rq3_candidates.csv, rq3_tactic_distribution.csv (long), rq3_tactic_distribution_wide.csv
"""

from typing import Dict, List

import pandas as pd

from aitp import attack as A
from aitp import config as C
from aitp import dataset as D
from aitp import descriptives as DS
from aitp import stats as S


def top10(ds: D.Dataset, which: str) -> List[str]:
    prev, _ = S.prevalence(ds.sample_sets(ds.samples["set"] == which))
    return S.ranked(prev).head(10)["technique"].tolist()


def candidates(cfg: Dict, ds: D.Dataset, lists: Dict[str, List[str]]) -> pd.DataFrame:
    published = set().union(*lists.values())
    sets = ds.sample_sets()
    smp = ds.samples.set_index("sample_id")
    ai = [s for s in smp.index[smp["set"] == D.AI] if s in sets]
    ctl = [s for s in smp.index[smp["set"] == D.CTL] if s in sets]
    big = cfg["largest_ai_unit"]
    names = A.technique_names(cfg)
    rows = []
    for t in top10(ds, D.AI):
        if t in published:
            continue
        a = [s for s in ai if t in sets[s]]
        c = [s for s in ctl if t in sets[s]]
        h = sum(smp.at[s, "family"] == big for s in a)
        n_rest = sum(smp.at[s, "family"] != big for s in ai)
        rows.append({"technique": t, "name": names.get(t, ""), "tactics": "|".join(A.tactics_for(cfg, t)),
                     "ai_samples": len(a), "ai_labelled": len(ai), "ai_share": len(a) / len(ai),
                     f"{big}_samples": h, f"{big}_share_of_ai_samples": h / len(a) if a else 0.0,
                     f"ai_samples_without_{big}": len(a) - h, f"ai_labelled_without_{big}": n_rest,
                     f"ai_share_without_{big}": (len(a) - h) / n_rest if n_rest else 0.0,
                     "conventional_samples": len(c), "conventional_labelled": len(ctl), "conventional_share": len(c) / len(ctl),
                     "APT28_samples": sum(smp.at[s, "actor"] == "APT28" for s in c),
                     "APT36_samples": sum(smp.at[s, "actor"] == "APT36" for s in c)})
    return pd.DataFrame(rows)


def tactic_distribution(cfg: Dict, lists: Dict[str, List[str]]) -> pd.DataFrame:
    names = A.tactic_names(cfg)
    rows = []
    for lname, lst in lists.items():
        pairs = [x for t in lst for x in A.tactics_any(cfg, t)]
        for tac in A.TACTIC_ORDER:
            k = pairs.count(tac)
            rows.append({"list": lname, "tactic": tac, "tactic_name": names.get(tac, tac), "pairs": k,
                         "total_pairs": len(pairs), "share": k / len(pairs) if pairs else 0.0})
    return pd.DataFrame(rows)


def run(cfg: Dict) -> None:
    ds = D.load(cfg, D.analysis(cfg))
    cand = candidates(cfg, ds, DS.published_lists(cfg))
    fam = DS.ranked_lists(ds, "family")
    lists = {"AI-assisted": top10(ds, D.AI), "Conventional": top10(ds, D.CTL),
             "AI-assisted (family level)": fam["AI"]["table"].head(10)["technique"].tolist(),
             "Conventional (family level)": fam["conventional"]["table"].head(10)["technique"].tolist(),
             **DS.published_entries(cfg)}
    dist = tactic_distribution(cfg, lists)
    wide = dist.pivot_table(index=["tactic", "tactic_name"], columns="list", values="share", sort=False)[list(lists)]
    C.write(cfg, cand, "rq3_candidates")
    C.write(cfg, dist, "rq3_tactic_distribution")
    C.write(cfg, wide.reset_index(), "rq3_tactic_distribution_wide")
    print(cand.round(3).to_string(index=False))
    print((100 * wide).round(2).to_string())
