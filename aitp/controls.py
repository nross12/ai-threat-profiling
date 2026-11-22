"""Controls for the dominant family, actor, platform and file format.

  without_<largest>   the AI-assisted top-10 (sample and family level) and its Jaccard with the five
                      published lists and with our conventional top-10, with the largest AI unit
                      (HONESTCUE, config.largest_ai_unit) left out.
  leave-one-out       each AI-assisted family left out in turn: the AI-assisted top-10 at sample and
                      family level, which of the techniques absent from the published lists (RQ3) stay
                      in it, and the mean Jaccard with the five published lists.
  formats             labelled samples per file-format / toolchain group (aitp.extract.stratum: .NET PE,
                      native PE, script, document, archive, ELF, APK, Mach-O, other) and per platform, for
                      the AI-assisted set (with and without the largest unit), APT28 and APT36; and the
                      prevalence of each RQ3 technique within each format group.

Outputs: tables/controls_top10_without_<largest>.csv, controls_overlap_without_<largest>.csv,
controls_leave_one_family_out.csv, controls_format_composition.csv, controls_platform_composition.csv,
controls_techniques_by_format.csv
"""

from typing import Dict, List

import pandas as pd

from aitp import config as C
from aitp import dataset as D
from aitp import descriptives as DS
from aitp import rq3_novelty as R3
from aitp import stats as S


def without_largest(cfg: Dict):
    big = cfg["largest_ai_unit"]
    base = D.analysis(cfg)
    v = base.but(name=f"{base.name}_without_{big}", drop_units=base.drop_units + (big,))
    tops, jacs = [], []
    for level in ("sample", "family"):
        t, j = DS.top10_and_overlap(cfg, v, level)
        tops.append(t[t["list"] == "AI"])
        jacs.append(j[j["list"] == "AI"])
    return pd.concat(tops), pd.concat(jacs)


def leave_one_out(cfg: Dict, focus: List[str]) -> pd.DataFrame:
    base = D.analysis(cfg)
    published = DS.published_lists(cfg)
    units = [D.display(u) for u in D.load(cfg, base).units(D.AI)]
    rows = []
    for fam in [None] + units:
        v = base if fam is None else base.but(name=f"without_{fam}", drop_units=base.drop_units + (fam,))
        ds = D.load(cfg, v)
        lists = DS.ranked_lists(ds, "sample"), DS.ranked_lists(ds, "family")
        row = {"left_out": fam or "(none)", "ai_units": len(ds.units(D.AI)),
               "ai_samples": int((ds.samples["set"] == D.AI).sum())}
        for level, ls in zip(("sample", "family"), lists):
            top = ls["AI"]["table"].head(10)["technique"].tolist()
            row[f"{level}_top10"] = "|".join(top)
            row[f"{level}_mean_jaccard_published"] = sum(S.jaccard(top, b) for b in published.values()) / len(published)
            for t in focus:
                row[f"{level}_{t}_in_top10"] = t in top
        rows.append(row)
    return pd.DataFrame(rows)


def formats(cfg: Dict, focus: List[str]):
    big = cfg["largest_ai_unit"]
    ds = D.load(cfg, D.analysis(cfg))
    smp = ds.samples.copy()
    smp["group"] = smp["actor"].where(smp["set"] == D.CTL, "AI-assisted")
    groups = {"AI-assisted": smp["group"] == "AI-assisted",
              f"AI-assisted without {big}": (smp["group"] == "AI-assisted") & (smp["family"] != big),
              big: smp["family"] == big, "APT28": smp["group"] == "APT28", "APT36": smp["group"] == "APT36",
              "conventional": smp["set"] == D.CTL}
    comp = pd.DataFrame({g: smp.loc[m, "stratum"].value_counts() for g, m in groups.items()}).fillna(0).astype(int)
    plat = pd.DataFrame({g: smp.loc[m, "platform"].value_counts() for g, m in groups.items()}).fillna(0).astype(int)
    sets = ds.sample_sets()
    rows = []
    for t in focus:
        for stratum, sg in smp.groupby("stratum"):
            for g in ("AI-assisted", f"AI-assisted without {big}", "conventional"):
                ids = sg.loc[groups[g].loc[sg.index], "sample_id"]
                n = len(ids)
                k = sum(t in sets.get(s, set()) for s in ids)
                rows.append({"technique": t, "format": stratum, "group": g, "samples": n, "with_technique": k,
                             "share": k / n if n else None})
    return comp.rename_axis("format").reset_index(), plat.rename_axis("platform").reset_index(), pd.DataFrame(rows)


def run(cfg: Dict) -> None:
    big = cfg["largest_ai_unit"]
    ds = D.load(cfg, D.analysis(cfg))
    focus = R3.candidates(cfg, ds, DS.published_lists(cfg))["technique"].tolist()
    top, ov = without_largest(cfg)
    lofo = leave_one_out(cfg, focus)
    comp, plat, by_fmt = formats(cfg, focus)
    C.write(cfg, top, f"controls_top10_without_{big}")
    C.write(cfg, ov, f"controls_overlap_without_{big}")
    C.write(cfg, lofo, "controls_leave_one_family_out")
    C.write(cfg, comp, "controls_format_composition")
    C.write(cfg, plat, "controls_platform_composition")
    C.write(cfg, by_fmt, "controls_techniques_by_format")
    for level in ("sample", "family"):
        x = top[top["level"] == level]
        j = ov[(ov["level"] == level) & ov["compared_with"].isin(DS.BASELINES)]["jaccard"].mean()
        print(f"  without {big}, {level} level: {', '.join(x['technique'])}; mean Jaccard {j:.3f}")
    print(lofo[["left_out"] + [c for c in lofo.columns if c.endswith("_in_top10") or "mean_jaccard" in c]].round(3).to_string(index=False))
    print(comp.to_string(index=False))
