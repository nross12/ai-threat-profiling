"""Dataset description and RQ1: counts, coverage, top-10 tables and the comparison with the published top-10 lists.

Outputs (outputs/tables/)
  dataset_flow.csv            listed -> distinct -> on VT -> with reports -> labelled, per set
  coverage_by_sandbox.csv     per engine: samples whose report carries ATT&CK only / MBC only / both / neither
  coverage_by_group.csv       per AI family and conventional actor: ATT&CK / MBC / both / none, coverage %
  engines_per_sample.csv      engines contributing ATT&CK labels per labelled sample
  top10_attack.csv            ten most prevalent techniques (AI, conventional, APT28, APT36), sample and family level
  top10_mbc.csv               ten most prevalent MBC behaviours (objective IDs excluded)
  measurement_effect.csv      Jaccard of each top-10 with the five published top-10 lists and with each other
  honestcue_attribution.csv   per HONESTCUE sample: build name, toolchain, submission, Gemini lookup, csc.exe
  attack_mapping.csv          raw ID -> v18.1 with the action taken; attack_mapping_summary.csv
"""

import json
from typing import Dict, List

import numpy as np
import pandas as pd

from aitp import attack as A
from aitp import config as C
from aitp import dataset as D
from aitp import stats as S

BASELINES = ["Picus", "Mandiant", "Red Canary", "CTID", "Saccone"]


def published_entries(cfg: Dict) -> Dict[str, List[str]]:
    """The five published top-10 lists, each entry mapped to its v18.1 parent (duplicates kept)."""
    pub = json.loads(C.path(cfg, "external_top10s").read_text(encoding="utf-8"))
    mp = D.derived(cfg, "mapping")
    m = dict(zip(mp["original_id"], mp["mapped_id"]))
    out = {}
    for name in BASELINES:
        out[name] = [x for x in (m.get(str(t).strip().upper()) for t in pub[name]["techniques"]) if isinstance(x, str)]
    return out


def published_lists(cfg: Dict) -> Dict[str, List[str]]:
    """The five published top-10 lists mapped to v18.1 parents; later duplicates dropped, order kept."""
    return {name: list(dict.fromkeys(lst)) for name, lst in published_entries(cfg).items()}


def dataset_flow(cfg: Dict) -> pd.DataFrame:
    lst, smp = D.derived(cfg, "listed"), D.derived(cfg, "samples")
    rows = []
    for name, ml, ms in (("AI-assisted", lst["set"] == "AI", smp["set"] == "AI"),
                         ("APT28 conventional", lst["actor"] == "APT28", smp["actor"] == "APT28"),
                         ("APT36 conventional", lst["actor"] == "APT36", smp["actor"] == "APT36")):
        s = smp[ms]
        rows.append({"set": name, "listed_entries": int(ml.sum()), "malformed_hashes": int((~lst.loc[ml, "valid_format"]).sum()),
                     "distinct_samples": len(s), "on_virustotal": int(s["on_vt"].sum()),
                     "with_sandbox_report": int((s["n_reports"] > 0).sum()),
                     "attack_labelled": int(s["attack_labelled"].sum()), "mbc_labelled": int(s["mbc_labelled"].sum())})
    return pd.DataFrame(rows)


def coverage_by_sandbox(cfg: Dict) -> pd.DataFrame:
    """Per engine, over the distinct samples it analysed (MBC objective IDs excluded)."""
    reps = D.derived(cfg, "reports")
    mbc = D.derived(cfg, "report_mbc")
    mbc = mbc[~mbc["parent_id"].str.startswith(("OB", "OC"))]
    beh = mbc.groupby(["sample_id", "engine"]).size().rename("n_beh")
    g = reps.groupby(["sample_id", "engine"]).agg(att=("n_attack", "max")).join(beh).fillna(0).reset_index()
    g["has_att"], g["has_mbc"] = g["att"] > 0, g["n_beh"] > 0
    out = g.groupby("engine").apply(lambda d: pd.Series({
        "samples": len(d), "attack_only": int((d.has_att & ~d.has_mbc).sum()),
        "mbc_only": int((~d.has_att & d.has_mbc).sum()), "both": int((d.has_att & d.has_mbc).sum()),
        "no_data": int((~d.has_att & ~d.has_mbc).sum())}), include_groups=False).reset_index()
    out = out[(out["attack_only"] + out["mbc_only"] + out["both"]) > 0]   # engines with no ATT&CK/MBC output omitted
    return out.sort_values("samples", ascending=False)


def coverage_by_group(cfg: Dict) -> pd.DataFrame:
    """ATT&CK-only / MBC-only / both / none per AI family and per conventional actor."""
    smp = D.derived(cfg, "samples")
    smp["group"] = np.where(smp["set"] == "AI", smp["family"], smp["actor"] + " conventional")
    rows = []
    for grp, d in smp.groupby("group", sort=False):
        a, m = d["attack_labelled"].astype(bool), d["mbc_labelled"].astype(bool)
        rows.append({"group": grp, "set": d["set"].iloc[0], "attack_only": int((a & ~m).sum()),
                     "mbc_only": int((~a & m).sum()), "both": int((a & m).sum()), "none": int((~a & ~m).sum()),
                     "total": len(d), "attack_coverage_pct": 100 * a.mean()})
    return pd.DataFrame(rows)


def engines_per_sample(cfg: Dict) -> pd.DataFrame:
    smp = D.derived(cfg, "samples")
    smp = smp[smp["attack_labelled"].astype(bool)]
    smp["n_engines"] = smp["attack_engines"].fillna("").map(lambda s: len([e for e in s.split("|") if e]))
    rows = [{"set": "AI-assisted", "labelled": int((smp["set"] == "AI").sum()),
             "mean_engines": smp.loc[smp["set"] == "AI", "n_engines"].mean()},
            {"set": "conventional", "labelled": int((smp["set"] == "control").sum()),
             "mean_engines": smp.loc[smp["set"] == "control", "n_engines"].mean()}]
    for a in ("APT28", "APT36"):
        rows.append({"set": a, "labelled": int((smp["actor"] == a).sum()),
                     "mean_engines": smp.loc[smp["actor"] == a, "n_engines"].mean()})
    return pd.DataFrame(rows)


def ranked_lists(ds: D.Dataset, level: str) -> Dict[str, Dict]:
    """Ranked prevalence tables for AI, conventional and each actor, at sample or family level."""
    masks = {"AI": ds.samples["set"] == D.AI, "conventional": ds.samples["set"] == D.CTL,
             "APT28": (ds.samples["set"] == D.CTL) & (ds.samples["actor"] == "APT28"),
             "APT36": (ds.samples["set"] == D.CTL) & (ds.samples["actor"] == "APT36")}
    out = {}
    for name, mask in masks.items():
        if level == "family":
            units = ds.units(D.AI if name == "AI" else D.CTL)
            if name in ("APT28", "APT36"):
                units = [u for u in units if name in ds.unit_actor[u]]
            prev = ds.prev.loc[units].mean(axis=0)
            prev, n = prev[prev > 0], len(units)
        else:
            prev, n = S.prevalence(ds.sample_sets(mask))
        out[name] = {"table": S.ranked(prev), "n": n}
    return out


def top10_and_overlap(cfg: Dict, v: D.Variant, level: str):
    ds = D.load(cfg, v)
    lists, base, names = ranked_lists(ds, level), published_lists(cfg), A.technique_names(cfg)
    trows, jrows = [], []
    for lname, d in lists.items():
        top = d["table"].head(10)
        for r in top.itertuples():
            trows.append({"variant": v.name, "level": level, "list": lname, "rank": r.rank, "technique": r.technique,
                          "name": names.get(r.technique, ""), "tactics": "|".join(A.tactics_for(cfg, r.technique)),
                          "prevalence": r.prevalence, "denominator": d["n"]})
        ts = top["technique"].tolist()
        refs = {**base, **({"AI top-10": lists["AI"]["table"].head(10)["technique"].tolist()} if lname != "AI" else {})}
        for b, bl in refs.items():
            jrows.append({"variant": v.name, "level": level, "list": lname, "compared_with": b,
                          "jaccard": S.jaccard(ts, bl), "shared": "|".join(sorted(set(ts) & set(bl)))})
    return pd.DataFrame(trows), pd.DataFrame(jrows)


def top10_mbc(cfg: Dict, v: D.Variant) -> pd.DataFrame:
    """MBC behaviours (objective IDs excluded) over MBC-labelled samples, sample and family level."""
    names = {}
    for obj in json.loads(C.path(cfg, "mbc_names").read_text(encoding="utf-8")).values():
        for b, n in obj.get("behaviours", {}).items():
            names.setdefault(b, n)
    mbc = D.derived(cfg, "report_mbc")
    mbc = mbc[~mbc["parent_id"].str.startswith(("OB", "OC"))]
    sets = mbc.groupby("sample_id")["parent_id"].apply(set).to_dict()
    ds = D.load(cfg, v)
    rows = []
    for which in (D.AI, D.CTL):
        smp = ds.samples[ds.samples["set"] == which]
        prev_s, n_s = S.prevalence({s: sets[s] for s in smp["sample_id"] if s in sets})
        per_unit = []
        for _, g in smp[smp["unit"].isin(ds.prev.index)].groupby("unit"):
            ids = [s for s in g["sample_id"] if s in sets]
            if ids:
                per_unit.append(S.prevalence({s: sets[s] for s in ids})[0])
        prev_f = pd.concat(per_unit, axis=1).fillna(0).mean(axis=1)
        for level, prev, n in (("sample", prev_s, n_s), ("family", prev_f, len(per_unit))):
            for r in S.ranked(prev).head(10).itertuples():
                rows.append({"variant": v.name, "level": level, "list": "AI" if which == D.AI else "conventional",
                             "rank": r.rank, "behaviour": r.technique, "name": names.get(r.technique, ""),
                             "prevalence": r.prevalence, "denominator": n})
    return pd.DataFrame(rows)


def honestcue_attribution(cfg: Dict) -> pd.DataFrame:
    """Section 3.1.1: per HONESTCUE sample, build name, toolchain, first submission, Gemini lookup, csc.exe launch."""
    smp = D.derived(cfg, "samples")
    ev = D.derived(cfg, "llm_evidence").set_index("sample_id")
    h = smp[(smp["set"] == "AI") & (smp["family"] == cfg["largest_ai_unit"])].copy()
    h["dotnet"] = h["die_tags"].fillna("").str.contains(".NET", regex=False)
    h["gemini_dns"] = h["sample_id"].map(ev["llm_hosts"]).fillna("").str.contains("generativelanguage")
    h["csc_launched"] = h["sample_id"].map(ev.get("downstream_HONESTCUE", pd.Series(dtype=bool))).fillna(False)
    return h[["sample_id", "meaningful_name", "stratum", "dotnet", "die_tags", "first_submission_date",
              "attack_labelled", "gemini_dns", "csc_launched"]]


def mapping_summary(cfg: Dict):
    att = D.derived(cfg, "report_attack")
    mp = D.derived(cfg, "mapping")
    mp = mp[mp["original_id"].isin(set(att["raw_id"]))]
    n_samples = att.groupby("raw_id")["sample_id"].nunique()
    mp["samples_with_id"] = mp["original_id"].map(n_samples).fillna(0).astype(int)
    summ = mp.groupby("action").agg(ids=("original_id", "size"), samples=("samples_with_id", "sum")).reset_index()
    summ.loc[len(summ)] = {"action": "mobile_kept", "ids": int(((mp["domain"] == "mobile") & mp["mapped_id"].notna()).sum()),
                           "samples": np.nan}
    return mp, summ


def run(cfg: Dict) -> None:
    C.write(cfg, dataset_flow(cfg), "dataset_flow")
    C.write(cfg, coverage_by_sandbox(cfg), "coverage_by_sandbox")
    C.write(cfg, coverage_by_group(cfg), "coverage_by_group")
    C.write(cfg, engines_per_sample(cfg), "engines_per_sample")
    tops, jacs, mbcs = [], [], []
    v = D.analysis(cfg)
    for level in ("sample", "family"):
        t, j = top10_and_overlap(cfg, v, level)
        tops.append(t); jacs.append(j)
    mbcs.append(top10_mbc(cfg, v))
    C.write(cfg, pd.concat(tops), "top10_attack")
    jac = pd.concat(jacs)
    C.write(cfg, jac, "measurement_effect")
    C.write(cfg, honestcue_attribution(cfg), "honestcue_attribution")
    C.write(cfg, pd.concat(mbcs), "top10_mbc")
    mp, summ = mapping_summary(cfg)
    C.write(cfg, mp, "attack_mapping")
    C.write(cfg, summ, "attack_mapping_summary")
    m = jac[jac["compared_with"].isin(BASELINES)].groupby(["variant", "level", "list"])["jaccard"].mean().unstack()
    print("  mean Jaccard with the five published lists:\n" + m.round(3).to_string())
