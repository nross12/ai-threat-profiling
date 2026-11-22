"""Data release and corpus provenance.

Outputs
  release/sample_manifest.csv          per sample: hashes, set, actor, family, file type, platform, format
                                       stratum, VT first submission, first/last sandbox report date, engines,
                                       labelled flags, number of v18.1 techniques
  release/technique_matrix.csv         binary sample x technique matrix (v18.1 parents)
  release/technique_matrix_sub.csv     the same with sub-techniques
  release/family_prevalence.csv  unit x technique prevalence used by the family-level analyses
  tables/provenance.csv                per set: entries, distinct samples, on VT, labelled, date ranges
  tables/dual_use_check.csv            conventional samples whose VT names or family match a dual-use tool
  tables/ai_exclusion_check.csv        AI-assisted hashes in a conventional list; conventional samples with
                                       LLM-endpoint evidence
"""

from typing import Dict

import pandas as pd

from aitp import config as C
from aitp import dataset as D


def manifest(cfg: Dict) -> pd.DataFrame:
    smp = D.derived(cfg, "samples")
    reps = D.derived(cfg, "reports")
    reps = reps[(reps["n_attack"] > 0) | (reps["n_mbc"] > 0)]
    rd = reps.groupby("sample_id")["analysis_date"].agg(["min", "max"])
    nt = D.derived(cfg, "sample_techniques").groupby("sample_id")["technique"].nunique()
    fam = pd.read_csv(C.path(cfg, "conventional_families"))
    fam_of = dict(zip(fam["sample_id"], fam["family"]))
    m = smp[["sample_id", "sha256", "sha1", "md5", "listed_hashes", "set", "actor", "family", "on_vt", "type_tag",
             "platform", "stratum", "first_submission_date", "attack_engines", "attack_labelled", "mbc_labelled"]].copy()
    m["family"] = [f if s == "AI" else fam_of.get(i, "") for s, f, i in zip(m["set"], m["family"], m["sample_id"])]
    m["actor"] = [a if s == "control" else next((k for k, v in cfg["case_studies"].items() if v == f), "")
                  for s, a, f in zip(m["set"], m["actor"], m["family"])]
    m["first_report_date"] = m["sample_id"].map(rd["min"])
    m["last_report_date"] = m["sample_id"].map(rd["max"])
    m["n_techniques_v18_1"] = m["sample_id"].map(nt).fillna(0).astype(int)
    return m


def provenance(cfg: Dict, m: pd.DataFrame) -> pd.DataFrame:
    lst = D.derived(cfg, "listed")
    rows = []
    for name, ml, mm in (("APT28 conventional", lst["actor"] == "APT28", (m["set"] == "control") & (m["actor"] == "APT28")),
                         ("APT36 conventional", lst["actor"] == "APT36", (m["set"] == "control") & (m["actor"] == "APT36")),
                         ("AI-assisted", lst["set"] == "AI", m["set"] == "AI")):
        d = m[mm]
        fs = pd.to_datetime(d["first_submission_date"], errors="coerce").dropna()
        rp = pd.to_datetime(d["first_report_date"], errors="coerce").dropna()
        rows.append({"set": name, "listed_entries": int(ml.sum()), "malformed": int((~lst.loc[ml, "valid_format"]).sum()),
                     "listed_twice_under_other_hash_form": int(ml.sum() - lst.loc[ml, "sample_id"].nunique()),
                     "distinct_samples": len(d), "on_vt": int(d["on_vt"].sum()), "attack_labelled": int(d["attack_labelled"].sum()),
                     "first_submission_min": fs.min().date(), "first_submission_median": fs.median().date(),
                     "first_submission_max": fs.max().date(), "report_date_min": rp.min().date(),
                     "report_date_max": rp.max().date()})
    return pd.DataFrame(rows)


def dual_use(cfg: Dict) -> pd.DataFrame:
    smp = D.derived(cfg, "samples")
    fam = pd.read_csv(C.path(cfg, "conventional_families"), keep_default_na=False)
    tok = dict(zip(fam["sample_id"], fam["claravy_token"]))
    tools = sorted({t.lower() for t in cfg["dual_use_tools"]})
    rows = []
    for r in smp[smp["set"] == "control"].itertuples():
        text = f"{r.vt_names if isinstance(r.vt_names, str) else ''} {tok.get(r.sample_id, '')}".lower().replace(" ", "")
        hit = [t for t in tools if t.replace(" ", "") in text]
        if hit:
            rows.append({"sample_id": r.sample_id, "actor": r.actor, "matched_tool": "|".join(hit)})
    return pd.DataFrame(rows, columns=["sample_id", "actor", "matched_tool"])


def ai_exclusion(cfg: Dict) -> pd.DataFrame:
    lst, smp, ev = D.derived(cfg, "listed"), D.derived(cfg, "samples"), D.derived(cfg, "llm_evidence")
    ai = set(lst.loc[lst["set"] == "AI", "sample_id"])
    rows = [{"check": "AI-assisted hash in a conventional list", "sample_id": s, "detail": ""}
            for s in lst.loc[(lst["set"] == "control") & lst["sample_id"].isin(ai), "sample_id"]]
    ctl = set(smp.loc[smp["set"] == "control", "sample_id"])
    e = ev[ev["sample_id"].isin(ctl) & (ev["endpoint_in_memory"] | ev["dns_attempt"] | ev["tls_sni"] | ev["http"])]
    rows += [{"check": "conventional sample with LLM-endpoint evidence", "sample_id": r.sample_id, "detail": r.llm_hosts}
             for r in e.itertuples()]
    return pd.DataFrame(rows or [{"check": "none found", "sample_id": "", "detail": ""}])


def run(cfg: Dict) -> None:
    out = C.path(cfg, "outputs", "release")
    out.mkdir(parents=True, exist_ok=True)
    m = manifest(cfg)
    m.to_csv(out / "sample_manifest.csv", index=False)
    for name, src in (("technique_matrix", "sample_techniques"), ("technique_matrix_sub", "sample_techniques_sub")):
        st = D.derived(cfg, src)
        st.assign(v=1).pivot_table(index="sample_id", columns="technique", values="v", fill_value=0,
                                   aggfunc="max").to_csv(out / f"{name}.csv")
    ds = D.load(cfg, D.analysis(cfg))
    p = ds.prev.copy()
    p.insert(0, "n_labelled", ds.n_lab)
    p.insert(0, "set", ds.unit_set)
    p.to_csv(out / "family_prevalence.csv")
    prov = provenance(cfg, m)
    C.write(cfg, prov, "provenance")
    du, ex = dual_use(cfg), ai_exclusion(cfg)
    C.write(cfg, du, "dual_use_check")
    C.write(cfg, ex, "ai_exclusion_check")
    print(prov.to_string(index=False))
    print(f"  dual-use matches: {len(du)}; exclusion check: {ex['check'].value_counts().to_dict()}")
