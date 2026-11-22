"""LLM-dependent behaviour and AI role.

1. Outcome of the LLM call per AI-assisted sample, best evidence first:
     downstream_observed   behaviour that only runs after the model answered (config.llm_downstream)
     llm_contacted         an LLM endpoint resolved in DNS, or a TLS/HTTP session to it
     dns_unresolved        a DNS lookup of an LLM endpoint that returned no address
     endpoint_static_only  an LLM endpoint only in memory strings
     none
   HTTPS hides response codes: "contacted" shows a connection was possible, not that the model answered.
   api_key_placeholder: the request to the LLM carries a template API key (e.g. 'sk-your-api-key-here'),
   so the call cannot succeed (AI Theater).
   Counted per family (llm_evidence_units) and per sample (llm_evidence_samples).
2. Techniques per runtime-family sample by outcome (median, mean, range).
3. The steps the model's answer drives (config.llm_steps; for LAMEHUG: discovery and collection
   commands into C:\\ProgramData\\info and an outbound SFTP connection), per sample, next to the
   Collection (TA0009) and Exfiltration (TA0010) techniques the sandboxes assigned to that sample.
4. Each AI-assisted family with a published ATT&CK software entry (config.published_mappings; only
   LAMEHUG, S9035 in Enterprise) against its sandbox profile: every parent technique in either, whether
   it is in the published entry, in any sample, and in the samples whose LLM call is shown to have
   been answered; tactics from ATT&CK v18.1.
5. The RQ1-RQ3 results by AI role (config.ai_roles): all families, runtime only, development only,
   runtime without HONESTCUE, without AI Theater, without AI Theater and FRUITSHELL. Per stratum: the
   AI-assisted top-10 at sample and family level, its mean Jaccard with the five published lists and its
   Jaccard with the conventional top-10, its Defense Evasion share, and the samples
   showing each RQ3 technique.

Outputs: tables/llm_evidence_samples.csv, llm_evidence_units.csv, llm_breadth_by_outcome.csv,
llm_steps.csv, llm_published_mapping.csv, llm_role_strata.csv
"""

from typing import Dict, List

import pandas as pd

from aitp import attack as A
from aitp import config as C
from aitp import dataset as D
from aitp import descriptives as DS
from aitp import rq3_novelty as R3
from aitp import stats as S

OUTCOMES = ["downstream_observed", "llm_contacted", "dns_unresolved", "endpoint_static_only", "none"]
ANSWERED = "downstream_observed"


def evidence(cfg: Dict) -> pd.DataFrame:
    smp = D.derived(cfg, "samples")
    smp = smp[smp["set"] == "AI"]
    ev = D.derived(cfg, "llm_evidence").set_index("sample_id")
    nt = D.derived(cfg, "sample_techniques").groupby("sample_id")["technique"].nunique()
    rows = []
    for r in smp.itertuples():
        e = ev.loc[r.sample_id]
        down_col = f"downstream_{r.family}"
        down = bool(e[down_col]) if down_col in e.index else False
        if down:
            o = "downstream_observed"
        elif e["dns_resolved"] or e["tls_sni"] or e["http"]:
            o = "llm_contacted"
        elif e["dns_attempt"]:
            o = "dns_unresolved"
        elif e["endpoint_in_memory"]:
            o = "endpoint_static_only"
        else:
            o = "none"
        rows.append({"sample_id": r.sample_id, "family": r.family, "role": cfg["ai_roles"].get(r.family, ""),
                     "labelled": bool(r.attack_labelled), "n_techniques": int(nt.get(r.sample_id, 0)),
                     "endpoint_in_memory": bool(e["endpoint_in_memory"]), "dns_attempt": bool(e["dns_attempt"]),
                     "dns_resolved": bool(e["dns_resolved"]), "tls_sni": bool(e["tls_sni"]), "http": bool(e["http"]),
                     "api_key_placeholder": bool(e["llm_api_key_placeholder"]),
                     "llm_hosts": e["llm_hosts"], "downstream_marker": cfg["llm_downstream"].get(r.family, ""),
                     "downstream": down, "outcome": o})
    return pd.DataFrame(rows)


def by_unit(ev: pd.DataFrame) -> pd.DataFrame:
    lab = ev[ev["labelled"]]
    out = lab.groupby(["family", "role"]).size().rename("n_labelled").to_frame()
    for o in OUTCOMES:
        out[o] = lab.groupby(["family", "role"])["outcome"].apply(lambda s: int((s == o).sum()))
    out["api_key_placeholder"] = lab.groupby(["family", "role"])["api_key_placeholder"].sum().astype(int)
    return out.reset_index().sort_values(["role", "family"])


def breadth(ev: pd.DataFrame) -> pd.DataFrame:
    r = ev[ev["labelled"] & (ev["role"] == "runtime")]
    groups = [(f, o, d) for (f, o), d in r.groupby(["family", "outcome"])]
    reached = r["outcome"].isin(["downstream_observed", "llm_contacted"])
    groups += [("all runtime", "model reached (answered or contacted)", r[reached]),
               ("all runtime", "model not reached", r[~reached])]
    return pd.DataFrame([{"family": f, "outcome": o, "n": len(d), "median_techniques": d["n_techniques"].median(),
                          "mean_techniques": d["n_techniques"].mean(), "min_techniques": d["n_techniques"].min(),
                          "max_techniques": d["n_techniques"].max()} for f, o, d in groups])


def steps(cfg: Dict, ev: pd.DataFrame) -> pd.DataFrame:
    """Per sample of the families in config.llm_steps: LLM outcome, each step seen, and the Collection and
    Exfiltration techniques assigned to the sample."""
    le = D.derived(cfg, "llm_evidence").set_index("sample_id")
    st = D.derived(cfg, "sample_techniques")
    techs = st.groupby("sample_id")["technique"].apply(set).to_dict()
    rows = []
    for fam, d in (cfg.get("llm_steps") or {}).items():
        for r in ev[ev["family"] == fam].itertuples():
            ts = techs.get(r.sample_id, set())
            row = {"family": fam, "sample_id": r.sample_id, "labelled": r.labelled, "outcome": r.outcome,
                   "n_techniques": r.n_techniques}
            for k in d:
                row[k] = bool(le.at[r.sample_id, f"step_{fam}_{k}"])
            for tac, name in (("TA0009", "collection"), ("TA0010", "exfiltration")):
                row[f"{name}_techniques_assigned"] = "|".join(sorted(t for t in ts if tac in A.tactics_for(cfg, t)))
            rows.append(row)
    return pd.DataFrame(rows)


def published_mapping(cfg: Dict, ev: pd.DataFrame) -> pd.DataFrame:
    """Published ATT&CK software entry vs the family's sandbox profile, per parent technique."""
    st = D.derived(cfg, "sample_techniques")
    names = A.technique_names(cfg)
    rows = []
    for fam, m in (cfg.get("published_mappings") or {}).items():
        sw_name, pub = A.software_techniques(cfg, m["bundle"], m["software"])
        lab = ev[(ev["family"] == fam) & ev["labelled"]]
        sand = set(st[st["sample_id"].isin(lab["sample_id"])]["technique"])
        ans = set(st[st["sample_id"].isin(lab.loc[lab["outcome"] == ANSWERED, "sample_id"])]["technique"])
        for t in sorted(pub | sand):
            rows.append({"family": fam, "software": f"{m['software']} {sw_name}", "bundle": m["bundle"],
                         "technique": t, "name": names.get(t, ""), "tactics": "|".join(A.tactics_for(cfg, t)),
                         "in_published": t in pub, "in_sandbox": t in sand, "in_sandbox_llm_answered": t in ans})
    return pd.DataFrame(rows)


def role_strata(cfg: Dict, focus: List[str]) -> pd.DataFrame:
    roles = cfg["ai_roles"]
    big = cfg["largest_ai_unit"]
    base = D.analysis(cfg)
    published = DS.published_lists(cfg)
    units = [D.display(u) for u in D.load(cfg, base).units(D.AI)]
    not_rt = [u for u in units if roles.get(u) != "runtime"]
    strata = {"all_units": [], "runtime_only": not_rt,
              "development_only": [u for u in units if roles.get(u) != "development"],
              f"runtime_only_without_{big}": not_rt + [big],
              "without_AI_Theater": ["AI Theater"], "without_AI_Theater_FRUITSHELL": ["AI Theater", "FRUITSHELL"]}
    rows = []
    for name, drop in strata.items():
        v = base.but(name=f"{base.name}:{name}", drop_units=base.drop_units + tuple(drop))
        ds = D.load(cfg, v)
        sets = ds.sample_sets(ds.samples["set"] == D.AI)
        row = {"stratum": name, "n_ai_units": len(ds.units(D.AI)),
               "ai_units": "|".join(D.display(u) for u in ds.units(D.AI)), "n_ai_samples": len(sets)}
        for level in ("sample", "family"):
            ls = DS.ranked_lists(ds, level)
            top = ls["AI"]["table"].head(10)["technique"].tolist()
            conv = ls["conventional"]["table"].head(10)["technique"].tolist()
            de = R3.tactic_distribution(cfg, {"x": top})
            row[f"{level}_top10"] = "|".join(top)
            row[f"{level}_mean_jaccard_published"] = sum(S.jaccard(top, b) for b in published.values()) / len(published)
            row[f"{level}_jaccard_conventional_top10"] = S.jaccard(top, conv)
            row[f"{level}_defense_evasion_share"] = float(de.loc[de["tactic"] == "TA0005", "share"].iloc[0])
        for t in focus:
            k = sum(t in s for s in sets.values())
            row[f"{t}_samples"] = k
            row[f"{t}_share"] = k / len(sets) if sets else 0.0
        rows.append(row)
    return pd.DataFrame(rows)


def run(cfg: Dict) -> None:
    ev = evidence(cfg)
    u = by_unit(ev)
    br = breadth(ev)
    stp = steps(cfg, ev)
    pm = published_mapping(cfg, ev)
    ds = D.load(cfg, D.analysis(cfg))
    focus = R3.candidates(cfg, ds, DS.published_lists(cfg))["technique"].tolist()
    rs = role_strata(cfg, focus)
    C.write(cfg, ev, "llm_evidence_samples")
    C.write(cfg, u, "llm_evidence_units")
    C.write(cfg, br, "llm_breadth_by_outcome")
    C.write(cfg, stp, "llm_steps")
    C.write(cfg, pm, "llm_published_mapping")
    C.write(cfg, rs, "llm_role_strata")
    print(u.to_string(index=False))
    print(br.round(1).to_string(index=False))
    print(stp.drop(columns=["sample_id"]).to_string(index=False))
    for fam, d in pm.groupby("family"):
        p, s = set(d.loc[d["in_published"], "technique"]), set(d.loc[d["in_sandbox"], "technique"])
        print(f"  {fam} vs {d['software'].iloc[0]}: published {len(p)}, sandbox {len(s)}, both {len(p & s)}, "
              f"Jaccard {len(p & s) / len(p | s):.2f}; published only: {', '.join(sorted(p - s))}")
    print(rs.drop(columns=["ai_units"]).round(3).T.to_string())
