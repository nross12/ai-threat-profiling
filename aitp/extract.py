"""Build the derived tables every analysis reads, from the fetched VirusTotal reports.

Hash resolution: a file can be listed under its MD5, SHA-1 or SHA-256. Every vt-general report gives
all three, so each listed hash is mapped to the file's SHA-256 (the sample id) and a file listed twice
counts once. Hashes VirusTotal does not know keep their listed form.

Per sandbox report, technique IDs are read from every ``mitre_attack_techniques`` list and MBC
behaviour IDs from every ``mbc`` list in the report. A sample's technique set is the union over its
reports. Technique IDs are then mapped to ATT&CK v18.1 (aitp.attack).

Outputs (data/derived/)
  listed.csv               one row per listed entry
  samples.csv              one row per (set, actor, sample): VT status, engines, labels, file type,
                           platform, format stratum, build name, first submission
  reports.csv              one row per sandbox report
  report_attack.csv        (sample, report, engine, raw technique ID)
  report_mbc.csv           (sample, report, engine, raw MBC ID)
  report_attack_evidence.csv  (sample, report, engine, raw technique ID, evidence line), every entry
  mapping.csv              raw technique ID -> v18.1 (sandbox, CAPA and the published lists)
  sample_techniques.csv    (sample, v18.1 parent technique) with the engines that reported it
  sample_techniques_sub.csv  the same with sub-techniques kept
  llm_evidence.csv         per sample: LLM endpoint strings, DNS, TLS, HTTP; downstream markers; LLM-driven steps
"""

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from aitp import attack as A
from aitp import config as C

HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
MBC_OBJECTIVE_PREFIXES = ("OB", "OC")
SCRIPT_TAGS = {"python", "pyc", "javascript", "powershell", "bat", "shell", "vba", "c"}
DOC_TAGS = {"doc", "docx", "xls", "xlsx", "rtf", "pdf", "lnk", "outlook", "email", "ppt", "pptx"}
ARCHIVE_TAGS = {"zip", "rar", "isoimage", "7zip", "gzip"}


# ---------------------------------------------------------------------------------------------
# Raw report access
# ---------------------------------------------------------------------------------------------

def _load(p: Path) -> Any:
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _iso(epoch) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return None


def _walk(obj: Any, key: str) -> Iterable[Any]:
    """Every value stored under ``key`` anywhere in a JSON object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from _walk(v, key)
    elif isinstance(obj, list):
        for x in obj:
            yield from _walk(x, key)


def _ids(report: Dict, key: str) -> List[str]:
    out = []
    for lst in _walk(report, key):
        if isinstance(lst, list):
            for e in lst:
                i = e.get("id") if isinstance(e, dict) else (e if key == "mitre_attack_techniques" else None)
                if isinstance(i, str) and i.strip():
                    out.append(i.strip().upper())
    return out


def general_reports(cfg: Dict) -> Tuple[Dict[str, str], Dict[str, Dict]]:
    """(alias -> SHA-256, SHA-256 -> vt-general attributes) over every fetched general report."""
    alias, attrs = {}, {}
    gdir = C.path(cfg, "raw", "vt-general")
    for p in sorted(gdir.glob("*.json")):
        stem = p.stem.lower().removeprefix("fail_")
        j = _load(p)
        a = j.get("data", {}).get("attributes", {}) if isinstance(j.get("data"), dict) else {}
        if not a:
            continue
        sha = (a.get("sha256") or stem).lower()
        for h in (a.get("md5"), a.get("sha1"), a.get("sha256"), stem):
            if h:
                alias[h.lower()] = sha
        attrs[sha] = a
    return alias, attrs


def behaviour_reports(cfg: Dict, alias: Dict[str, str]) -> Dict[str, List[Tuple[str, Dict]]]:
    """SHA-256 -> [(file stem, behaviour response)]; error responses (not on VT) are skipped."""
    out: Dict[str, List[Tuple[str, Dict]]] = defaultdict(list)
    for p in sorted(C.path(cfg, "raw", "vt-behaviour").glob("*.json")):
        stem = p.stem.lower()
        j = _load(p)
        if stem.startswith("fail_") or "error" in j:
            continue
        out[alias.get(stem, stem)].append((stem, j))
    return out


# ---------------------------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------------------------

def listed(cfg: Dict, alias: Dict[str, str]) -> pd.DataFrame:
    rows = []
    ai = pd.read_csv(C.path(cfg, "hashes.ai"))
    for r in ai.itertuples():
        h = str(r.listed_hash).strip().lower()
        rows.append({"set": "AI", "actor": "", "family": r.family, "listed_hash": h,
                     "valid_format": bool(HASH_RE.match(h)), "sample_id": alias.get(h, h)})
    for actor in ("APT28", "APT36"):
        for h in pd.read_csv(C.path(cfg, f"hashes.{actor}"))["listed_hash"]:
            h = str(h).strip().lower()
            rows.append({"set": "control", "actor": actor, "family": "", "listed_hash": h,
                         "valid_format": bool(HASH_RE.match(h)), "sample_id": alias.get(h, h)})
    return pd.DataFrame(rows)


def stratum(type_tag: Optional[str], magika: Optional[str], die: List[Dict]) -> str:
    """File format / toolchain stratum: pe_dotnet, pe_native, script, document, archive, elf, apk, macho, other."""
    tt, mg = (type_tag or "").lower(), (magika or "").upper()
    if tt in ("peexe", "pedll") or mg == "PEBIN":
        names = " ".join(f"{v.get('type', '')}:{v.get('name', '')}" for v in die).lower()
        return "pe_dotnet" if (".net" in names or "costura" in names) else "pe_native"
    if tt in SCRIPT_TAGS or mg in {"PYTHON", "JAVASCRIPT", "POWERSHELL", "BATCH", "SHELL", "VBA"}:
        return "script"
    if tt in DOC_TAGS:
        return "document"
    if tt in ARCHIVE_TAGS or mg in {"ZIP", "RAR", "ISO"}:
        return "archive"
    if tt == "elf" or mg == "ELF":
        return "elf"
    if tt == "android" or mg == "APK":
        return "apk"
    if tt == "macho" or mg == "MACHO":
        return "macho"
    return "other"


def report_tables(beh: Dict[str, List[Tuple[str, Dict]]], ids: Iterable[str]):
    """reports, report_attack, report_mbc and report_attack_evidence for the given sample ids (reports
    de-duplicated by id). The evidence table keeps every entry of a report's ``mitre_attack_techniques``
    list with its signature description: one row per (technique, evidence line), as RQ7 counts them."""
    reps, att, mbc, evd = [], [], [], []
    for sid in sorted(set(ids)):
        seen = set()
        for stem, j in beh.get(sid, []):
            for item in j.get("data", []) or []:
                if not isinstance(item, dict):
                    continue
                rid = item.get("id") or f"{stem}#{len(seen)}"
                if rid in seen:
                    continue
                seen.add(rid)
                a = item.get("attributes", {}) or {}
                eng = a.get("sandbox_name") or "unknown"
                date = _iso(a.get("analysis_date"))
                t, b = sorted(set(_ids(item, "mitre_attack_techniques"))), sorted(set(_ids(item, "mbc")))
                reps.append({"sample_id": sid, "report_id": rid, "engine": eng, "analysis_date": date,
                             "n_attack": len(t), "n_mbc": len(b)})
                src = "capa" if eng == "CAPA" else "sandbox"
                att += [{"sample_id": sid, "report_id": rid, "engine": eng, "source": src, "raw_id": x} for x in t]
                mbc += [{"sample_id": sid, "report_id": rid, "engine": eng, "raw_id": x,
                         "parent_id": x.split(".", 1)[0]} for x in b]
                for e in a.get("mitre_attack_techniques") or []:
                    x = e.get("id") if isinstance(e, dict) else None
                    if isinstance(x, str) and x.strip():
                        evd.append({"sample_id": sid, "report_id": rid, "engine": eng, "raw_id": x.strip().upper(),
                                    "evidence": e.get("signature_description") or ""})
    cols = ["sample_id", "report_id", "engine"]
    return (pd.DataFrame(reps, columns=cols + ["analysis_date", "n_attack", "n_mbc"]),
            pd.DataFrame(att, columns=cols + ["source", "raw_id"]),
            pd.DataFrame(mbc, columns=cols + ["raw_id", "parent_id"]),
            pd.DataFrame(evd, columns=cols + ["raw_id", "evidence"]))


def sample_techniques(att: pd.DataFrame, mp: pd.DataFrame) -> pd.DataFrame:
    """One row per (sample, mapped technique) with the engines and reports behind it."""
    m = dict(zip(mp["original_id"], mp["mapped_id"]))
    dom = dict(zip(mp["original_id"], mp["domain"]))
    a = att.assign(technique=att["raw_id"].map(m), domain=att["raw_id"].map(dom))
    a = a[a["technique"].notna()]
    return a.groupby(["sample_id", "technique"]).agg(
        n_engines=("engine", "nunique"), engines=("engine", lambda s: "|".join(sorted(set(s)))),
        sources=("source", lambda s: "|".join(sorted(set(s)))), domain=("domain", "first"),
        n_reports=("report_id", "nunique")).reset_index()


PRIVATE = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)")

# An API key left as a template value (e.g. 'sk-your-api-key-here'): the LLM call cannot succeed.
PLACEHOLDER_KEY = re.compile(r"your|here|placeholder|xxxx|example|<.*>", re.I)


def llm_evidence(cfg: Dict, beh: Dict[str, List[Tuple[str, Dict]]], ids: Iterable[str]) -> pd.DataFrame:
    """Per sample: LLM endpoint evidence in memory strings, DNS, TLS and HTTP, and downstream-marker hits."""
    eps = [e.lower() for e in cfg["llm_endpoints"]]
    hit = lambda x: bool(x) and any(e in str(x).lower() for e in eps)
    down = {k: re.compile(v, re.I) for k, v in cfg["llm_downstream"].items()}
    steps = {(f, k): re.compile(v, re.I) for f, d in (cfg.get("llm_steps") or {}).items() for k, v in d.items()}
    rows = []
    for sid in sorted(set(ids)):
        ev = dict.fromkeys(("endpoint_in_memory", "dns_attempt", "dns_resolved", "tls_sni", "http"), False)
        hosts, codes, contact_eng = set(), [], set()
        placeholder = False
        dn = {k: set() for k in down}
        st = {k: set() for k in steps}
        n_rep = 0
        for _, j in beh.get(sid, []):
            for item in j.get("data", []) or []:
                a = (item or {}).get("attributes", {}) or {}
                n_rep += 1
                eng = a.get("sandbox_name", "")
                for k in ("memory_pattern_urls", "memory_pattern_domains"):
                    for m in a.get(k, []):
                        if hit(m if isinstance(m, str) else m.get("value")):
                            ev["endpoint_in_memory"] = True
                for d in a.get("dns_lookups", []):
                    if hit(d.get("hostname")):
                        ev["dns_attempt"] = True
                        hosts.add(d["hostname"])
                        if d.get("resolved_ips"):
                            ev["dns_resolved"] = True
                            contact_eng.add(eng)
                for t in a.get("tls", []):
                    if hit(t.get("sni")):
                        ev["tls_sni"] = True
                        hosts.add(t["sni"])
                        contact_eng.add(eng)
                for h in a.get("http_conversations", []):
                    if hit(h.get("url")):
                        ev["http"] = True
                        codes.append(str(h.get("response_status_code")))
                        auth = str((h.get("request_headers") or {}).get("Authorization", ""))
                        if auth and PLACEHOLDER_KEY.search(auth):
                            placeholder = True
                text = [str(x) for x in a.get("command_executions", [])] + [str(x) for x in a.get("processes_created", [])]
                for k, rx in down.items():
                    if any(rx.search(x) for x in text):
                        dn[k].add(eng)
                net = [f"tcp://{t.get('destination_ip')}:{t.get('destination_port')}" for t in a.get("ip_traffic", [])
                       if t.get("destination_ip") and not PRIVATE.match(str(t.get("destination_ip")))]
                for k, rx in steps.items():
                    if any(rx.search(x) for x in text + net):
                        st[k].add(eng)
        rows.append({"sample_id": sid, "n_reports": n_rep, **ev, "llm_api_key_placeholder": placeholder,
                     "llm_hosts": "|".join(sorted(hosts)),
                     "http_codes": "|".join(codes), "engines_contact": "|".join(sorted(contact_eng)),
                     **{f"downstream_{k}": bool(v) for k, v in dn.items()},
                     **{f"downstream_{k}_engines": "|".join(sorted(v)) for k, v in dn.items()},
                     **{f"step_{f}_{k}": bool(v) for (f, k), v in st.items()}})
    return pd.DataFrame(rows)


def run(cfg: Dict) -> None:
    out = C.derived_dir(cfg)
    alias, gen = general_reports(cfg)
    beh = behaviour_reports(cfg, alias)
    lst = listed(cfg, alias)
    ids = lst["sample_id"].unique()
    reps, att, mbc, evd = report_tables(beh, ids)

    # mapping to v18.1 (sandbox and CAPA IDs, and the published top-10 lists)
    pub = json.loads(C.path(cfg, "external_top10s").read_text(encoding="utf-8"))
    pub_ids = [t for v in pub.values() if isinstance(v, dict) for t in v.get("techniques", [])]
    mp = A.mapping(cfg, list(att["raw_id"]) + pub_ids)
    st = sample_techniques(att, mp)
    st_sub = sample_techniques(att, A.mapping(cfg, att["raw_id"], collapse=False))

    # per-sample table
    plat = cfg["type_tag_to_platform"]
    mbc_beh = mbc[~mbc["parent_id"].str.startswith(MBC_OBJECTIVE_PREFIXES)]
    rep_eng = reps.groupby("sample_id")["engine"].apply(lambda s: "|".join(sorted(set(s))))
    att_eng = att.groupby("sample_id")["engine"].apply(lambda s: "|".join(sorted(set(s))))
    mbc_eng = mbc_beh.groupby("sample_id")["engine"].apply(lambda s: "|".join(sorted(set(s))))
    n_rep = reps.groupby("sample_id").size()
    rows = []
    for (set_, actor, sid), g in lst.groupby(["set", "actor", "sample_id"], sort=True):
        a = gen.get(sid, {})
        on_vt, nr = sid in gen, int(n_rep.get(sid, 0))
        tag = a.get("type_tag")
        die = a.get("detectiteasy", {}).get("values", []) if isinstance(a.get("detectiteasy"), dict) else []
        rows.append({"set": set_, "actor": actor, "family": g["family"].iloc[0], "sample_id": sid,
                     "listed_hashes": "|".join(g["listed_hash"]), "n_listed": len(g),
                     "all_listed_valid": bool(g["valid_format"].all()),
                     "sha256": a.get("sha256"), "sha1": a.get("sha1"), "md5": a.get("md5"), "on_vt": on_vt,
                     "vt_status": "reports" if nr else ("on_vt_no_reports" if on_vt else "not_on_vt"),
                     "n_reports": nr, "engines": rep_eng.get(sid, ""), "attack_engines": att_eng.get(sid, ""),
                     "mbc_engines": mbc_eng.get(sid, ""), "attack_labelled": sid in att_eng.index,
                     "mbc_labelled": sid in mbc_eng.index, "type_tag": tag,
                     "platform": plat.get(tag, "unknown") if tag else ("unknown" if on_vt else "not_on_vt"),
                     "stratum": stratum(tag, a.get("magika"), die) if on_vt else "not_on_vt",
                     "meaningful_name": a.get("meaningful_name"), "vt_names": "|".join((a.get("names") or [])[:20]),
                     "die_tags": "|".join(f"{v.get('type', '')}:{v.get('name', '')}" for v in die),
                     "first_submission_date": _iso(a.get("first_submission_date")),
                     "first_submission_ts": a.get("first_submission_date")})
    samples = pd.DataFrame(rows)

    for name, df in (("listed", lst), ("samples", samples), ("reports", reps), ("report_attack", att),
                     ("report_mbc", mbc), ("report_attack_evidence", evd), ("mapping", mp), ("sample_techniques", st),
                     ("sample_techniques_sub", st_sub), ("llm_evidence", llm_evidence(cfg, beh, ids))):
        df.to_csv(out / f"{name}.csv", index=False)
    print(f"  {len(lst)} listed entries, {len(samples)} samples, {int(samples['attack_labelled'].sum())} "
          f"ATT&CK-labelled, {len(reps)} reports -> {out}")
