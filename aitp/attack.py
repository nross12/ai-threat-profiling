"""MITRE ATT&CK: bundle index, technique-ID normalisation to v18.1, tactics and kill-chain stages.

Normalisation of a raw technique ID (sandbox, CAPA or a published list):
  1. look it up in the Enterprise v18.1 bundle, else in the Mobile v18.1 bundle;
  2. follow ``revoked-by`` relationships to the current technique;
  3. drop deprecated techniques (a deprecated sub-technique with a live parent collapses to the parent);
  4. collapse sub-techniques to their parent (unless ``collapse=False``);
  5. drop IDs found in neither bundle.
"""

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Set, Tuple

import pandas as pd

from aitp import config as C

TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SOURCES = {"mitre-attack", "mitre-mobile-attack"}

TACTIC_NAMES = {"TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
                "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion", "TA0006": "Credential Access",
                "TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection",
                "TA0010": "Exfiltration", "TA0011": "C2", "TA0040": "Impact", "TA0042": "Resource Development",
                "TA0043": "Reconnaissance"}
TACTIC_ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007",
                "TA0008", "TA0009", "TA0010", "TA0011", "TA0040"]
# Lockheed Martin kill chain: tactic -> stage
TACTIC_TO_KILL_CHAIN = {"TA0043": "1-Reconnaissance", "TA0042": "2-Weaponization", "TA0001": "3-Delivery",
                        "TA0002": "4-Exploitation", "TA0003": "5-Installation", "TA0004": "5-Installation",
                        "TA0005": "5-Installation", "TA0006": "7-Actions", "TA0007": "7-Actions",
                        "TA0008": "7-Actions", "TA0009": "7-Actions", "TA0010": "7-Actions", "TA0011": "6-C2",
                        "TA0040": "7-Actions"}
KILL_CHAIN_ORDER = ["1-Reconnaissance", "2-Weaponization", "3-Delivery", "4-Exploitation", "5-Installation",
                    "6-C2", "7-Actions"]
KILL_CHAIN_LABELS = {"1-Reconnaissance": "Reconnaissance", "2-Weaponization": "Weaponization",
                     "3-Delivery": "Delivery", "4-Exploitation": "Exploitation", "5-Installation": "Installation",
                     "6-C2": "C2", "7-Actions": "Actions on Objectives"}

BUNDLES = {"enterprise_18_1": "enterprise-attack-18.1.json", "mobile_18_1": "mobile-attack-18.1.json"}


def _ext(obj: Dict) -> Optional[str]:
    for r in obj.get("external_references", []) or []:
        if r.get("source_name") in SOURCES and r.get("external_id"):
            return r["external_id"]
    return None


def _dead(o: Dict) -> bool:
    return bool(o.get("revoked")) or bool(o.get("x_mitre_deprecated"))


@dataclass
class Index:
    """Look-ups over one STIX bundle."""
    domain: str
    bundle: Dict
    techniques: Dict[str, Dict] = field(default_factory=dict)
    stix_to_ext: Dict[str, str] = field(default_factory=dict)
    revoked_by: Dict[str, str] = field(default_factory=dict)
    tactic_by_shortname: Dict[str, str] = field(default_factory=dict)
    tactic_names: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(cls, bundle: Dict, domain: str) -> "Index":
        idx = cls(domain=domain, bundle=bundle)
        for o in bundle["objects"]:
            t = o.get("type")
            if t == "attack-pattern" and _ext(o):
                e = _ext(o)
                idx.stix_to_ext[o["id"]] = e
                prev = idx.techniques.get(e)
                if prev is None or (_dead(prev) and not _dead(o)):
                    idx.techniques[e] = o
            elif t == "x-mitre-tactic" and _ext(o) and o.get("x_mitre_shortname"):
                idx.tactic_by_shortname[o["x_mitre_shortname"]] = _ext(o)
                idx.tactic_names[_ext(o)] = o.get("name", "")
            elif t == "relationship" and o.get("relationship_type") == "revoked-by":
                idx.revoked_by[o["source_ref"]] = o["target_ref"]
        return idx

    def tactics_of(self, tech: str) -> List[str]:
        o = self.techniques.get(tech)
        out: List[str] = []
        for ph in (o or {}).get("kill_chain_phases", []) or []:
            ta = self.tactic_by_shortname.get(ph.get("phase_name", ""))
            if ta and ta not in out:
                out.append(ta)
        return out


@lru_cache(maxsize=None)
def _index_cached(raw: str, key: str) -> Index:
    with open(f"{raw}/attack/{BUNDLES[key]}", encoding="utf-8") as f:
        return Index.build(json.load(f), "mobile" if key.startswith("mobile") else "enterprise")


def index(cfg: Dict, key: str = "enterprise_18_1") -> Index:
    """Index of one bundle (enterprise_18_1, mobile_18_1); fetched by `aitp fetch`."""
    return _index_cached(str(C.path(cfg, "raw")), key)


def _follow(idx: Index, tid: str) -> Tuple[str, List[str]]:
    chain, obj, seen = [tid], idx.techniques[tid], set()
    while obj.get("revoked"):
        tgt = idx.revoked_by.get(obj["id"])
        if tgt is None or tgt in seen:
            break
        seen.add(tgt)
        e = idx.stix_to_ext.get(tgt)
        if e is None or e not in idx.techniques:
            break
        chain.append(e)
        obj = idx.techniques[e]
    return chain[-1], chain


def map_technique(raw: str, ent: Index, mob: Optional[Index] = None, collapse: bool = True) -> Tuple[Optional[str], Optional[str], str]:
    """(mapped ID or None, domain, action) for one raw technique ID."""
    tid = str(raw).strip().upper()
    if not TECH_RE.match(tid):
        return None, None, "dropped_invalid"
    for idx in (ent, mob):
        if idx is None or tid not in idx.techniques:
            continue
        cur, chain = _follow(idx, tid)
        obj = idx.techniques[cur]
        if obj.get("revoked"):
            return None, idx.domain, "dropped_unmapped"
        if obj.get("x_mitre_deprecated"):
            parent = cur.split(".", 1)[0]
            p = idx.techniques.get(parent)
            if parent != cur and p is not None and not _dead(p):
                return parent, idx.domain, "deprecated_sub_collapsed"
            return None, idx.domain, "dropped_deprecated"
        out = cur.split(".", 1)[0] if collapse else cur
        if out != cur and idx.techniques.get(out, {}).get("revoked"):
            out, _ = _follow(idx, out)
        remapped, collapsed = cur != tid, out != cur
        action = {(False, False): "unchanged", (True, False): "remapped", (False, True): "collapsed",
                  (True, True): "remapped+collapsed"}[(remapped, collapsed)]
        return out, idx.domain, action
    return None, None, "dropped_unmapped"


def mapping(cfg: Dict, ids: Iterable[str], collapse: bool = True) -> pd.DataFrame:
    """One row per distinct raw ID: mapped ID (v18.1), domain, action."""
    ent = index(cfg, "enterprise_18_1")
    mob = index(cfg, "mobile_18_1") if cfg["attack"]["keep_mobile"] else None
    rows = []
    for raw in sorted({str(i).strip().upper() for i in ids if str(i).strip()}):
        m, d, a = map_technique(raw, ent, mob, collapse)
        rows.append({"original_id": raw, "mapped_id": m, "domain": d, "action": a})
    return pd.DataFrame(rows, columns=["original_id", "mapped_id", "domain", "action"])


def tactics_for(cfg: Dict, tech: str) -> List[str]:
    """Enterprise tactics of a v18.1 technique (empty for Mobile techniques)."""
    return index(cfg, "enterprise_18_1").tactics_of(tech)


def tactics_any(cfg: Dict, tech: str) -> List[str]:
    """Enterprise tactics of a technique; for a Mobile technique, the Enterprise tactics with the same
    names as its Mobile tactics (e.g. Mobile Defense Evasion -> TA0005)."""
    ent = tactics_for(cfg, tech)
    if ent:
        return ent
    mob = index(cfg, "mobile_18_1")
    by_name = {n: t for t, n in tactic_names(cfg).items()}
    return [by_name[mob.tactic_names[x]] for x in mob.tactics_of(tech) if mob.tactic_names.get(x) in by_name]


def tactic_names(cfg: Dict) -> Dict[str, str]:
    """Tactic ID -> name in Enterprise v18.1."""
    return index(cfg, "enterprise_18_1").tactic_names


def technique_names(cfg: Dict) -> Dict[str, str]:
    """v18.1 technique ID -> name (Enterprise over Mobile)."""
    out = {t: o.get("name", "") for t, o in index(cfg, "mobile_18_1").techniques.items()}
    out.update({t: o.get("name", "") for t, o in index(cfg, "enterprise_18_1").techniques.items()})
    return out


def software_techniques(cfg: Dict, bundle_file: str, software_id: str) -> Tuple[str, Set[str]]:
    """Name and parent technique IDs that one ATT&CK software entry 'uses' in a bundle (e.g. S9035 in v19.2).

    Revoked or deprecated relationships and techniques are skipped; sub-techniques collapse to their parent."""
    with open(C.path(cfg, "raw", "attack") / bundle_file, encoding="utf-8") as f:
        objs = json.load(f)["objects"]
    by_id = {o["id"]: o for o in objs}
    sw = next(o for o in objs if o.get("type") in ("malware", "tool") and _ext(o) == software_id and not _dead(o))
    out = set()
    for r in objs:
        if r.get("type") == "relationship" and r.get("relationship_type") == "uses" and r.get("source_ref") == sw["id"] \
                and not _dead(r):
            t = by_id.get(r["target_ref"])
            if t and t.get("type") == "attack-pattern" and not _dead(t):
                out.add(_ext(t).split(".")[0])
    return sw["name"], out
