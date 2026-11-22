"""The analysis data: labelled samples, analysis units and prevalence matrices, per analysis variant.

Definitions
  * A sample is labelled if it has at least one v18.1 technique (after the merge rule).
  * Units: each AI-assisted family (data/hashes/ai_assisted.csv, ``analysis_unit``) and each
    conventional family marked ``family_included`` in data/labels/conventional_families.csv. A unit
    enters family-level analyses with at least ``min_labelled_per_unit`` labelled samples.
  * Sample-level analyses use every labelled AI-assisted sample of an included unit and every
    labelled conventional sample, whatever its family.
  * A unit's prevalence vector holds, for each technique, the share of its labelled samples showing it.
  * Every analysis uses samples of all platforms. A sample's techniques are the union over all engines
    that analysed it (aitp.extract).
"""

from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from aitp import config as C

AI, CTL = "AI", "control"


@dataclass(frozen=True)
class Variant:
    """One set of analysis choices: the main analysis, or a sensitivity check derived from it."""
    name: str = "all_platforms"
    drop_units: Tuple[str, ...] = ()     # AI units left out
    level: str = "default"               # default | switched (sample <-> family level)
    granularity: str = "parent"          # parent | sub

    def but(self, **kw) -> "Variant":
        return replace(self, **kw)


# Offset of the analysis's random streams (rq2, rq3, rq5 rarefaction, llm). It is the slot the
# all-platform analysis has always used, so the manuscript's values reproduce exactly.
SEED_SLOT = 1


def analysis(cfg: Dict) -> Variant:
    """The analysis: every platform, every AI unit except ``exclude_ai_units``."""
    return Variant(drop_units=tuple(cfg.get("exclude_ai_units") or ()))


@dataclass
class Dataset:
    variant: Variant
    samples: pd.DataFrame      # labelled samples kept by the variant (one row per sample)
    st: pd.DataFrame           # sample_id, technique
    prev: pd.DataFrame         # units x techniques prevalence
    n_lab: pd.Series           # labelled samples per unit
    unit_set: pd.Series        # unit -> AI | control
    unit_actor: pd.Series      # unit -> actor(s) ("" for AI)

    def units(self, which: str) -> List[str]:
        return [u for u in self.prev.index if self.unit_set[u] == which]

    def sample_sets(self, mask: Optional[pd.Series] = None) -> Dict[str, set]:
        s = self.samples if mask is None else self.samples[mask]
        g = self.st[self.st["sample_id"].isin(s["sample_id"])].groupby("sample_id")["technique"].apply(set)
        return g.to_dict()


def display(unit: str) -> str:
    """'AI:LameHug' -> 'LameHug'."""
    return unit.split(":", 1)[1] if ":" in unit else unit


@lru_cache(maxsize=None)
def _read(path: str) -> pd.DataFrame:
    return pd.read_csv(path, keep_default_na=False, na_values=[""])


def derived(cfg: Dict, name: str) -> pd.DataFrame:
    """A table written by `aitp extract` (copy)."""
    return _read(str(C.path(cfg, "derived", f"{name}.csv"))).copy()


def prevalence_matrix(st: pd.DataFrame, unit_of: Dict[str, str]) -> Tuple[pd.DataFrame, pd.Series]:
    """Units x techniques prevalence matrix and labelled samples per unit."""
    st = st[st["sample_id"].isin(unit_of.keys())].drop_duplicates(["sample_id", "technique"]).copy()
    st["unit"] = st["sample_id"].map(unit_of)
    n_lab = st.groupby("unit")["sample_id"].nunique()
    prev = st.groupby(["unit", "technique"])["sample_id"].nunique().unstack(fill_value=0).div(n_lab, axis=0)
    prev = prev.reindex(columns=sorted(prev.columns), fill_value=0.0).sort_index()
    return prev, n_lab.reindex(prev.index)


def load(cfg: Dict, v: Variant) -> Dataset:
    """Labelled samples, units and prevalence matrix under the variant's choices."""
    samples = derived(cfg, "samples")
    st = derived(cfg, "sample_techniques_sub" if v.granularity == "sub" else "sample_techniques")
    st = st[["sample_id", "technique"]]
    samples = samples[samples["sample_id"].isin(set(st["sample_id"]))].copy()

    fams = pd.read_csv(C.path(cfg, "conventional_families"), keep_default_na=False, na_values=[""])
    included = dict(zip(fams["sample_id"], fams["family"].where(fams["family_included"].astype(str).str.lower() == "true")))
    is_ai = samples["set"] == AI
    samples["unit"] = None
    samples.loc[is_ai, "unit"] = samples.loc[is_ai, "family"].map(
        lambda f: None if f in v.drop_units else f"AI:{f}")
    samples.loc[~is_ai, "unit"] = samples.loc[~is_ai, "sample_id"].map(
        lambda s: f"CTL:{included[s]}" if isinstance(included.get(s), str) else None)
    samples = samples[~is_ai | samples["unit"].notna()].reset_index(drop=True)

    fam = samples[samples["unit"].notna()]
    counts = fam.groupby("unit")["sample_id"].nunique()
    kept = set(counts[counts >= int(cfg["min_labelled_per_unit"])].index)
    unit_of = {s: u for s, u in zip(fam["sample_id"], fam["unit"]) if u in kept}
    st = st[st["sample_id"].isin(samples["sample_id"])][["sample_id", "technique"]].drop_duplicates()
    prev, n_lab = prevalence_matrix(st, unit_of)
    unit_set = pd.Series({u: (AI if u.startswith("AI:") else CTL) for u in prev.index}, dtype=object)
    unit_actor = pd.Series({u: ("" if u.startswith("AI:") else
                                "|".join(sorted(set(fam.loc[fam["unit"] == u, "actor"])))) for u in prev.index}, dtype=object)
    return Dataset(v, samples, st.reset_index(drop=True), prev, n_lab, unit_set, unit_actor)


def case_study_sets(cfg: Dict, ds: Dataset) -> Dict[str, Dict]:
    """Per actor: technique sets of its AI-assisted family's samples and of its conventional samples."""
    sets = ds.sample_sets()
    out = {}
    for actor, family in cfg["case_studies"].items():
        ai_ids = ds.samples.loc[(ds.samples["set"] == AI) & (ds.samples["unit"] == f"AI:{family}"), "sample_id"]
        ctl_ids = ds.samples.loc[(ds.samples["set"] == CTL) & (ds.samples["actor"] == actor), "sample_id"]
        out[actor] = {"ai_family": family, "ai": {s: sets[s] for s in ai_ids if s in sets},
                      "control": {s: sets[s] for s in ctl_ids if s in sets}}
    return out
