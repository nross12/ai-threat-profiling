"""Unit tests for the parts of aitp that do not need fetched data (run: python -m pytest tests)."""

import numpy as np
import pandas as pd
import pytest

from aitp import attack as A
from aitp import extract as E
from aitp import rq2_techniques as R2
from aitp import stats as S


def test_prominence_delta_classification():
    # Table 10: PD = APS - CPS; CPS = 0 means absent from every published list
    assert R2.classify(10, 3) == "Higher in AI top-10"
    assert R2.classify(6, 0) == "Absent from external top-10s"
    assert R2.classify(7, 7) == "Parity"
    assert R2.classify(8, 13) == "Higher in external baselines"


def test_jaccard_and_pairwise():
    assert S.jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)
    m = pd.DataFrame([[1, 0.5, 0], [0, 1, 1]], index=["x", "y"], columns=list("abc"))
    assert S.pairwise(m, "jaccard").loc["x", "y"] == pytest.approx(1 / 3)
    assert S.pairwise(m, "cosine").loc["x", "y"] == pytest.approx(0.5 / (1.25 ** 0.5 * 2 ** 0.5))


def test_prevalence_ignores_unlabelled():
    prev, n = S.prevalence({"s1": {"T1"}, "s2": {"T1", "T2"}, "s3": set()})
    assert n == 2 and prev["T1"] == 1.0 and prev["T2"] == 0.5


@pytest.mark.parametrize("tt,mg,die,expected", [
    ("peexe", "PEBIN", [{"type": "Library", "name": ".NET"}], "pe_dotnet"),
    ("peexe", "PEBIN", [{"type": "Compiler", "name": "Microsoft Visual C/C++"}], "pe_native"),
    ("python", "PYTHON", [], "script"), ("docx", "DOCX", [], "document"),
    ("zip", "ZIP", [], "archive"), ("elf", "ELF", [], "elf"), ("android", "APK", [], "apk")])
def test_stratum(tt, mg, die, expected):
    assert E.stratum(tt, mg, die) == expected


def test_report_id_extraction_walks_nested_lists():
    rep = {"attributes": {"mitre_attack_techniques": [{"id": "t1055.001"}, {"id": "T1082"}],
                          "nested": {"mbc": [{"id": "B0001.012"}, {"name": "no id"}]}}}
    assert sorted(E._ids(rep, "mitre_attack_techniques")) == ["T1055.001", "T1082"]
    assert E._ids(rep, "mbc") == ["B0001.012"]


def _bundle():
    """A three-technique bundle: T1000 (live), T1000.001 (sub), T1999 revoked by T1000, T1888 deprecated."""
    tech = lambda i, sid, **kw: {"type": "attack-pattern", "id": sid, "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
        "external_references": [{"source_name": "mitre-attack", "external_id": i}], **kw}
    return {"objects": [
        tech("T1000", "ap--1"), tech("T1000.001", "ap--2"), tech("T1999", "ap--3", revoked=True),
        tech("T1888", "ap--4", x_mitre_deprecated=True),
        {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "ap--3", "target_ref": "ap--1"},
        {"type": "x-mitre-tactic", "x_mitre_shortname": "discovery",
         "external_references": [{"source_name": "mitre-attack", "external_id": "TA0007"}], "name": "Discovery"}]}


def test_mapping_rules():
    idx = A.Index.build(_bundle(), "enterprise")
    assert A.map_technique("T1000.001", idx)[0] == "T1000"
    assert A.map_technique("T1000.001", idx, collapse=False)[0] == "T1000.001"
    assert A.map_technique("T1999", idx)[:3:2] == ("T1000", "remapped")
    assert A.map_technique("T1888", idx)[2] == "dropped_deprecated"
    assert A.map_technique("T4242", idx)[2] == "dropped_unmapped"
    assert idx.tactics_of("T1000") == ["TA0007"]


def test_rq5_profile_counts_every_tactic_and_stage_once():
    from aitp import rq5_case_studies as R5
    tac = {"T1": ["TA0005", "TA0004"], "T2": ["TA0002"], "T3": []}.get
    val, n = R5.profile(tac, {"T1", "T2", "T3"})
    assert n == 2                                            # T3 has no tactic
    assert val[("tactic", "TA0005")] == pytest.approx(0.5)
    assert val[("kill_chain", "5-Installation")] == pytest.approx(0.5)   # TA0004 and TA0005: one stage, counted once
    assert val[("kill_chain", "4-Exploitation")] == pytest.approx(0.5)


def test_private_addresses_are_not_outbound_connections():
    assert all(E.PRIVATE.match(ip) for ip in ("10.0.0.5", "192.168.0.24", "172.20.1.1", "127.0.0.1"))
    assert not any(E.PRIVATE.match(ip) for ip in ("144.126.202.227", "172.32.0.1", "8.8.8.8"))


def test_jensen_shannon_divergence_bounds():
    from aitp import rq7_anthropic as R7
    same = R7.divergence({"a": {"TA0005": 3, "TA0007": 1}, "b": {"TA0005": 6, "TA0007": 2}})
    apart = R7.divergence({"a": {"TA0005": 1}, "b": {"TA0007": 1}})
    assert same["jensen_shannon_divergence"].abs().max() < 1e-12
    assert apart.loc[apart["scope"] == "all 14 tactics", "jensen_shannon_divergence"].iloc[0] == pytest.approx(1.0)


def test_rescaled_prominence_delta():
    # PD_mean = APS - CPS/5: T1071 at sample level (APS 9, CPS 13) changes sign
    assert 9 - 13 < 0 < 9 - 13 / 5
