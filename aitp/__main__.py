"""Command line: python -m aitp <stage> [--raw-dir DIR]

Stages
  fetch         download ATT&CK bundles and VirusTotal reports (needs VT_API_KEY)
  extract       build data/derived/ from the fetched reports
  descriptives  Tables 4-8 (coverage, top-10 techniques and MBC behaviours, overlap with the
                published lists; RQ1), counts
  rq2 ... rq7   one research question each
  controls      without HONESTCUE, leave-one-family-out, per-format and per-platform composition
  llm           LLM-dependent behaviour
  release       sample manifest, technique matrices, provenance checks
  all           every stage after extract, in order
"""

import argparse
import importlib
import time

from aitp import config as C

STAGES = {"fetch": "aitp.fetch", "extract": "aitp.extract", "descriptives": "aitp.descriptives",
          "rq2": "aitp.rq2_techniques", "rq3": "aitp.rq3_novelty",
          "rq4": "aitp.rq4_similarity", "rq5": "aitp.rq5_case_studies", "llm": "aitp.llm_dependence",
          "controls": "aitp.controls", "rq6": "aitp.rq6_css", "rq7": "aitp.rq7_anthropic",
          "release": "aitp.release"}
ALL = ["descriptives", "rq2", "rq3", "controls", "rq4", "rq5", "llm", "rq6", "rq7", "release"]


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m aitp", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stages", nargs="+", choices=list(STAGES) + ["all"])
    ap.add_argument("--raw-dir", help="folder with vt-general/, vt-behaviour/ and attack/ (default data/raw)")
    args = ap.parse_args()
    cfg = C.load(raw_dir=args.raw_dir)
    todo = [s for a in args.stages for s in (ALL if a == "all" else [a])]
    for s in todo:
        t0 = time.perf_counter()
        print(f"== {s}")
        importlib.import_module(STAGES[s]).run(cfg)
        print(f"   done in {time.perf_counter() - t0:.1f}s")


if __name__ == "__main__":
    main()
