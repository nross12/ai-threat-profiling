"""Download the inputs that cannot be shipped: VirusTotal reports (by hash) and ATT&CK bundles.

VirusTotal: for every listed hash, ``GET /files/{hash}`` is saved to data/raw/vt-general/{hash}.json
and ``GET /files/{hash}/behaviours`` to data/raw/vt-behaviour/{hash}.json. A hash VirusTotal does not
know is saved as its error response, which `extract` treats as "not on VirusTotal". Existing files are
kept, so an interrupted run can be resumed. Reports change as VirusTotal re-analyses files, so a new
download gives results close to, but not identical with, our reports (retrieved
18-25 March 2026).

ATT&CK: the STIX bundles listed in data/published/attack_manifest.csv are downloaded from
github.com/mitre-attack/attack-stix-data and checked against their SHA-256.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Iterable, List

import pandas as pd
import requests

from aitp import config as C


def listed_hashes(cfg: Dict) -> List[str]:
    """Every listed hash (AI-assisted and both conventional lists), lower-cased, in file order."""
    out: List[str] = []
    for key in ("ai", "APT28", "APT36"):
        for h in pd.read_csv(C.path(cfg, f"hashes.{key}"))["listed_hash"]:
            h = str(h).strip().lower()
            if h and h not in out:
                out.append(h)
    return out


def _get(session: requests.Session, url: str, key: str) -> Dict:
    r = session.get(url, headers={"x-apikey": key}, timeout=120)
    if r.status_code == 429:
        raise RuntimeError("VirusTotal quota exceeded; re-run later (finished files are kept)")
    return r.json()


def virustotal(cfg: Dict, hashes: Iterable[str]) -> None:
    """Download general and behaviour reports for ``hashes`` (needs the API key in the environment)."""
    key = os.environ.get(cfg["virustotal"]["api_key_env"])
    if not key:
        raise SystemExit(f"Set {cfg['virustotal']['api_key_env']} to a VirusTotal API key.")
    base = cfg["virustotal"]["api_url"]
    wait = 60.0 / float(cfg["virustotal"]["requests_per_minute"])
    gen, beh = C.path(cfg, "raw", "vt-general"), C.path(cfg, "raw", "vt-behaviour")
    gen.mkdir(parents=True, exist_ok=True)
    beh.mkdir(parents=True, exist_ok=True)
    with requests.Session() as s:
        for i, h in enumerate(hashes, 1):
            for folder, url in ((gen, f"{base}/files/{h}"), (beh, f"{base}/files/{h}/behaviours")):
                out = folder / f"{h}.json"
                if out.exists():
                    continue
                out.write_text(json.dumps(_get(s, url, key)), encoding="utf-8")
                time.sleep(wait)
            print(f"  [{i}] {h}")


def attack_bundles(cfg: Dict) -> None:
    """Download and checksum-verify the ATT&CK bundles of the manifest."""
    out_dir = C.path(cfg, "raw", "attack")
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in pd.read_csv(C.path(cfg, "attack_manifest")).itertuples():
        p = out_dir / r.file
        if not p.exists():
            print(f"  downloading {r.url}")
            p.write_bytes(requests.get(r.url, timeout=300).content)
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        if digest != r.sha256:
            raise SystemExit(f"{p.name}: SHA-256 {digest} does not match the manifest ({r.sha256})")
    print("  ATT&CK bundles verified")


def run(cfg: Dict) -> None:
    attack_bundles(cfg)
    hashes = listed_hashes(cfg)
    print(f"  {len(hashes)} listed hashes")
    virustotal(cfg, hashes)
