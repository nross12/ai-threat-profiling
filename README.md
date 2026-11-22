# aitp: AI threat profiling

This project was made for our paper: paper: *AI-Augmented Threats in the Wild: TTP-Driven Behavioural Profiling using the MITRE ATT&CK Framework* and compares the tactics and techniques used in AI-assisted malware, comparative to conventional malware, published Top-10 ATT&CK reports, and accounts showing adversarial behaviour (We use Anthropic's mapping of AI-enabled cyber threats from their observed banned accounts). Starting from the listed hashes, `aitp` downloads the VirusTotal sandbox reports, maps their ATT&CK techniques to ATT&CK v18.1, and produces every table and figure of the results.

## Requirements

- Python 3.12 is what I used (any earlier/later versions may work, but are untested) and the packages in `requirements.txt` (`pip install -r requirements.txt`).
- A VirusTotal API key, in the environment variable `VT_API_KEY`. The download makes two requests per listed hash. At the public API's 4 requests per minute this takes about eight hours; set `virustotal.requests_per_minute` in `config.yaml` for a premium key.
- About 2 GB of disk for the reports.

## Running

```bash
pip install -r requirements.txt
export VT_API_KEY=...                 
python -m aitp fetch                  # ATT&CK bundles (checksum-verified, because why not) and VirusTotal reports
python -m aitp extract                # data/derived/ from the reports
python -m aitp all                    # every analysis; about 10 minutes on an 8-core laptop
python -m aitp rq5                    # or a single stage
python -m pytest tests                # unit tests (no data needed)
```

`fetch` keeps files it has already downloaded, so it can be re-run after an interruption. If you already hold the reports, point `--raw-dir` at a folder containing `vt-general/`, `vt-behaviour/`, and `attack/`, e.g. `python -m aitp extract all --raw-dir /path/to/raw`.

**Expect close, not identical, numbers.** VirusTotal re-analyses files and adds samples over time, so reports fetched today could differ from those we used (retrieved 18–25 March 2026). Every random draw is seeded (`config.yaml`), so a given set of reports always gives the same results.

## What each stage produces

All tables are in `outputs/tables/`, figures in `outputs/figures/`, release files in `outputs/release/`. Every analysis uses the samples of all platforms (Windows, Linux, Android, macOS, cross-platform
scripts).

## Analysis choices

All parameters are in `config.yaml`: seed, number of permutations (Mantel test) and rarefaction draws (RQ5) and technique subsets (RQ6), the ATT&CK version, the AI role of each family, the LLM endpoints, downstream markers and LLM-driven steps, the published ATT&CK software entries, and `exclude_ai_units` (e.g. `[AI Theater]` to drop a family
from every analysis).

## Layout

```
aitp/            the package (one module per stage)
data/            inputs (see data/README.md)
tests/           unit tests
config.yaml      parameters
```

# Citing us
If you use or add to this dataset in a project or publication, please reference our paper:
```
TO BE COMPLETED
```

## Licence

Code: see `LICENSE`. The hash lists and labels are released for research use; VirusTotal content is
not included and is subject to VirusTotal's terms.
