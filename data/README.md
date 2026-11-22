# Data

Only hashes, our own labels, and small published inputs are shipped. VirusTotal reports are not
redistributed: `python -m aitp fetch` downloads them by hash with your own API key, and
`python -m aitp extract` turns them into the tables in `derived/`.

| Path | Contents | Source |
|---|---|---|
| `hashes/ai_assisted.csv` | 154 in-the-wild AI-assisted malware files, with family (`family`, `analysis_unit`) | public reports |
| `hashes/apt28_conventional.csv` | 283 files attributed to APT28 | threat-intelligence reports |
| `hashes/apt36_conventional.csv` | 486 files attributed to APT36 | threat-intelligence reports |
| `hashes/with_fixed/` | the same three lists plus 2 AI-assisted files whose hashes were corrected after the study (156 AI-assisted); not used by default | this package, VirusTotal reports of 13 November 2026 |
| `hashes/hash_changes.csv` | every published entry that was converted to SHA-256 or removed (duplicate or malformed) | this package |
| `labels/conventional_families.csv` | family of each conventional sample (keyed by SHA-256) and whether the family is an analysis unit | ClarAVy run on the samples' antivirus labels, family names merged with ATT&CK software names and aliases |
| `published/external_top10s.json` | the five published top-10 technique lists (Picus, Mandiant, Red Canary, MITRE CTID, Saccone et al.) | the cited reports |
| `published/anthropic_tactic_shares.json` | tactic shares of Anthropic's banned-account activity | Anthropic, LLM ATT&CK Navigator |
| `published/mbc_objective_behaviours.json` | MBC behaviour names (used for labels only) | MITRE Malware Behavior Catalog |
| `published/attack_manifest.csv` | URL and SHA-256 of each ATT&CK STIX bundle | github.com/mitre-attack/attack-stix-data |

Notes on the hash lists
- The three lists in `hashes/` hold the samples of the study, whose reports were collected 18–25 March 2026, one entry per file. Every hash VirusTotal resolved is given as the file's SHA-256: the sources published some files as MD5 or SHA-1, and some under two hash forms (77 entries converted, 11 duplicates removed: 10 APT36, 1 APT28).
- Five published values were malformed and are removed: four SHA-256 values truncated to 63 characters (Koske Malware `29393520…`, FunkSec `dd15ce86…`, APT28 `be859b4f…` and `a876f648…`) and an APT36 SHA-1 with the letter "o" in place of a zero. VirusTotal resolved none of them, so no analysed sample is lost. The APT36 SHA-1, corrected, is a file already in the list; APT28 `a876f648…` is likely a mistyped copy of a listed file.
- 57 entries are MD5 or SHA-1 because VirusTotal did not know the file in March: 33 AI-assisted MD5s (31 Vibeware, 2 ATOMIC), 11 MD5s and 7 SHA-1s for APT28, and 6 MD5s for APT36. They are kept as published. Re-fetching may now find some of them, which changes the results.
- `hash_changes.csv` maps every converted or removed entry back to the hash as published (line numbers refer to the published lists).
- `with_fixed/` adds the full SHA-256 of the Koske Malware and FunkSec files, found in November 2026 together with their reports. They are not in the study's analyses, because reports collected eight months later would mix two collection dates, and VirusTotal sandboxes change over time. To analyse this set, point `paths.hashes` in `config.yaml` at `data/hashes/with_fixed/` and run `fetch`.

Created by `aitp` (not shipped, git-ignored): `raw/` (VirusTotal responses and ATT&CK bundles) and `derived/` (tables built from them).
