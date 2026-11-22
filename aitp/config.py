"""Configuration: load config.yaml and resolve paths relative to the artefact root."""

from pathlib import Path
from typing import Any, Dict, Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(path: Optional[Path] = None, raw_dir: Optional[str] = None) -> Dict[str, Any]:
    """Read config.yaml. ``raw_dir`` overrides paths.raw (a folder holding vt-general/ and vt-behaviour/)."""
    with open(path or ROOT / "config.yaml", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if raw_dir:
        cfg["paths"]["raw"] = str(Path(raw_dir).resolve())
    return cfg


def path(cfg: Dict, key: str, *parts: str) -> Path:
    """Absolute path of cfg['paths'][key] (nested keys separated by '.'), joined with ``parts``."""
    node: Any = cfg["paths"]
    for k in key.split("."):
        node = node[k]
    p = Path(node)
    return (p if p.is_absolute() else ROOT / p).joinpath(*parts)


def tables_dir(cfg: Dict) -> Path:
    d = path(cfg, "outputs", "tables")
    d.mkdir(parents=True, exist_ok=True)
    return d


def figures_dir(cfg: Dict) -> Path:
    d = path(cfg, "outputs", "figures")
    d.mkdir(parents=True, exist_ok=True)
    return d


def derived_dir(cfg: Dict) -> Path:
    d = path(cfg, "derived")
    d.mkdir(parents=True, exist_ok=True)
    return d


def write(cfg: Dict, df, name: str) -> Path:
    """Write a DataFrame to outputs/tables/<name>.csv."""
    p = tables_dir(cfg) / f"{name}.csv"
    df.to_csv(p, index=False)
    return p


def write_json(cfg: Dict, obj, name: str) -> Path:
    """Write a JSON-serialisable object to outputs/tables/<name>.json."""
    import json
    p = tables_dir(cfg) / f"{name}.json"
    p.write_text(json.dumps(obj, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o)), encoding="utf-8")
    return p
