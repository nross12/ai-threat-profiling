"""Figure style; every figure is saved as PDF and PNG in outputs/figures/."""

import os
from typing import Dict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from aitp import config as C  # noqa: E402

AI_COLOUR, CONV_COLOUR, NEUTRAL = "#dc2626", "#2563eb", "#9ca3af"
STYLE = {"font.family": "sans-serif", "font.size": 10, "pdf.fonttype": 42, "ps.fonttype": 42,
         "axes.spines.top": False, "axes.spines.right": False}


def style() -> None:
    plt.rcdefaults()
    plt.rcParams.update(STYLE)


def save(cfg: Dict, fig, stem: str) -> None:
    os.environ.setdefault("SOURCE_DATE_EPOCH", "1791763200")   # reproducible PDF metadata
    for ext in ("pdf", "png"):
        fig.savefig(C.figures_dir(cfg) / f"{stem}.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
