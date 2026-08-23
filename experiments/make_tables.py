"""Generate Markdown result tables from results/*.json into results/tables.md.

Tables:
  - Headline results (prevention, false-block, prevention|attempted) per defense
  - Prevention rate per injection style per defense
These are embedded into the README.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")

LABEL = {"no_defense": "No defense", "classifier": "Classifier baseline",
         "tokentaint_structural": "TokenTaint (structural)",
         "tokentaint_attribution": "TokenTaint (attribution)"}
STYLES = ["direct", "indirect", "obfuscated", "laundered"]


def _load(name):
    with open(os.path.join(RESULTS, name)) as f:
        return json.load(f)


def headline(summary) -> str:
    rows = ["| Defense | Attack prevention ↑ | False-block rate ↓ | Prevention \\| attempted ↑ |",
            "|---|---|---|---|"]
    for name, m in summary.items():
        rows.append(f"| {LABEL[name]} | {m['attack_prevention_rate']:.3f} | "
                    f"{m['false_block_rate']:.3f} | {m['prevention_given_attempted']:.3f} |")
    return "\n".join(rows)


def by_style(bs) -> str:
    header = "| Defense | " + " | ".join(s.capitalize() for s in STYLES) + " |"
    sep = "|---|" + "---|" * len(STYLES)
    rows = [header, sep]
    for name, d in bs.items():
        rows.append(f"| {LABEL[name]} | " + " | ".join(f"{d[s]:.2f}" for s in STYLES) + " |")
    return "\n".join(rows)


def laundering(l) -> str:
    rows = ["| Laundering effort | " + " | ".join(str(e) for e in l["effort"]) + " |",
            "|---|" + "---|" * len(l["effort"]),
            "| Structural | " + " | ".join(f"{v:.2f}" for v in l["structural"]) + " |",
            "| Attribution | " + " | ".join(f"{v:.2f}" for v in l["attribution"]) + " |"]
    return "\n".join(rows)


def main():
    summary = _load("summary.json")
    out = ["# TokenTaint results (auto-generated)\n",
           "## Headline: security vs. utility\n", headline(summary), "",
           "## Attack-prevention rate by injection style\n", by_style(_load("by_style.json")), "",
           "## Tier-3: prevention vs. laundering effort\n", laundering(_load("laundering.json")), ""]
    md = "\n".join(out)
    with open(os.path.join(RESULTS, "tables.md"), "w") as f:
        f.write(md)
    print(md)
    print(f"\nwrote -> {os.path.join(os.path.abspath(RESULTS), 'tables.md')}")


if __name__ == "__main__":
    main()
