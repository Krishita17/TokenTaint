"""Generate all figures from results/*.json into docs/figures/.

Figures:
  fig1_prevention_vs_falseblock.png  headline ROC-style scatter (per defense)
  fig2_prevention_by_style.png       grouped bars, prevention per injection style
  fig3_propagation_compare.png       structural vs attribution, per style + FBR
  fig4_laundering.png                Tier-3: prevention vs laundering effort

All figures are code-generated and reproducible. Requires matplotlib
(`pip install -r requirements.txt`). Run `python experiments/run_eval.py` first.
"""
from __future__ import annotations

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")
FIGS = os.path.join(HERE, "..", "docs", "figures")

# colorblind-safe palette
C = {"no_defense": "#8c8c8c", "classifier": "#d55e00",
     "tokentaint_structural": "#0072b2", "tokentaint_attribution": "#009e73"}
LABEL = {"no_defense": "No defense", "classifier": "Classifier baseline",
         "tokentaint_structural": "TokenTaint (structural)",
         "tokentaint_attribution": "TokenTaint (attribution)"}


def _load(name):
    with open(os.path.join(RESULTS, name)) as f:
        return json.load(f)


def fig1(summary):
    fig, ax = plt.subplots(figsize=(7, 5.5))
    for name, m in summary.items():
        ax.scatter(m["false_block_rate"], m["attack_prevention_rate"],
                   s=220, color=C[name], edgecolor="black", zorder=3, label=LABEL[name])
        ax.annotate(LABEL[name], (m["false_block_rate"], m["attack_prevention_rate"]),
                    textcoords="offset points", xytext=(10, -4), fontsize=9)
    ax.set_xlabel("False-block rate on benign tasks  (lower is better) →", fontsize=11)
    ax.set_ylabel("Attack-prevention rate  (higher is better) →", fontsize=11)
    ax.set_title("TokenTaint vs. baselines: security vs. utility", fontsize=13, weight="bold")
    ax.axhspan(0.9, 1.02, xmin=0, xmax=0.25, color="#e6f4ea", zorder=0)
    ax.text(0.005, 0.955, "ideal region", fontsize=9, color="#2e7d32")
    ax.set_xlim(-0.02, max(0.3, max(m["false_block_rate"] for m in summary.values()) + 0.05))
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGS, "fig1_prevention_vs_falseblock.png"), dpi=150)
    plt.close(fig)


def fig2(by_style):
    styles = ["direct", "indirect", "obfuscated", "laundered"]
    names = list(by_style.keys())
    x = range(len(styles))
    w = 0.2
    fig, ax = plt.subplots(figsize=(9, 5))
    for i, name in enumerate(names):
        vals = [by_style[name][s] for s in styles]
        ax.bar([xx + i * w for xx in x], vals, w, color=C[name], label=LABEL[name],
               edgecolor="black", linewidth=0.4)
    ax.set_xticks([xx + 1.5 * w for xx in x])
    ax.set_xticklabels([s.capitalize() for s in styles])
    ax.set_ylabel("Attack-prevention rate")
    ax.set_ylim(0, 1.08)
    ax.set_title("Prevention rate by injection style", fontsize=13, weight="bold")
    ax.legend(fontsize=8, ncol=2)
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGS, "fig2_prevention_by_style.png"), dpi=150)
    plt.close(fig)


def fig3(prop):
    styles = ["direct", "indirect", "obfuscated", "laundered"]
    strat = ["tokentaint_structural", "tokentaint_attribution"]
    x = range(len(styles))
    w = 0.35
    fig, ax = plt.subplots(figsize=(8, 5))
    for i, name in enumerate(strat):
        vals = [prop[name][s] for s in styles]
        ax.bar([xx + i * w for xx in x], vals, w, color=C[name], label=LABEL[name],
               edgecolor="black", linewidth=0.4)
    ax.set_xticks([xx + 0.5 * w for xx in x])
    ax.set_xticklabels([s.capitalize() for s in styles])
    ax.set_ylabel("Attack-prevention rate")
    ax.set_ylim(0, 1.08)
    fbr = prop.get("_false_block", {})
    sub = "  |  false-block rate: " + ", ".join(
        f"{LABEL[k].split('(')[1][:-1]}={v:.2f}" for k, v in fbr.items())
    ax.set_title("Structural vs. attribution propagation" + sub, fontsize=11, weight="bold")
    ax.legend(fontsize=9)
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGS, "fig3_propagation_compare.png"), dpi=150)
    plt.close(fig)


def fig4(launder):
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(launder["effort"], launder["structural"], "-o", color=C["tokentaint_structural"],
            label="Structural", linewidth=2)
    ax.plot(launder["effort"], launder["attribution"], "-s", color=C["tokentaint_attribution"],
            label="Attribution", linewidth=2)
    ax.set_xlabel("Attacker laundering effort  (severing the provenance chain) →")
    ax.set_ylabel("Attack-prevention rate")
    ax.set_title("Tier-3: taint-laundering arms race", fontsize=13, weight="bold")
    ax.set_ylim(0, 1.08)
    ax.set_xticks(launder["effort"])
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.annotate("attribution degrades as the\ninstruction is laundered through\na trusted-looking transform",
                (2, launder["attribution"][2]), textcoords="offset points", xytext=(20, -50),
                fontsize=9, arrowprops=dict(arrowstyle="->", color="gray"))
    fig.tight_layout()
    fig.savefig(os.path.join(FIGS, "fig4_laundering.png"), dpi=150)
    plt.close(fig)


def main():
    os.makedirs(FIGS, exist_ok=True)
    summary = _load("summary.json")
    fig1(summary)
    fig2(_load("by_style.json"))
    fig3(_load("propagation.json"))
    fig4(_load("laundering.json"))
    print(f"wrote 4 figures -> {os.path.abspath(FIGS)}")


if __name__ == "__main__":
    main()
