"""Fetchers for public, real-world prompt-injection corpora.

We do NOT vendor large or license-encumbered datasets into the repo. Instead we
record each source with its citation and license and fetch on demand into
`data/corpora/cache/` (git-ignored). Using real, adversarially-authored
injections that the author did not write is a stronger evaluation than synthetic
payloads alone.

Every entry lists: name, URL, license, and how it maps onto a TokenTaint
`Scenario` (which span is untrusted, which sink it targets). If a download
fails (offline / moved), the loader degrades to the bundled synthetic generator
and says so -- the benchmark still runs end to end.

NOTE: verify each license before redistribution. Fetching is opt-in via
`--download`; nothing is downloaded automatically on import.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.request

CACHE = os.path.join(os.path.dirname(__file__), "cache")

# Curated list of well-known public sources. URLs are intentionally the project
# landing pages / raw dataset endpoints; confirm availability + license at use
# time. These are references, not a redistribution.
SOURCES = [
    {
        "name": "deepset/prompt-injections",
        "kind": "huggingface",
        "url": "https://huggingface.co/datasets/deepset/prompt-injections",
        "license": "Apache-2.0 (verify on dataset card)",
        "notes": "Labeled benign vs. injection prompts; maps to WEB_FETCH spans.",
    },
    {
        "name": "jailbreak/prompt-injection-payloads",
        "kind": "reference",
        "url": "https://github.com/topics/prompt-injection",
        "license": "per-repo (verify)",
        "notes": "Collections of adversarial payloads for indirect injection.",
    },
    {
        "name": "InjecAgent-style agent traces",
        "kind": "reference",
        "url": "https://arxiv.org/abs/2403.02691",
        "license": "see paper / associated repo",
        "notes": "Benchmark of indirect prompt injection against tool-use agents.",
    },
    {
        "name": "AgentDojo",
        "kind": "reference",
        "url": "https://github.com/ethz-spylab/agentdojo",
        "license": "see repo",
        "notes": "Dynamic environment for evaluating agent prompt-injection defenses.",
    },
]


def list_sources() -> None:
    for s in SOURCES:
        print(f"- {s['name']}  [{s['license']}]\n    {s['url']}\n    {s['notes']}")


def try_download(name: str) -> str | None:
    os.makedirs(CACHE, exist_ok=True)
    src = next((s for s in SOURCES if s["name"] == name), None)
    if not src:
        print(f"unknown source '{name}'")
        return None
    dest = os.path.join(CACHE, name.replace("/", "__") + ".json")
    try:
        req = urllib.request.Request(src["url"], headers={"User-Agent": "TokenTaint"})
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
            data = r.read().decode("utf-8", errors="replace")
        with open(dest, "w") as f:
            json.dump({"source": src, "raw": data[:200000]}, f)
        print(f"cached -> {dest}")
        return dest
    except Exception as e:  # noqa: BLE001
        print(f"[offline/failed] {name}: {e}\n  -> falling back to synthetic generator.")
        return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="list known corpora + licenses")
    ap.add_argument("--download", metavar="NAME", help="attempt to cache one source")
    args = ap.parse_args()
    if args.download:
        try_download(args.download)
    else:
        list_sources()
