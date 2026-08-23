# Contributing to TokenTaint

Thanks for your interest. TokenTaint is a research/defensive-security project;
contributions that strengthen the security guarantee or the honesty of the
evaluation are especially welcome.

## Ground rules

- **Defensive use only.** The scenario generators exist to test the author's own
  harness. Do not contribute payloads or tooling intended to attack third-party
  systems. See [`SECURITY.md`](SECURITY.md).
- **Keep the core dependency-free.** `src/tokentaint/` must run on the standard
  library alone. Put anything heavier behind an optional extra.
- **Reproducibility is non-negotiable.** Any change to behavior must keep
  `make repro` deterministic and update `results/` + `docs/figures/` in the same
  PR.

## Development setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make test        # unit tests
make repro       # regenerate results, figures, tables
```

## What makes a good contribution

- **New propagation strategy** — subclass `Propagation`, register it in
  `propagation.STRATEGIES`, and add it to the evaluation so it appears in the
  head-to-head charts.
- **New attack style / laundering class** — extend the injection generator with
  ground-truth labels; if it defeats a strategy the docs claim is safe, that is a
  valuable *finding*, not a bug to hide — document it in the threat model.
- **Real-corpus adapters** — map a public injection dataset into `Scenario`
  objects via `data/corpora/`, with license noted. Do not vendor large datasets.
- **Integration adapters** — wire the `Firewall` into a real agent framework.

## Pull request checklist

- [ ] `make test` passes
- [ ] `make repro` runs clean and regenerated artifacts are committed
- [ ] New behavior has a unit test
- [ ] Docs updated (README / `docs/`) if behavior or guarantees changed
- [ ] No new runtime dependency in `src/tokentaint/`

## Reporting guard bypasses

A way to defeat the sink guard, forge provenance, or launder taint beyond what
`docs/threat_model.md` documents is a **security report** — please follow the
private disclosure process in [`SECURITY.md`](SECURITY.md) rather than opening a
public issue.
