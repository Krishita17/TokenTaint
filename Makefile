.PHONY: help install eval figures tables repro test demo clean

help:
	@echo "TokenTaint — make targets"
	@echo "  install   create venv + install deps (matplotlib, pytest)"
	@echo "  eval      run the benchmark -> results/*.json"
	@echo "  figures   render docs/figures/*.png from results/"
	@echo "  tables    render results/tables.md from results/"
	@echo "  repro     eval + figures + tables (full reproduction)"
	@echo "  test      run the unit test suite"
	@echo "  demo      run the quickstart example"
	@echo "  clean     remove caches and generated artifacts"

install:
	python3 -m venv .venv
	./.venv/bin/pip install -U pip
	./.venv/bin/pip install -e ".[dev]"

eval:
	python3 experiments/run_eval.py

figures:
	python3 experiments/make_figures.py

tables:
	python3 experiments/make_tables.py

repro: eval figures tables
	@echo "Reproduction complete: results/ and docs/figures/ refreshed."

test:
	python3 -m pytest -q

demo:
	python3 examples/quickstart.py

clean:
	rm -rf __pycache__ */__pycache__ */*/__pycache__ .pytest_cache *.egg-info src/*.egg-info
	rm -rf data/corpora/cache
