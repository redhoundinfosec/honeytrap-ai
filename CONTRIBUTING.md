# Contributing to HoneyTrap AI

Thanks for your interest in improving HoneyTrap AI! Contributions of all sizes are welcome — bug reports, new device profiles, protocol handlers, documentation, tests, and larger features.

## Ground rules

- Be respectful. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).
- Don't open issues that include real attack data from your honeypot without scrubbing PII.
- All contributions are MIT-licensed.

## Development setup

```bash
git clone https://github.com/redhoundinfosec/honeytrap-ai
cd honeytrap-ai
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev,full]"
```

## Running the tests

```bash
pytest                                                # default selection (no benchmarks)
pytest -m fuzz                                        # property-based fuzz tests
pytest -m benchmark --benchmark-only                  # performance benchmarks
pytest -m "not benchmark" --cov=src/honeytrap         # with coverage
```

The default test run excludes the `benchmark` marker and is what CI runs on
every PR. `pytest -m fuzz` runs the Hypothesis-based property tests; the
nightly workflow runs them with `HYPOTHESIS_PROFILE=ci` for a 500-example
budget.

## Lint and type checks

```bash
ruff check src tests
ruff format --check src tests
mypy src/honeytrap
codespell src/ tests/
```

## Local quality gates (pre-commit)

After installing the dev extras, register the hooks once:

```bash
pip install -e ".[dev]"
pre-commit install
```

Hooks then run automatically on every `git commit`. To run them across the
whole repo manually:

```bash
pre-commit run --all-files
```

The hook set covers ruff, ruff-format, mypy strict, codespell, end-of-file
fixes, trailing whitespace, large-file detection, private-key detection, and
YAML/TOML syntax checks.

## Adding a device profile

1. Copy `profiles/web_server.yaml` to `profiles/my_new_device.yaml`.
2. Edit services, banners, AI personality, and fake file system entries.
3. Add a test in `tests/` that loads the profile and validates the schema.
4. Open a PR with a short description of the device modeled.

## Adding a protocol handler

1. Subclass `honeytrap.protocols.base.ProtocolHandler`.
2. Implement `start()`, `stop()`, and the per-connection handler.
3. Wire it into `honeytrap.core.engine.Engine._build_handlers`.
4. Add unit tests under `tests/test_protocols.py`.
5. Document any new dependencies in `pyproject.toml` as an optional extra.

## Pull request checklist

- [ ] Passes `pre-commit run --all-files`.
- [ ] Passes `pytest -m "not benchmark" --cov=src/honeytrap` with coverage >= 90%.
- [ ] Passes `mypy src/honeytrap` (strict).
- [ ] Includes tests for new behavior where practical.
- [ ] Updates README if user-facing behavior changes.
- [ ] Uses type hints and docstrings throughout.
- [ ] No real attacker data committed.

## Commit messages

Use short, imperative subjects (≤ 72 chars), e.g.:

```
Add Telnet protocol handler with AI-enhanced shell

- Implements minimal Telnet negotiation
- Fake /etc/passwd, /etc/shadow, ls responses
- Falls back to rule engine if LLM fails
```

## Reporting bugs

Include:

- OS and Python version
- HoneyTrap AI version (`honeytrap --version`)
- Which profile was loaded
- Full traceback
- Reproduction steps

Thanks for helping make HoneyTrap AI better!
