# HoneyTrap AI — Test Suite

The test tree is split by purpose. Each subdirectory has a distinct
intent and is opted into / out of via pytest markers configured in
`pyproject.toml`.

## Layout

```
tests/
├── unit/         # default — fast deterministic tests (per-module)
├── fuzz/         # property-based fuzz tests (Hypothesis)
└── bench/        # micro-benchmarks (pytest-benchmark)
```

`tests/unit/` historically holds the bulk of the suite; subpackages
under it cover protocols, AI, API, forensics, intel, sinks, etc.

## Markers

Markers are registered in `pyproject.toml` under
`[tool.pytest.ini_options]`:

| Marker      | Meaning                                          | Default |
|-------------|--------------------------------------------------|---------|
| `fuzz`      | Hypothesis property-based fuzz tests             | ON      |
| `benchmark` | pytest-benchmark micro-benchmarks                | OFF     |
| `slow`      | Long-running tests (skip with `-m "not slow"`)   | ON      |
| `docker`    | Tests requiring a local Docker daemon            | ON      |

The default `pytest` invocation includes everything *except*
benchmarks (`addopts = "-m 'not benchmark'"`).

## Running

```sh
# Full default run (unit + fuzz, excludes bench).
pytest

# Just the fuzz suite.
pytest -m fuzz

# Skip fuzz (e.g., on slower CI legs).
pytest -m "not fuzz"

# Run all benchmarks; print stats only, no asserts on absolute time.
pytest tests/bench/ --benchmark-only

# Save a benchmark snapshot for later comparison.
pytest tests/bench/ --benchmark-only --benchmark-autosave

# Compare two saved snapshots.
pytest-benchmark compare 0001 0002

# Single file, single test.
pytest tests/fuzz/test_tls_clienthello_fuzz.py -k random_bytes
```

## Fuzz tests (`tests/fuzz/`)

Property-based tests using
[Hypothesis](https://hypothesis.readthedocs.io/). The contract for
every parser under fuzz is: **never raise an unhandled exception on
attacker-controlled input**.

- `test_tls_clienthello_fuzz.py` — TLS record + ClientHello parser,
  SNI handling, oversized handshake length.
- `test_rdp_tpkt_fuzz.py` — TPKT, X.224 Connection Request, NTLM
  NEGOTIATE_MESSAGE; CC-TPDU builder round-trip.
- `test_mqtt_fuzz.py` — CONNECT / SUBSCRIBE / PUBLISH parsers,
  variable-byte remaining-length round-trip, response builders.
- `test_coap_fuzz.py` — RFC 7252 message parser, build_response
  round-trip.
- `test_stix_roundtrip_fuzz.py` — STIX 2.1 bundle generation,
  validation, dedup.

`@settings(deadline=None, max_examples=100,
suppress_health_check=[HealthCheck.too_slow])` is used so that the
entire fuzz leg comfortably finishes in ~10 s on contemporary CPUs
without flakes.

## Benchmarks (`tests/bench/`)

Micro-benchmarks for hot paths. These are excluded from the default
run. See `tests/bench/README.md` for module-level coverage and
benchmark stability tips.

- `test_event_bus_bench.py` — async fan-out at multiple
  subscriber counts.
- `test_intent_classifier_bench.py` — one bench per `IntentLabel`
  (10 labels).
- `test_response_cache_bench.py` — LRU+TTL cache hit/miss/insert.
- `test_tls_fingerprint_bench.py` — parse-only, JA3+JA4, end-to-end
  `TLSFingerprinter`.

## Coverage

Branch coverage is enforced via `pytest-cov` and `coverage[toml]`. The
configuration lives in `pyproject.toml` under `[tool.coverage.run]` and
`[tool.coverage.report]`:

- `branch = true` — every conditional must be exercised both ways.
- `source = ["src/honeytrap"]` plus an explicit `omit` list for
  modules that genuinely require live external services or optional
  binary deps (CLIs, TUI, asyncio wire-protocol servers, AI backend
  HTTP transports, geoip2, weasyprint, the management API). The
  per-module exemption list is documented in
  `CHANGELOG_IMPROVEMENTS.md` under the Cycle 14B entry.
- `fail_under = 90` — the test job in CI fails the build if coverage
  drops below 90% on the targeted core.
- `exclude_lines` — `pragma: no cover`, `TYPE_CHECKING`,
  `NotImplementedError`, `@abstractmethod`, `__main__`.

Run the gate locally:

```sh
pytest -m "not benchmark" \
    --cov=src/honeytrap --cov-branch \
    --cov-report=term-missing \
    --cov-fail-under=90
```

Read `term-missing` output as: leftmost columns are statements/missed,
branches/partial, then percentage; the rightmost column lists the
specific line numbers and branch arrows (`A->B`) that were never
exercised. To regenerate the XML used by CI for artifact upload:

```sh
pytest -m "not benchmark" --cov=src/honeytrap --cov-report=xml --cov-branch
```

## Dev dependencies

`hypothesis`, `pytest-benchmark`, `pytest-cov`, `coverage[toml]`,
`mypy`, `pre-commit`, `codespell`, and `types-PyYAML` are all dev-only;
they live under `[project.optional-dependencies] dev` in
`pyproject.toml` and are not pulled in by `pip install honeytrap-ai`.
Install them with:

```sh
pip install -e ".[dev]"
pre-commit install
```
