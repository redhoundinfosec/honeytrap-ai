# Performance benchmarks

This directory holds `pytest-benchmark` micro-benchmarks for the hot-path
components of HoneyTrap. They are excluded from the default `pytest`
run via the `benchmark` marker filter declared in `pyproject.toml`.

## Running benchmarks

Run the full benchmark suite and save the results for later comparison:

```bash
pytest tests/bench/ --benchmark-only --benchmark-autosave
```

Compare two saved runs:

```bash
pytest-benchmark compare 0001 0002
```

Filter to a single module:

```bash
pytest tests/bench/test_event_bus_bench.py --benchmark-only
```

## Skipping benchmarks

Benchmarks are skipped automatically by `pytest` because the project's
`addopts` includes `-m 'not benchmark'`. Default invocations of
`pytest` therefore never run benchmark code.

## Coverage

* `test_event_bus_bench.py` -- in-process pub/sub fan-out throughput.
* `test_intent_classifier_bench.py` -- per-call latency for the
  heuristic attacker-intent classifier.
* `test_response_cache_bench.py` -- adaptive AI response cache get/set/miss
  micro-benchmarks.
* `test_tls_fingerprint_bench.py` -- JA3/JA4 generation cost over a
  population of synthetic ClientHello samples.
