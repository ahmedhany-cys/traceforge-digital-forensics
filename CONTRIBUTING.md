# Contributing

Thanks for your interest in improving TraceForge.

## Ground rules

* **Never add real malware, real evidence or real personal data** to the repository. Use the synthetic generator (`dataset/generator/`) or build harmless test files in tests.
* Detection logic must stay **explainable**: every rule needs an ID, a description and a rationale that states benign explanations. YARA rules must define `id`, `description`, `severity` and `explanation` meta.
* Do not present correlation output as proof of causation, and do not label indicators "malicious" without a concrete, documented reason.
* Only add third-party signatures whose licence permits redistribution, and credit them.

## Development setup

See [docs/INSTALLATION.md](docs/INSTALLATION.md). In short:

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r backend/requirements-dev.txt
cd frontend && npm ci
```

## Before opening a pull request

```bash
cd backend
../.venv/bin/python -m pytest                 # all tests must pass
../.venv/bin/bandit -q -r app                 # no new findings (justify any nosec)
../.venv/bin/pip-audit -r requirements.txt
cd ../frontend
npm test && npm run lint && npm run build && npm audit --omit=dev
```

* Add tests that exercise real behaviour (parse a file, run a rule, call the API) – not assertions on hard-coded values.
* If you change the dataset generator, regenerate `dataset/meridian/` and commit the updated `manifest.json`; `tests/test_dataset.py` checks they match.
* Keep the `forensics/` package free of database and web-framework imports.
* Update the relevant document in `docs/` when behaviour changes.

## Adding a detection rule

1. Windows events: add an entry to `backend/rules/detections/windows_events.json` (include `prerequisites`).
2. Sequences: add a rule to `backend/rules/detections/correlation.json`.
3. YARA: add a `.yar` file under `backend/rules/yara/`.
4. Add positive **and** negative tests, and document the rule in `docs/DETECTION_RULES.md`.
