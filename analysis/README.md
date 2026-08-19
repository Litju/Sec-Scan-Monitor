# Python platform

The Python package contains the typed SecScanMonitor platform. It is designed for local/self-hosted inspection workflows and uses deterministic fakes in the canonical unit suite.

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m mypy src
python -m ruff check src tests
```

PostgreSQL, OPA, Temporal, Docker, and object storage are explicit adapters. Their integrations are not silently replaced by an in-memory implementation in hosted mode. Run only the services you have intentionally configured.
