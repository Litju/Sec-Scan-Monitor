# Development

## Python

```bash
cd analysis
python -m pip install -e '.[dev]'
python -m pytest -q
python -m mypy src
python -m ruff check src tests
```

## Web

```bash
cd apps/web
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

The default web mode is synthetic preview. Run the API and set `SECSCAN_API_URL` only when the local integration is intentionally configured. Do not use live credentials in tests.

## Change discipline

Keep the smallest meaningful diff. For a security-sensitive change, include the trust boundary, authority decision, evidence path, failure behavior, test command, and rollback note. A test that was not run is `NOT_VALIDATED`, not pass evidence.
