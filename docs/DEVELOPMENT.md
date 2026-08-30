# Development

## Platform core

```bash
cd analysis
python -m pip install -e '.[dev]'
python -m pytest -q
python -m mypy src
python -m ruff check src tests
```

## Web Command Center

```bash
cd apps/web
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

## OpenTUI Operator Console

```bash
cd apps/tui
npm ci
npm test
npm run typecheck
npm run build
```

The default safe evaluation mode may use synthetic preview data. Integrated live mode requires the documented PostgreSQL canonical store, repository-pinned OPA, API, and durable worker environment. Configure live endpoints outside version control and never use live credentials in tests.

## Change discipline

Keep the smallest meaningful diff. For a security-sensitive change, include the trust boundary, authority decision, evidence path, failure behavior, test command, and rollback note. A test that was not run is `NOT_VALIDATED`, not pass evidence.
