# SecScanMonitor web surface

The web application is a desktop-first, read-only operating surface for the public foundation. `PREVIEW` is the default mode and uses synthetic, non-personal, non-client data. It never silently falls back from an explicitly configured integration.

```bash
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

Local integration is explicit:

```text
NEXT_PUBLIC_SECSCAN_MODE=LOCAL_INTEGRATED
SECSCAN_API_URL=http://127.0.0.1:8000
```

The browser does not connect directly to PostgreSQL, Temporal, OPA, or raw evidence storage. Hosted managed-cloud operation is `NOT_VALIDATED` by this public foundation.
