# Architecture

`IMPLEMENTED` public boundaries:

1. **Domain** — typed identities, engagement lifecycle, authority, capability manifests, evidence metadata, observations, claims, adjudication, and findings.
2. **Application** — contract and authority services coordinate work without allowing agents to mutate canonical state directly.
3. **Adapters** — PostgreSQL, local content-addressed evidence, optional S3-compatible evidence, OPA, Temporal, Docker sandbox, and FastAPI are replaceable boundaries.
4. **Product surface** — the web UI consumes controlled API/read models and presents explicit preview, unavailable, and `NOT_VALIDATED` states.

The canonical chain is:

```text
EvidenceObject -> Observation -> Claim -> Adjudication -> Finding
```

Agents do not construct findings. A finding is an adjudicated conclusion with evidence references, rationale, severity, remediation guidance, verification steps, and confidence.

`EXPERIMENTAL` or `NOT YET QUALIFIED`: managed hosted deployment, external identity providers, production Temporal operation, production object storage, and live-model execution.
