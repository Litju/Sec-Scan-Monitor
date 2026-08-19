# Deployment

`IMPLEMENTED`: local/self-hosted composition can be assembled from the Python API, PostgreSQL adapter, optional OPA, optional Temporal, optional sandbox, and the web surface. Bind development services to loopback and provide configuration outside version control.

`NOT VALIDATED`: managed cloud hosting, multi-tenant production isolation, hosted identity, production object storage, production Temporal workers, autoscaling, public ingress, external model providers, and operational SLOs.

The public repository intentionally provides no production credentials, hosted provider project, deployment secret, or managed-cloud claim. A deployment proposal must add an engagement or architecture decision, qualification evidence, rollback, and an explicit go/no-go.
