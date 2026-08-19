# Release process

This repository is released only after a sanitized export review.

1. Start from a clean private work branch and record the source revision.
2. Review the allowlist, exclusions, source-to-public provenance, secrets scan, privacy scan, binary scan, license scan, deterministic export, and tests.
3. Build the public tree twice from the same source revision and compare every file and digest.
4. Run public Python, web, clean-clone, dogfood, SBOM, and workflow checks.
5. Push only the new sanitized public history to the public repository. Never mirror private history and never force-push.
6. Verify repository identity, visibility, branch protections, workflow permissions, vulnerability reporting, and security files after the push.

The foundation run does not create a product tag, GitHub Release, package publication, or production deployment. Those require a later, explicit release decision.
