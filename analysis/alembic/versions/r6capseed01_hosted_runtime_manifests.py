"""Seed canonical capability and agent manifests required by hosted workflows."""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "r6capseed01"
down_revision = "c302adjudication"
branch_labels = None
depends_on = None

_CAPABILITY_ROWS = json.loads(r'''[
  {
    "capability_id": "CAP-EVIDENCE-NORMALIZE",
    "version": "1.0.0",
    "description": "Normalize captured raw output into typed observations with provenance.",
    "risk_class": "info",
    "accepted_inputs": [
      "evidence_ids"
    ],
    "produced_outputs": [
      "observations"
    ],
    "required_authority": "collect",
    "requires_approval": false,
    "sandbox_profile": "default",
    "sandbox_requirement": "none",
    "network_policy": "none",
    "timeout_seconds": 60,
    "resource_limits": {
      "cpu": "1",
      "memory": "256m",
      "pids": "64"
    },
    "tool_identity": "secscan-internal",
    "tool_version": "1.0.0",
    "tool_license": "",
    "source_url": "",
    "release_url": "",
    "artifact_ref": "",
    "artifact_digest": "",
    "evidence_type": "observation",
    "normalizer": "",
    "failure_semantics": "",
    "command_allowlist": [
      "python"
    ]
  },
  {
    "capability_id": "CAP-FIRM-REPORT-RENDER",
    "version": "1.0.0",
    "description": "Render a sanitized firm report from adjudicated findings via the case engine.",
    "risk_class": "info",
    "accepted_inputs": [
      "engagement_id"
    ],
    "produced_outputs": [
      "firm_report"
    ],
    "required_authority": "inspect",
    "requires_approval": false,
    "sandbox_profile": "default",
    "sandbox_requirement": "none",
    "network_policy": "none",
    "timeout_seconds": 60,
    "resource_limits": {
      "cpu": "1",
      "memory": "256m",
      "pids": "64"
    },
    "tool_identity": "secscan-internal",
    "tool_version": "1.0.0",
    "tool_license": "",
    "source_url": "",
    "release_url": "",
    "artifact_ref": "",
    "artifact_digest": "",
    "evidence_type": "report",
    "normalizer": "",
    "failure_semantics": "",
    "command_allowlist": [
      "python"
    ]
  },
  {
    "capability_id": "CAP-REPO-INVENTORY",
    "version": "1.0.0",
    "description": "Enumerate repository structure: files, sizes, type counts. Read-only metadata.",
    "risk_class": "info",
    "accepted_inputs": [
      "repo_path"
    ],
    "produced_outputs": [
      "file_inventory"
    ],
    "required_authority": "inspect",
    "requires_approval": false,
    "sandbox_profile": "default",
    "sandbox_requirement": "none",
    "network_policy": "none",
    "timeout_seconds": 60,
    "resource_limits": {
      "cpu": "1",
      "memory": "256m",
      "pids": "64"
    },
    "tool_identity": "secscan-internal",
    "tool_version": "1.0.0",
    "tool_license": "",
    "source_url": "",
    "release_url": "",
    "artifact_ref": "",
    "artifact_digest": "",
    "evidence_type": "repository-inventory",
    "normalizer": "",
    "failure_semantics": "",
    "command_allowlist": [
      "python",
      "dir"
    ]
  },
  {
    "capability_id": "CAP-REPO-READONLY-INSPECTION",
    "version": "1.0.0",
    "description": "Read files and metadata inside the declared target scope. The inspector never executes target code and reads an immutable snapshot through a bounded host-side reader.",
    "risk_class": "low",
    "accepted_inputs": [
      "file_paths",
      "patterns"
    ],
    "produced_outputs": [
      "file_contents",
      "file_metadata"
    ],
    "required_authority": "inspect",
    "requires_approval": false,
    "sandbox_profile": "default",
    "sandbox_requirement": "none",
    "network_policy": "none",
    "timeout_seconds": 120,
    "resource_limits": {
      "cpu": "1",
      "memory": "256m",
      "pids": "64"
    },
    "tool_identity": "secscan-internal",
    "tool_version": "1.0.0",
    "tool_license": "",
    "source_url": "",
    "release_url": "",
    "artifact_ref": "",
    "artifact_digest": "",
    "evidence_type": "file-read",
    "normalizer": "",
    "failure_semantics": "",
    "command_allowlist": [
      "python",
      "cat"
    ]
  },
  {
    "capability_id": "CAP-REPO-TRIVY",
    "version": "1.0.0",
    "description": "Offline Trivy filesystem vulnerability, misconfiguration, and secret inspection.",
    "risk_class": "medium",
    "accepted_inputs": [
      "immutable_source_snapshot"
    ],
    "produced_outputs": [
      "trivy_json"
    ],
    "required_authority": "inspect",
    "requires_approval": false,
    "sandbox_profile": "scanner-default",
    "sandbox_requirement": "required",
    "network_policy": "none",
    "timeout_seconds": 300,
    "resource_limits": {
      "cpu": "1",
      "memory": "1g",
      "pids": "64"
    },
    "tool_identity": "aquasec/trivy",
    "tool_version": "0.74.0",
    "tool_license": "Apache-2.0",
    "source_url": "https://github.com/aquasecurity/trivy",
    "release_url": "https://github.com/aquasecurity/trivy/releases/tag/v0.74.0",
    "artifact_ref": "docker.io/aquasec/trivy@sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9",
    "artifact_digest": "sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9",
    "evidence_type": "trivy-json",
    "normalizer": "secscan.platform.capabilities.scanner_adapters._safe_payload",
    "failure_semantics": "missing offline advisory DB is NOT_QUALIFIED; skip-db-update never authorizes network fallback",
    "command_allowlist": [
      "fs"
    ]
  },
  {
    "capability_id": "CAP-SAST-SEMGREP",
    "version": "1.0.0",
    "description": "Offline Semgrep Community static analysis against an immutable source snapshot.",
    "risk_class": "medium",
    "accepted_inputs": [
      "immutable_source_snapshot"
    ],
    "produced_outputs": [
      "semgrep_json"
    ],
    "required_authority": "inspect",
    "requires_approval": false,
    "sandbox_profile": "scanner-default",
    "sandbox_requirement": "required",
    "network_policy": "none",
    "timeout_seconds": 300,
    "resource_limits": {
      "cpu": "1",
      "memory": "512m",
      "pids": "64"
    },
    "tool_identity": "semgrep/semgrep",
    "tool_version": "1.173.0",
    "tool_license": "LGPL-2.1",
    "source_url": "https://github.com/semgrep/semgrep",
    "release_url": "https://github.com/semgrep/semgrep/releases/tag/v1.173.0",
    "artifact_ref": "docker.io/semgrep/semgrep@sha256:44dd022c29d4f881a939f7281b4ba8855cb940a2dd272883908d8947325a4ba7",
    "artifact_digest": "sha256:44dd022c29d4f881a939f7281b4ba8855cb940a2dd272883908d8947325a4ba7",
    "evidence_type": "semgrep-json",
    "normalizer": "secscan.platform.capabilities.scanner_adapters._safe_payload",
    "failure_semantics": "non-zero is preserved as evidence; findings do not become findings without adjudication",
    "command_allowlist": [
      "semgrep"
    ]
  },
  {
    "capability_id": "CAP-SCA-OSV",
    "version": "1.0.0",
    "description": "Offline OSV-Scanner dependency inspection against an immutable source snapshot.",
    "risk_class": "medium",
    "accepted_inputs": [
      "immutable_source_snapshot"
    ],
    "produced_outputs": [
      "osv_json"
    ],
    "required_authority": "inspect",
    "requires_approval": false,
    "sandbox_profile": "scanner-default",
    "sandbox_requirement": "required",
    "network_policy": "none",
    "timeout_seconds": 300,
    "resource_limits": {
      "cpu": "1",
      "memory": "512m",
      "pids": "64"
    },
    "tool_identity": "ghcr.io/google/osv-scanner",
    "tool_version": "2.5.0",
    "tool_license": "Apache-2.0",
    "source_url": "https://github.com/google/osv-scanner",
    "release_url": "https://github.com/google/osv-scanner/releases/tag/v2.5.0",
    "artifact_ref": "ghcr.io/google/osv-scanner@sha256:ed5c1cda47b439a9bf0b010d2f0920b70d6cf2e003fe1774c0e4c405e5747213",
    "artifact_digest": "sha256:ed5c1cda47b439a9bf0b010d2f0920b70d6cf2e003fe1774c0e4c405e5747213",
    "evidence_type": "osv-json",
    "normalizer": "secscan.platform.capabilities.scanner_adapters._safe_payload",
    "failure_semantics": "offline database absence is NOT_QUALIFIED; no network fallback is permitted",
    "command_allowlist": [
      "scan"
    ]
  },

  {
    "capability_id": "CAP-SECRETS-GITLEAKS",
    "version": "1.0.0",
    "description": "Redacted Gitleaks secret detection against an immutable source snapshot.",
    "risk_class": "medium",
    "accepted_inputs": [
      "immutable_source_snapshot"
    ],
    "produced_outputs": [
      "gitleaks_json_redacted"
    ],
    "required_authority": "inspect",
    "requires_approval": false,
    "sandbox_profile": "scanner-default",
    "sandbox_requirement": "required",
    "network_policy": "none",
    "timeout_seconds": 300,
    "resource_limits": {
      "cpu": "1",
      "memory": "512m",
      "pids": "64"
    },
    "tool_identity": "zricethezav/gitleaks",
    "tool_version": "8.30.1",
    "tool_license": "MIT",
    "source_url": "https://github.com/gitleaks/gitleaks",
    "release_url": "https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1",
    "artifact_ref": "docker.io/zricethezav/gitleaks@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb",
    "artifact_digest": "sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb",
    "evidence_type": "gitleaks-json-redacted",
    "normalizer": "secscan.platform.capabilities.scanner_adapters._safe_payload",
    "failure_semantics": "exit 1 with redacted detections is successful evidence collection; values are never persisted",
    "command_allowlist": [
      "detect"
    ]
  }
]''')
_AGENT_ROWS = json.loads(r'''[
  {
    "manifest_id": "AM-FIRM-COORDINATOR-V1",
    "agent_id": "AGT-FIRM-COORDINATOR",
    "role": "firm-coordinator",
    "version": "1.0.0",
    "accepted_inputs": [
      "engagement_id"
    ],
    "produced_outputs": [
      "deployment_plan",
      "capability_requests",
      "coordinator_verdict"
    ],
    "requested_capabilities": [
      "CAP-REPO-INVENTORY",
      "CAP-FIRM-REPORT-RENDER",
      "CAP-REPO-READONLY-INSPECTION",
      "CAP-SAST-SEMGREP",
      "CAP-SCA-OSV",
      "CAP-SECRETS-GITLEAKS",
      "CAP-REPO-TRIVY"
    ],
    "allowed_tools": [
      "read-engagement",
      "request-capability",
      "collect-specialist-output",
      "send-claims"
    ],
    "forbidden_tools": [
      "create-finding",
      "mutate-target",
      "execute-shell"
    ],
    "authority_ceiling": "inspect",
    "evidence_consumed": [
      "engagement_record",
      "scope"
    ],
    "evidence_produced": [
      "deployment_plan",
      "coordinator_verdict"
    ],
    "escalation_rules": [
      "escalate out-of-scope requests to the operator; never expand scope"
    ],
    "refusal_rules": [
      "refuse when scope is missing; refuse when target is undeclared"
    ],
    "model_policy": "deterministic-fake-first; live-model only with explicit credentials",
    "timeout_policy": "bounded per step; total run capped",
    "retry_policy": "structured-output retry once, then fail closed"
  },
  {
    "manifest_id": "AM-SECURITY-REVIEW-SPECIALIST-V1",
    "agent_id": "AGT-SECURITY-REVIEW-SPECIALIST",
    "role": "security-review-specialist",
    "version": "1.0.0",
    "accepted_inputs": [
      "evidence_ids",
      "target_scope"
    ],
    "produced_outputs": [
      "observations",
      "claims"
    ],
    "requested_capabilities": [
      "CAP-REPO-READONLY-INSPECTION"
    ],
    "allowed_tools": [
      "read-evidence",
      "request-inspection-capability"
    ],
    "forbidden_tools": [
      "create-finding",
      "mutate-target",
      "execute-shell",
      "active-testing"
    ],
    "authority_ceiling": "inspect",
    "evidence_consumed": [
      "evidence_objects"
    ],
    "evidence_produced": [
      "observations",
      "claims"
    ],
    "escalation_rules": [
      "escalate secrets encountered: metadata only, never the value"
    ],
    "refusal_rules": [
      "refuse capability requests beyond read-only inspection"
    ],
    "model_policy": "deterministic-fake-first; live-model only with explicit credentials",
    "timeout_policy": "bounded per step",
    "retry_policy": "structured-output retry once, then fail closed"
  }
]''')


def upgrade() -> None:
    capability_table = sa.table(
        "capability_manifests",
        *[
            sa.column(
                name,
                sa.JSON()
                if name in {
                    "accepted_inputs",
                    "produced_outputs",
                    "resource_limits",
                    "command_allowlist",
                }
                else sa.Boolean()
                if name == "requires_approval"
                else sa.Integer()
                if name == "timeout_seconds"
                else sa.String(),
            )
            for name in ["capability_id","version","description","risk_class","accepted_inputs","produced_outputs","required_authority","requires_approval","sandbox_profile","sandbox_requirement","network_policy","timeout_seconds","resource_limits","tool_identity","tool_version","tool_license","source_url","release_url","artifact_ref","artifact_digest","evidence_type","normalizer","failure_semantics","command_allowlist"]
        ],
    )
    op.bulk_insert(capability_table, _CAPABILITY_ROWS)

    agent_table = sa.table(
        "agent_manifests",
        *[
            sa.column(name, sa.JSON() if name in {
                "accepted_inputs",
                "produced_outputs",
                "requested_capabilities",
                "allowed_tools",
                "forbidden_tools",
                "evidence_consumed",
                "evidence_produced",
                "escalation_rules",
                "refusal_rules",
            } else sa.String())
            for name in ["manifest_id","agent_id","role","version","accepted_inputs","produced_outputs","requested_capabilities","allowed_tools","forbidden_tools","authority_ceiling","evidence_consumed","evidence_produced","escalation_rules","refusal_rules","model_policy","timeout_policy","retry_policy"]
        ],
    )
    op.bulk_insert(agent_table, _AGENT_ROWS)


def downgrade() -> None:
    op.execute(
        sa.text(
            "DELETE FROM agent_manifests WHERE manifest_id IN "
            "('AM-FIRM-COORDINATOR-V1', 'AM-SECURITY-REVIEW-SPECIALIST-V1')"
        )
    )
    op.execute(
        sa.text(
            "DELETE FROM capability_manifests WHERE capability_id IN "
            "('CAP-EVIDENCE-NORMALIZE', 'CAP-FIRM-REPORT-RENDER', 'CAP-REPO-INVENTORY', 'CAP-REPO-READONLY-INSPECTION', 'CAP-REPO-TRIVY', 'CAP-SAST-SEMGREP', 'CAP-SCA-OSV', 'CAP-SECRETS-GITLEAKS')"
        )
    )
