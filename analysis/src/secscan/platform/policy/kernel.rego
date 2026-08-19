# SecScanMonitor firm authorization policy kernel (OPA/Rego)
#
# Deterministic decider. Decisions: allow | deny | require_approval.
# The model may recommend; only this kernel (via the application boundary)
# authorizes. Baseline policy per ADR-0006.
#
# Expected input shape (built by AuthorityService.decide):
# {
#   "principal": {"id": "..."},
#   "agent": {"id": "..."},
#   "engagement": {"id": "...", "status": "...", "authority_level": "...",
#                  "target_ids": [...]},
#   "target": {"id": "..."},
#   "capability": {"id": "...", "registered": bool, "risk_class": "...",
#                  "requires_approval": bool, "required_authority": "..."},
#   "action": "inspect|collect|active_test|mutate|remediate",
#   "risk": "...",
#   "authority_grant": {"matched": bool, "grant_ids": [...]},
#   "approval": {"id": "...", "decision": "approved|denied|pending",
#                "target_id": "...", "capability_id": "...",
#                "action": "...", "engagement_id": "..."},
#   "workflow_phase": "...",
#   "requested_resources": {...}
# }
#
# Laws enforced here (each deny rule has a test):
# - unknown/empty action           => DENY
# - unknown/unregistered capability => DENY
# - out-of-engagement target        => DENY
# - non-working engagement status   => DENY (suspended/revoked/closed/draft/
#                                     refused/failed/partial never authorize)
# - no matching active grant        => DENY
# - mutation/active-testing without remediation engagement authority => DENY
# - capability authority mismatch   => DENY
# - high-risk or requires_approval without a VALID, REQUEST-BOUND approval
#                                    => REQUIRE_APPROVAL
# - valid approval (decision=approved, bound to this request's target/
#   capability/action/engagement)   => ALLOW (subject to the gates above)

package secscan.authorize

import rego.v1

# --- deny by default -------------------------------------------------------
default decision := "deny"

known_actions := {"inspect", "collect", "active_test", "mutate", "remediate"}
known_engagement_authority_levels := {"inspection-only", "remediation"}
mutation_actions := {"mutate", "remediate", "active_test"}
high_risk_classes := {"critical", "high"}
# Engagement states in which capability execution is permissible.
working_engagement_statuses := {
    "authorized",
    "active",
    "evidence_collection",
    "analysis",
    "adjudication",
    "reporting",
    "remediation",
}

# --- structural denials -----------------------------------------------------
decision := "deny" if {
    not known_actions[input.action]
}

decision := "deny" if {
    not capability_registered
}

# --- engagement-state denials ----------------------------------------------
decision := "deny" if {
    not engagement_working
}

decision := "deny" if {
    not known_engagement_authority_levels[input.engagement.authority_level]
}

# --- scope denials ----------------------------------------------------------
decision := "deny" if {
    not target_in_engagement_scope
}

# --- authority denials ------------------------------------------------------
decision := "deny" if {
    not input.authority_grant.matched
}

decision := "deny" if {
    input.authority_grant.matched
    not grant_binding_ok
}

decision := "deny" if {
    input.authority_grant.matched
    not action_allowed_by_engagement_level
}

decision := "deny" if {
    input.authority_grant.matched
    capability_authority_required
    input.action != input.capability.required_authority
}

# --- high-risk requires approval -------------------------------------------
decision := "require_approval" if {
    authorization_gates_ok
    high_risk_operation
    not approved
}

decision := "require_approval" if {
    authorization_gates_ok
    input.capability.requires_approval
    not approved
}

# --- authorized operations: allow -------------------------------------------
# Covers inspection within valid scope AND non-high-risk mutation that has an
# explicit remediation-engagement grant (action_allowed_by_engagement_level
# gates mutation actions). Scope, engagement status, registration, and grant
# are re-checked in every allow rule: they can never reach ALLOW.
decision := "allow" if {
    authorization_gates_ok
    not high_risk_operation
    not input.capability.requires_approval
}

decision := "allow" if {
    authorization_gates_ok
    approved
}

# --- helpers ----------------------------------------------------------------
authorization_gates_ok if {
    capability_registered
    engagement_working
    known_engagement_authority_levels[input.engagement.authority_level]
    target_in_engagement_scope
    input.authority_grant.matched
    action_allowed_by_engagement_level
    capability_authority_ok
}

capability_registered if {
    input.capability.id
    input.capability.id != ""
    input.capability.registered == true
}

engagement_working if {
    working_engagement_statuses[input.engagement.status]
}

target_in_engagement_scope if {
    target := input.target.id
    engagement := input.engagement
    target in engagement.target_ids
}

action_allowed_by_engagement_level if {
    not mutation_actions[input.action]
}

action_allowed_by_engagement_level if {
    input.engagement.authority_level == "remediation"
    mutation_actions[input.action]
}

capability_authority_required if {
    input.capability.required_authority
    input.capability.required_authority != ""
}

capability_authority_ok if {
    not capability_authority_required
}

capability_authority_ok if {
    input.action == input.capability.required_authority
}

high_risk_operation if {
    high_risk_classes[input.capability.risk_class]
}

high_risk_operation if {
    high_risk_classes[input.risk]
}

# An approval counts ONLY when it is a recorded canonical object, decided
# "approved", and bound to this exact request: same target, capability,
# action, engagement. A fabricated, pending, denied, or foreign approval id
# can never convert REQUIRE_APPROVAL into ALLOW.
approved if {
    input.approval.recorded == true
    input.approval.id != ""
    input.approval.decision == "approved"
    input.approval.decided_by_principal_id != ""
    input.approval.target_id == input.target.id
    input.approval.capability_id == input.capability.id
    input.approval.action == input.action
    input.approval.engagement_id == input.engagement.id
}

# A matched grant must be one canonical non-empty grant and preserve its
# request binding. The application service resolves the requested grant ID;
# these checks prevent a malformed policy input from turning matched=true into
# authority.
grant_binding_ok if {
    count(input.authority_grant.grant_ids) == 1
    input.authority_grant.grant_ids[0] != ""
    grant_principal_ok
    grant_engagement_ok
    grant_capability_ok
    grant_target_ok
    grant_action_ok
    grant_conditions_ok
}

grant_principal_ok if {
    not input.authority_grant.principal_id
}

grant_principal_ok if {
    input.authority_grant.principal_id == ""
}

grant_principal_ok if {
    input.authority_grant.principal_id == input.principal.id
}

grant_engagement_ok if {
    not input.authority_grant.engagement_id
}

grant_engagement_ok if {
    input.authority_grant.engagement_id == ""
}

grant_engagement_ok if {
    input.authority_grant.engagement_id == input.engagement.id
}

grant_capability_ok if {
    not input.authority_grant.capability_id
}

grant_capability_ok if {
    input.authority_grant.capability_id == ""
}

grant_capability_ok if {
    input.authority_grant.capability_id == input.capability.id
}

grant_target_ok if {
    not input.authority_grant.target_id
}

grant_target_ok if {
    input.authority_grant.target_id == ""
}

grant_target_ok if {
    input.authority_grant.target_id == input.target.id
}

grant_action_ok if {
    not input.authority_grant.action
}

grant_action_ok if {
    input.authority_grant.action == ""
}

grant_action_ok if {
    input.authority_grant.action == input.action
}

grant_requires_snapshot if {
    "immutable_snapshot_only" in input.authority_grant.conditions
}

grant_requires_no_client_writes if {
    "no_client_writes" in input.authority_grant.conditions
}

grant_requires_no_active_testing if {
    "no_production_active_testing" in input.authority_grant.conditions
}

grant_conditions_ok if {
    snapshot_condition_ok
    no_client_writes_condition_ok
    no_active_testing_condition_ok
}

snapshot_condition_ok if {
    not grant_requires_snapshot
}

snapshot_condition_ok if {
    grant_requires_snapshot
    input.requested_resources.snapshot != ""
}

no_client_writes_condition_ok if {
    not grant_requires_no_client_writes
}

no_client_writes_condition_ok if {
    grant_requires_no_client_writes
    not input.action in mutation_actions
}

no_active_testing_condition_ok if {
    not grant_requires_no_active_testing
}

no_active_testing_condition_ok if {
    grant_requires_no_active_testing
    input.action != "active_test"
}


# --- decision envelope (always defined) -------------------------------------
default target_in_scope_bool := false
target_in_scope_bool := true if {
    target_in_engagement_scope
}

default grant_matched_bool := false
grant_matched_bool := true if {
    input.authority_grant.matched
}

default engagement_working_bool := false
engagement_working_bool := true if {
    engagement_working
}

result := {
    "decision": decision,
    "target_in_scope": target_in_scope_bool,
    "grant_matched": grant_matched_bool,
    "engagement_working": engagement_working_bool,
}
