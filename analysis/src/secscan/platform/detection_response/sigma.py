"""Fail-closed Sigma specification 2.1.0 subset importer."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from secscan.platform.domain.common import Confidence, Severity

from .domain import (
    SUPPORTED_OCSF_VERSION,
    DetectionPlan,
    DetectionRule,
    DetectionRuleType,
    DetectionRuleVersion,
    EventSourceFamily,
    RuleStatus,
    UnsupportedDetectionConstruct,
    content_digest,
    stable_id,
)

SIGMA_SPEC_VERSION = "2.1.0"
_ALLOWED_ROOT_KEYS = {
    "title",
    "id",
    "name",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "references",
    "tags",
    "logsource",
    "detection",
    "level",
    "falsepositives",
    "fields",
}
_ALLOWED_CUSTOM_PREFIX = "x_secscan_"
_ALLOWED_CUSTOM_KEYS = {"x_secscan_confidence", "x_secscan_rationale", "x_secscan_version"}
_ALLOWED_LOGSOURCE_KEYS = {"category", "product", "service"}
_ATTACK_TAG = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_ATLAS_TAG = re.compile(r"^atlas\.[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$", re.IGNORECASE)


class SigmaImportResult:
    def __init__(self, rule: DetectionRule, plan: DetectionPlan, *, content_digest: str) -> None:
        self.rule = rule
        self.plan = plan
        self.content_digest = content_digest


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses ambiguous duplicate mapping keys."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a YAML mapping", node.start_mark)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(None, None, "YAML mapping keys must be scalar", key_node.start_mark) from exc
        if duplicate:
            raise ConstructorError(None, None, f"duplicate YAML key: {key!r}", key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise UnsupportedDetectionConstruct(f"Sigma {label} must be a mapping")
    return value


def _source_family(logsource: Mapping[str, Any]) -> str:
    unknown = [key for key in logsource if not isinstance(key, str) or key not in _ALLOWED_LOGSOURCE_KEYS]
    if unknown:
        raise UnsupportedDetectionConstruct("Sigma logsource contains unsupported fields")
    for key, value in logsource.items():
        if not isinstance(value, str) or not value.strip():
            raise UnsupportedDetectionConstruct(f"Sigma logsource {key} must be a non-empty string")
    category = str(logsource.get("category", "")).lower()
    product = str(logsource.get("product", "")).lower()
    service = str(logsource.get("service", "")).lower()
    families: set[str] = set()
    if category in {"process_creation", "process_access", "file_event"} or product in {"windows", "linux", "endpoint"}:
        families.add(EventSourceFamily.ENDPOINT_FIXTURE.value)
    if category in {"authentication", "cloud", "audit", "iam"} or product in {"aws", "azure", "gcp", "cloud"}:
        families.add(EventSourceFamily.CLOUD_AUDIT_FIXTURE.value)
    if product in {"mcp", "a2a", "gateway"} or service in {"mcp", "a2a", "gateway"}:
        families.add(EventSourceFamily.MCP_A2A_GATEWAY.value)
    if product in {"secscan", "secscanmonitor"}:
        families.add(EventSourceFamily.SECSCAN.value)
    if product in {"edge_runner", "runner"} or service == "edge_runner":
        families.add(EventSourceFamily.EDGE_RUNNER.value)
    if len(families) != 1:
        raise UnsupportedDetectionConstruct("Sigma logsource must resolve to exactly one bounded source family")
    return next(iter(families))


def _severity(level: Any) -> Severity:
    value = str(level or "medium").lower()
    try:
        return {
            "informational": Severity.LOW,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }[value]
    except KeyError as exc:
        raise UnsupportedDetectionConstruct(f"unsupported Sigma level: {value}") from exc


def _tags(value: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if value is None:
        return (), ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise UnsupportedDetectionConstruct("Sigma tags must be a list of strings")
    attack: list[str] = []
    atlas: list[str] = []
    for tag in value:
        normalized = tag.lower()
        if normalized.startswith("attack."):
            if not _ATTACK_TAG.fullmatch(normalized):
                raise UnsupportedDetectionConstruct("malformed ATT&CK tag")
            attack.append(tag)
        elif normalized.startswith("atlas."):
            if not _ATLAS_TAG.fullmatch(normalized):
                raise UnsupportedDetectionConstruct("malformed ATLAS tag")
            atlas.append(tag)
        elif "." in tag:
            raise UnsupportedDetectionConstruct("unsupported Sigma tag namespace")
    return tuple(sorted(set(attack))), tuple(sorted(set(atlas)))


def _selector(detection: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise UnsupportedDetectionConstruct("Sigma condition is required")
    selectors = {key: value for key, value in detection.items() if key != "condition"}
    if condition.strip() not in selectors:
        raise UnsupportedDetectionConstruct("only a single named Sigma selector condition is supported")
    if len(selectors) != 1:
        raise UnsupportedDetectionConstruct("multiple Sigma selectors/boolean expressions are not supported")
    selected = selectors[condition.strip()]
    selected_mapping = _mapping(selected, "selector")
    predicates: dict[str, Any] = {}
    for field, value in selected_mapping.items():
        if not isinstance(field, str) or not field.strip():
            raise UnsupportedDetectionConstruct("Sigma selector fields must be non-empty strings")
        if "|" in field and field.rsplit("|", 1)[1] not in {"contains", "startswith", "endswith"}:
            raise UnsupportedDetectionConstruct("unsupported Sigma field modifier")
        if isinstance(value, Mapping) or (
            isinstance(value, list) and any(isinstance(item, Mapping) for item in value)
        ):
            raise UnsupportedDetectionConstruct("nested Sigma selector values are not supported")
        scalar = (str, int, float, bool)
        if isinstance(value, list):
            if not value or any(not isinstance(item, scalar) for item in value):
                raise UnsupportedDetectionConstruct("Sigma selector lists must contain scalar values")
        elif not isinstance(value, scalar):
            raise UnsupportedDetectionConstruct("Sigma selector values must be scalar or scalar lists")
        predicates[field] = value
    if not predicates:
        raise UnsupportedDetectionConstruct("Sigma selector cannot be empty")
    return condition.strip(), predicates


class SigmaSubsetImporter:
    """Compile only safe Sigma 2.1 single-event rules into a DetectionPlan."""

    specification_version = SIGMA_SPEC_VERSION

    def import_rule(self, document: str | Mapping[str, Any], *, source_reference: str = "inline") -> SigmaImportResult:
        if isinstance(document, str):
            try:
                payload = yaml.load(document, Loader=_UniqueKeyLoader)
            except yaml.YAMLError as exc:
                raise UnsupportedDetectionConstruct("malformed Sigma YAML") from exc
        else:
            payload = document
        root = dict(_mapping(payload, "document"))
        unknown = [
            key
            for key in root
            if key not in _ALLOWED_ROOT_KEYS
            and (not isinstance(key, str) or not key.startswith(_ALLOWED_CUSTOM_PREFIX) or key not in _ALLOWED_CUSTOM_KEYS)
        ]
        if unknown:
            raise UnsupportedDetectionConstruct(f"unsupported Sigma fields: {sorted(str(item) for item in unknown)}")
        title = root.get("title", root.get("name"))
        if not isinstance(title, str) or not title.strip():
            raise UnsupportedDetectionConstruct("Sigma title is required")
        logsource = _mapping(root.get("logsource"), "logsource")
        source_family = _source_family(logsource)
        condition, predicates = _selector(_mapping(root.get("detection"), "detection"))
        attack, atlas = _tags(root.get("tags"))
        references = root.get("references", [])
        if not isinstance(references, list) or any(not isinstance(item, str) or not item.strip() for item in references):
            raise UnsupportedDetectionConstruct("Sigma references must be a list of non-empty strings")
        status_value = str(root.get("status", "stable")).lower()
        status = {"stable": RuleStatus.ACTIVE, "test": RuleStatus.TEST, "experimental": RuleStatus.TEST}.get(status_value)
        if status is None:
            raise UnsupportedDetectionConstruct(f"unsupported Sigma status: {status_value}")
        digest = content_digest(root)
        raw_rule_id = root.get("id")
        if raw_rule_id is not None and (not isinstance(raw_rule_id, str) or not raw_rule_id.strip()):
            raise UnsupportedDetectionConstruct("Sigma id must be a non-empty string")
        rule_id = raw_rule_id.strip() if isinstance(raw_rule_id, str) else stable_id("SIGMA-RULE-", title, digest)
        rationale = root.get("x_secscan_rationale", "SecScanMonitor-owned bounded detection content")
        if not isinstance(rationale, str) or not rationale.strip():
            raise UnsupportedDetectionConstruct("x_secscan_rationale must be a non-empty string")
        confidence_value = str(root.get("x_secscan_confidence", "medium")).lower()
        try:
            confidence = Confidence(confidence_value)
        except ValueError as exc:
            raise UnsupportedDetectionConstruct("x_secscan_confidence must use the fixed confidence scale") from exc
        raw_version = root.get("x_secscan_version", 1)
        if isinstance(raw_version, bool) or not isinstance(raw_version, int) or raw_version < 1:
            raise UnsupportedDetectionConstruct("x_secscan_version must be a positive integer")
        version = raw_version
        rule_version = DetectionRuleVersion(
            rule_id=rule_id,
            version=version,
            title=title,
            rule_type=DetectionRuleType.EVENT_MATCH,
            content_digest=digest,
            source=f"sigma-{SIGMA_SPEC_VERSION}",
            source_reference=source_reference,
            event_schema="OCSF",
            ocsf_version=SUPPORTED_OCSF_VERSION,
            supported_source_families=(source_family,),
            severity=_severity(root.get("level")),
            confidence=confidence,
            confidence_metadata={"sigma_specification": SIGMA_SPEC_VERSION, "rationale": rationale},
            attack_mappings=attack,
            atlas_mappings=atlas,
            references=tuple(references),
            predicates=predicates,
            status=status,
            evaluation_metadata={"condition": condition, "sigma_subset": "single_event"},
        )
        rule = DetectionRule(rule_id=rule_id, name=title, versions=(rule_version,), active_version=version)
        plan = DetectionPlan(
            plan_id=stable_id("PLAN-", rule_id, version, digest),
            rule_id=rule_id,
            rule_version=version,
            rule_type=DetectionRuleType.EVENT_MATCH,
            content_digest=digest,
            event_schema="OCSF",
            supported_source_families=(source_family,),
            predicates=predicates,
        )
        return SigmaImportResult(rule, plan, content_digest=digest)

    def import_path(self, path: str | Path) -> SigmaImportResult:
        resolved = Path(path)
        return self.import_rule(resolved.read_text(encoding="utf-8"), source_reference=str(resolved))
