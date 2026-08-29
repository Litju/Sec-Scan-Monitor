"""Deterministic v0.3 detection-response services.

The module deliberately stops at a signal, hunt result, adjudicated incident,
or response proposal. It contains no Finding writer and no action executor.
"""

from __future__ import annotations

import fnmatch
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Iterable, Mapping, Sequence

from secscan.platform.continuous_security.events import SecurityEvent, SecurityEventPlane
from secscan.platform.domain.common import Confidence, Severity, utc_now
from secscan.platform.domain.evidence import Claim

from .domain import (
    SUPPORTED_OCSF_CLASSES,
    SUPPORTED_OCSF_VERSION,
    SUPPORTED_SOURCE_FAMILIES,
    AdjudicationRefused,
    CapabilityRequest,
    DetectionEvaluation,
    DetectionInputError,
    DetectionPlan,
    DetectionRule,
    DetectionRuleType,
    DetectionRun,
    DetectionScopeError,
    DetectionSignal,
    EvaluationResult,
    HumanApproval,
    HumanApprovalState,
    HuntDisposition,
    HuntExecution,
    HuntHypothesis,
    HuntPlan,
    HuntResult,
    Incident,
    IncidentAdjudication,
    IncidentHypothesis,
    IncidentInvestigation,
    IncidentState,
    OpaDecision,
    ResponseAction,
    ResponseAuthorizationError,
    ResponseExecutionDisabled,
    ResponsePolicyPort,
    ResponseProposal,
    RuleStatus,
    Scope,
    content_digest,
    stable_id,
)

Clock = Callable[[], datetime]


class BoundedSecurityEventIngestor:
    """Adapter over the existing event plane with the v0.3 source boundary."""

    def __init__(self, plane: SecurityEventPlane | None = None, *, scope: Scope | None = None) -> None:
        self.plane = plane or SecurityEventPlane()
        self.scope = scope

    def _require_scope(self, scope: Scope) -> None:
        if self.scope is not None and self.scope != scope:
            raise DetectionScopeError("event access crossed the bound tenant/case/target scope")

    def _validate(self, event: SecurityEvent, scope: Scope | None = None) -> None:
        if event.source_family not in SUPPORTED_SOURCE_FAMILIES:
            raise DetectionInputError(f"unsupported source family: {event.source_family}")
        if event.ocsf_version != SUPPORTED_OCSF_VERSION:
            raise DetectionInputError(f"unsupported OCSF version: {event.ocsf_version}")
        if event.ocsf_class not in SUPPORTED_OCSF_CLASSES or event.event_class.value not in SUPPORTED_OCSF_CLASSES:
            raise DetectionInputError("unsupported OCSF event class")
        if event.ocsf_class != event.event_class.value:
            raise DetectionInputError("OCSF class does not match the normalized event class")
        if scope is not None and Scope(tenant=event.tenant, case=event.case, target=event.target) != scope:
            raise DetectionScopeError("event did not match the requested scope")

    @staticmethod
    def _validate_raw(raw: object) -> None:
        if not isinstance(raw, dict):
            raise DetectionInputError("raw security events must be mappings")
        required_text = (
            "source",
            "source_record_id",
            "source_digest",
            "source_system",
            "collector_version",
            "source_type",
            "source_family",
            "tenant",
            "case",
            "target",
            "actor",
            "object",
            "action",
            "outcome",
            "raw_evidence_ref",
            "normalization_version",
            "ocsf_version",
        )
        for field in required_text:
            value = raw.get(field)
            if not isinstance(value, str) or not value.strip():
                raise DetectionInputError(f"raw security event field {field} must be a non-empty string")
        if "event_id" in raw and (not isinstance(raw["event_id"], str) or not raw["event_id"].strip()):
            raise DetectionInputError("raw security event event_id must be a non-empty string when supplied")
        if raw.get("severity") is not None and not isinstance(raw["severity"], str):
            raise DetectionInputError("raw security event severity must be a string when supplied")
        for field in ("attributes", "ordering_metadata"):
            if field in raw and not isinstance(raw[field], dict):
                raise DetectionInputError(f"raw security event {field} must be a mapping")

    def ingest(self, event: SecurityEvent, *, scope: Scope | None = None):  # type: ignore[no-untyped-def]
        if scope is not None:
            self._require_scope(scope)
        self._validate(event, scope)
        return self.plane.ingest(event)

    def ingest_raw(self, raw: dict[str, Any], *, scope: Scope | None = None):  # type: ignore[no-untyped-def]
        self._validate_raw(raw)
        event = self.plane.normalize(raw)
        return self.ingest(event, scope=scope)

    def events(self, *, scope: Scope | None = None) -> tuple[SecurityEvent, ...]:
        requested = scope or self.scope
        if requested is None:
            raise DetectionScopeError("event reads require an explicit tenant/case/target scope")
        self._require_scope(requested)
        return tuple(
            event
            for event in self.plane.events(tenant=requested.tenant_id, case=requested.case_id)
            if event.target == requested.target_id
        )


def _field_value(event: SecurityEvent, field: str) -> Any:
    aliases: dict[str, Any] = {
        "event_id": event.event_id,
        "event.class": event.event_class.value,
        "event_class": event.event_class.value,
        "source": event.source,
        "source_type": event.source_type,
        "source_family": event.source_family,
        "ocsf_class": event.ocsf_class,
        "ocsf_version": event.ocsf_version,
        "tenant": event.tenant,
        "case": event.case,
        "target": event.target,
        "actor": event.actor,
        "user": event.actor,
        "object": event.object_ref,
        "object_ref": event.object_ref,
        "action": event.action,
        "outcome": event.outcome,
        "severity": event.severity,
        "raw_evidence_ref": event.raw_evidence_ref,
    }
    if field in aliases:
        return aliases[field]
    current: Any = event.attributes
    for part in field.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _value_matches(actual: Any, expected: Any, operator: str | None) -> bool:
    if isinstance(expected, list | tuple):
        return any(_value_matches(actual, item, operator) for item in expected)
    if operator == "exists":
        return (actual is not None) is bool(expected)
    if actual is None:
        return False
    if isinstance(actual, list | tuple | set):
        return any(_value_matches(item, expected, operator) for item in actual)
    actual_text = str(actual)
    expected_text = str(expected)
    if operator == "contains":
        return expected_text in actual_text
    if operator == "startswith":
        return actual_text.startswith(expected_text)
    if operator == "endswith":
        return actual_text.endswith(expected_text)
    if "*" in expected_text or "?" in expected_text:
        return fnmatch.fnmatchcase(actual_text, expected_text)
    return actual == expected or actual_text == expected_text


def _validate_predicates(predicates: Mapping[str, Any]) -> None:
    scalar = (str, int, float, bool)
    for raw_field, expected in predicates.items():
        if not isinstance(raw_field, str) or not raw_field.strip():
            raise DetectionInputError("predicate fields must be non-empty strings")
        if "|" in raw_field:
            field, operator = raw_field.rsplit("|", 1)
            if not field.strip() or operator not in {"contains", "startswith", "endswith"}:
                raise DetectionInputError("unsupported predicate modifier")
        if isinstance(expected, Mapping):
            raise DetectionInputError("nested predicate values are not supported")
        if isinstance(expected, (list, tuple)):
            if not expected or any(not isinstance(item, scalar) for item in expected):
                raise DetectionInputError("predicate lists must contain scalar values")
        elif not isinstance(expected, scalar):
            raise DetectionInputError("predicate values must be scalar or scalar lists")


def _matches(event: SecurityEvent, predicates: Mapping[str, Any]) -> tuple[bool, tuple[str, ...]]:
    _validate_predicates(predicates)
    matched: list[str] = []
    for raw_field, expected in predicates.items():
        if "|" in raw_field:
            field, operator = raw_field.rsplit("|", 1)
        else:
            field, operator = raw_field, None
        actual = _field_value(event, field)
        if not _value_matches(actual, expected, operator):
            return False, ()
        matched.append(raw_field)
    return True, tuple(matched)


class DetectionEngine:
    """Small deterministic rule engine with idempotent signal emission."""

    def __init__(
        self,
        events: BoundedSecurityEventIngestor,
        *,
        scope: Scope | None = None,
        engine_version: str = "secscan-detection-engine-v1",
        clock: Clock = utc_now,
    ) -> None:
        self.events = events
        self.scope = scope or events.scope
        self.engine_version = engine_version
        self.clock = clock
        self._rules: dict[tuple[str, int], DetectionRule] = {}
        self._plans: dict[tuple[str, int], DetectionPlan] = {}
        self._rule_bindings: dict[tuple[str, int], str] = {}
        self._plan_bindings: dict[tuple[str, int], str] = {}
        self._evaluations: dict[str, DetectionEvaluation] = {}
        self._signals: dict[str, DetectionSignal] = {}
        self._runs: dict[str, DetectionRun] = {}

    def _require_scope(self, scope: Scope) -> None:
        if self.scope is not None and self.scope != scope:
            raise DetectionScopeError("detection access crossed the bound tenant/case/target scope")

    @staticmethod
    def _binding_digest(value: Any) -> str:
        return content_digest(value.model_dump(mode="json", by_alias=True))

    def _assert_registered_binding(self, rule: DetectionRule, version: Any) -> None:
        key = (version.rule_id, version.version)
        if self._rule_bindings.get(key) != self._binding_digest(version):
            raise DetectionInputError("registered rule version content changed after binding")
        plan = self._plans.get(key)
        if plan is None or self._plan_bindings.get(key) != self._binding_digest(plan):
            raise DetectionInputError("registered detection plan content changed after binding")

    def register_rule(
        self,
        rule: DetectionRule,
        *,
        plan: DetectionPlan | None = None,
        version_number: int | None = None,
    ) -> DetectionPlan:
        try:
            version = rule.active if version_number is None else next(
                item for item in rule.versions if item.version == version_number
            )
        except StopIteration as exc:
            raise DetectionInputError("requested rule version is not present in the rule") from exc
        if version.status in {RuleStatus.DISABLED, RuleStatus.DEPRECATED}:
            raise DetectionInputError("disabled or deprecated rules cannot be registered for evaluation")
        if plan is None:
            plan = DetectionPlan(
                plan_id=stable_id("PLAN-", version.rule_id, version.version, version.content_digest),
                rule_id=version.rule_id,
                rule_version=version.version,
                rule_type=version.rule_type,
                content_digest=version.content_digest,
                event_schema=version.event_schema,
                supported_source_families=version.supported_source_families,
                predicates=version.predicates,
                correlation_keys=version.correlation_keys,
                window_seconds=version.window_seconds,
                threshold=version.threshold,
            )
        key = (version.rule_id, version.version)
        if key in self._rule_bindings and self._rule_bindings[key] != self._binding_digest(version):
            raise DetectionInputError("registered rule version content changed after binding")
        if key in self._plan_bindings:
            existing_plan = self._plans.get(key)
            if existing_plan is None or self._plan_bindings[key] != self._binding_digest(existing_plan):
                raise DetectionInputError("registered detection plan content changed after binding")
            if existing_plan != plan:
                raise DetectionInputError("rule version is already bound to a different detection plan")
        if plan.rule_id != version.rule_id or plan.rule_version != version.version:
            raise DetectionInputError("detection plan is bound to a different rule version")
        if plan.content_digest != version.content_digest:
            raise DetectionInputError("detection plan digest does not match the rule version")
        if (
            plan.rule_type != version.rule_type
            or plan.event_schema != version.event_schema
            or plan.supported_source_families != version.supported_source_families
            or plan.predicates != version.predicates
            or plan.correlation_keys != version.correlation_keys
            or plan.window_seconds != version.window_seconds
            or plan.threshold != version.threshold
        ):
            raise DetectionInputError("detection plan content does not match the rule version")
        _validate_predicates(plan.predicates)
        self._rules[key] = rule
        self._plans[key] = plan
        self._rule_bindings[key] = self._binding_digest(version)
        self._plan_bindings[key] = self._binding_digest(plan)
        return plan

    def _version(self, rule: DetectionRule | str, version: int | None = None):  # type: ignore[no-untyped-def]
        if isinstance(rule, DetectionRule):
            try:
                selected = rule.active if version is None else next(
                    item for item in rule.versions if item.version == version
                )
            except StopIteration as exc:
                raise DetectionInputError("requested rule version is not present in the rule") from exc
            return rule, selected
        if version is None:
            candidates = [item for (rule_id, _), item in self._rules.items() if rule_id == rule]
            if len(candidates) != 1:
                raise DetectionInputError("rule id requires one registered version")
            registered = candidates[0]
            selected = registered.active
            if (selected.rule_id, selected.version) not in self._plans:
                raise DetectionInputError("active rule version is not registered")
            self._assert_registered_binding(registered, selected)
            return registered, selected
        registered_rule = self._rules.get((rule, version))
        if registered_rule is None:
            raise DetectionInputError("rule version is not registered")
        try:
            selected = next(item for item in registered_rule.versions if item.version == version)
        except StopIteration as exc:
            raise DetectionInputError("registered rule does not contain the requested version") from exc
        self._assert_registered_binding(registered_rule, selected)
        return registered_rule, selected

    def run(self, rule: DetectionRule | str, *, scope: Scope | None = None, version: int | None = None) -> DetectionRun:
        requested = scope or self.scope
        if requested is None:
            raise DetectionScopeError("detection runs require an explicit scope")
        self._require_scope(requested)
        registered, selected = self._version(rule, version)
        if isinstance(rule, DetectionRule):
            self.register_rule(rule, version_number=selected.version)
        plan = self._plans[(selected.rule_id, selected.version)]
        source_events = tuple(
            event
            for event in self.events.events(scope=requested)
            if event.source_family in plan.supported_source_families
        )
        input_event_ids = tuple(event.event_id for event in source_events)
        run_id = stable_id("RUN-", requested.key(), selected.rule_id, selected.version, input_event_ids, plan.content_digest)
        existing_run = self._runs.get(run_id)
        if existing_run is not None:
            return existing_run
        started = self.clock().astimezone(UTC)
        evaluation_ids: list[str] = []
        signal_ids: list[str] = []
        if plan.rule_type == DetectionRuleType.EVENT_MATCH:
            for event in source_events:
                matched, predicates = _matches(event, plan.predicates)
                evaluation, signal = self._evaluate(
                    selected,
                    plan,
                    requested,
                    (event,),
                    predicates,
                    matched,
                    run_id=run_id,
                )
                evaluation_ids.append(evaluation.evaluation_id)
                if signal is not None:
                    signal_ids.append(signal.signal_id)
        else:
            groups: dict[tuple[Any, ...], list[SecurityEvent]] = defaultdict(list)
            for event in source_events:
                matched, _ = _matches(event, plan.predicates)
                if matched:
                    group_key = tuple(_field_value(event, key) for key in plan.correlation_keys)
                    if any(value is None or (isinstance(value, str) and not value.strip()) for value in group_key):
                        continue
                    try:
                        groups[group_key].append(event)
                    except TypeError as exc:
                        raise DetectionInputError("correlation keys must resolve to hashable values") from exc
            for group in groups.values():
                ordered = sorted(group, key=lambda item: (item.occurred_at, item.event_id))
                for end, event in enumerate(ordered):
                    window = [
                        candidate
                        for candidate in ordered[: end + 1]
                        if event.occurred_at - candidate.occurred_at <= timedelta(seconds=plan.window_seconds)
                    ]
                    if len(window) < plan.threshold:
                        continue
                    evaluation, signal = self._evaluate(
                        selected,
                        plan,
                        requested,
                        tuple(window),
                        ("COUNT_OVER_WINDOW",),
                        True,
                        run_id=run_id,
                    )
                    evaluation_ids.append(evaluation.evaluation_id)
                    if signal is not None:
                        signal_ids.append(signal.signal_id)
        completed = self.clock().astimezone(UTC)
        run = DetectionRun(
            run_id=run_id,
            scope=requested,
            rule_ids=(selected.rule_id,),
            input_event_ids=input_event_ids,
            evaluation_ids=tuple(dict.fromkeys(evaluation_ids)),
            signal_ids=tuple(dict.fromkeys(signal_ids)),
            engine_version=self.engine_version,
            started_at=started,
            completed_at=completed,
        )
        self._runs[run_id] = run
        return run

    def _evaluate(
        self,
        rule: Any,
        plan: DetectionPlan,
        scope: Scope,
        events: tuple[SecurityEvent, ...],
        predicates: tuple[str, ...],
        matched: bool,
        *,
        run_id: str,
    ) -> tuple[DetectionEvaluation, DetectionSignal | None]:
        event_ids = tuple(sorted(event.event_id for event in events))
        result = EvaluationResult.MATCH if matched else EvaluationResult.NO_MATCH
        evaluation_key = (scope.key(), rule.rule_id, rule.version, run_id, event_ids, result.value, plan.content_digest)
        evaluation_id = stable_id("EVAL-", evaluation_key)
        signal_id = stable_id("SIG-", scope.key(), rule.rule_id, rule.version, event_ids, plan.content_digest) if matched else None
        existing_evaluation = self._evaluations.get(evaluation_id)
        existing_signal = self._signals.get(signal_id) if signal_id is not None else None
        if existing_evaluation is not None:
            if existing_evaluation.result == EvaluationResult.MATCH and existing_signal is None:
                raise DetectionInputError("matched evaluation is missing its canonical signal")
            return existing_evaluation, existing_signal
        if existing_signal is not None:
            if (
                existing_signal.scope != scope
                or existing_signal.rule_id != rule.rule_id
                or existing_signal.rule_version != rule.version
                or existing_signal.event_ids != event_ids
                or existing_signal.matched_predicates != predicates
                or existing_signal.raw_evidence_refs != tuple(sorted({event.raw_evidence_ref for event in events}))
                or existing_signal.rule_digest != plan.content_digest
                or existing_signal.severity != rule.severity
                or existing_signal.confidence != rule.confidence
            ):
                raise DetectionInputError("signal identity was reused for different content")
        evaluation = DetectionEvaluation(
            evaluation_id=evaluation_id,
            run_id=run_id,
            scope=scope,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            input_event_ids=event_ids,
            evaluated_at=self.clock().astimezone(UTC),
            matched_predicates=predicates,
            result=result,
            signal_id=signal_id,
            engine_version=self.engine_version,
            rule_digest=plan.content_digest,
            idempotency_key=content_digest(evaluation_key),
        )
        self._evaluations[evaluation_id] = evaluation
        signal: DetectionSignal | None = None
        if matched and signal_id is not None:
            signal = DetectionSignal(
                signal_id=signal_id,
                scope=scope,
                rule_id=rule.rule_id,
                rule_version=rule.version,
                event_ids=event_ids,
                detected_at=self.clock().astimezone(UTC),
                severity=rule.severity,
                confidence=rule.confidence,
                matched_predicates=predicates,
                raw_evidence_refs=tuple(sorted({event.raw_evidence_ref for event in events})),
                rule_digest=plan.content_digest,
            )
            if existing_signal is None:
                self._signals[signal_id] = signal
            else:
                signal = existing_signal
        return evaluation, signal

    def signals(self, *, scope: Scope | None = None) -> tuple[DetectionSignal, ...]:
        requested = scope or self.scope
        if requested is None:
            raise DetectionScopeError("signal reads require an explicit scope")
        self._require_scope(requested)
        return tuple(sorted((item for item in self._signals.values() if item.scope == requested), key=lambda item: item.signal_id))

    def get_signal(self, signal_id: str, *, scope: Scope) -> DetectionSignal:
        self._require_scope(scope)
        signal = self._signals.get(signal_id)
        if signal is None or signal.scope != scope:
            raise DetectionScopeError("signal is absent or outside the requested scope")
        return signal

    def bind_signal(self, signal: DetectionSignal) -> None:
        """Hydrate one canonical signal into a fresh read-only engine view.

        The database remains the source of truth; this ephemeral index exists
        only so the existing hunt/adjudication engines can consume persisted
        signals after a process restart.
        """

        self._require_scope(signal.scope)
        existing = self._signals.get(signal.signal_id)
        if existing is not None and existing != signal:
            raise DetectionInputError("canonical signal identity was reused for different content")
        self._signals[signal.signal_id] = signal

    def evaluations(self, *, scope: Scope | None = None) -> tuple[DetectionEvaluation, ...]:
        requested = scope or self.scope
        if requested is None:
            raise DetectionScopeError("evaluation reads require an explicit scope")
        self._require_scope(requested)
        return tuple(sorted((item for item in self._evaluations.values() if item.scope == requested), key=lambda item: item.evaluation_id))

    def runs(self, *, scope: Scope | None = None) -> tuple[DetectionRun, ...]:
        requested = scope or self.scope
        if requested is None:
            raise DetectionScopeError("run reads require an explicit scope")
        self._require_scope(requested)
        return tuple(sorted((item for item in self._runs.values() if item.scope == requested), key=lambda item: item.run_id))


class ThreatHuntEngine:
    """Bounded event/signal hunts that stop at a typed HuntResult."""

    def __init__(self, events: BoundedSecurityEventIngestor, detections: DetectionEngine, *, clock: Clock = utc_now) -> None:
        self.events = events
        self.detections = detections
        self.clock = clock
        self._executions: dict[str, HuntExecution] = {}
        self._results: dict[str, HuntResult] = {}
        self._plan_bindings: dict[str, str] = {}
        self._hypothesis_bindings: dict[str, str] = {}

    def run(self, hypothesis: HuntHypothesis, plan: HuntPlan) -> HuntResult:
        if (
            hypothesis.hypothesis_id != plan.hypothesis_id
            or hypothesis.scope != plan.scope
            or self.detections.scope not in (None, plan.scope)
        ):
            raise DetectionScopeError("hunt scope does not match its hypothesis or detector")
        hypothesis_digest = content_digest(
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "scope": hypothesis.scope.model_dump(mode="json", by_alias=True),
                "question": hypothesis.question,
                "entity_keys": hypothesis.entity_keys,
                "supporting_signal_ids": hypothesis.supporting_signal_ids,
                "required_evidence_refs": hypothesis.required_evidence_refs,
            }
        )
        existing_hypothesis_digest = self._hypothesis_bindings.get(hypothesis.hypothesis_id)
        if existing_hypothesis_digest is not None and existing_hypothesis_digest != hypothesis_digest:
            raise DetectionInputError("hunt hypothesis identity was reused for different content")
        self._hypothesis_bindings[hypothesis.hypothesis_id] = hypothesis_digest
        plan_digest = content_digest(plan.model_dump(mode="json", by_alias=True))
        existing_plan_digest = self._plan_bindings.get(plan.plan_id)
        if existing_plan_digest is not None and existing_plan_digest != plan_digest:
            raise DetectionInputError("hunt plan identity was reused for different content")
        self._plan_bindings[plan.plan_id] = plan_digest
        available = [
            event
            for event in self.events.events(scope=plan.scope)
            if plan.window_start <= event.occurred_at <= plan.window_end
        ]
        if len(available) > plan.max_events:
            raise DetectionInputError("hunt exceeded its bounded event limit")
        event_query = plan.query.get("event", plan.query)
        if not isinstance(event_query, Mapping):
            raise DetectionInputError("hunt event query must be a mapping")
        matched_events = tuple(event for event in available if _matches(event, event_query)[0])
        raw_signal_ids = plan.query.get("signal_ids", hypothesis.supporting_signal_ids)
        if not isinstance(raw_signal_ids, (list, tuple, set)):
            raise DetectionInputError("hunt signal_ids must be a bounded sequence")
        requested_signals = {str(item) for item in raw_signal_ids}
        signals = self.detections.signals(scope=plan.scope)
        available_event_ids = {event.event_id for event in available}
        signals_by_id = {signal.signal_id: signal for signal in signals}

        def signal_is_in_window(signal_id: str, seen: frozenset[str] = frozenset()) -> bool:
            if signal_id in seen:
                return False
            signal = signals_by_id.get(signal_id)
            if signal is None:
                return False
            next_seen = seen | {signal_id}
            if signal.event_ids and not all(event_id in available_event_ids for event_id in signal.event_ids):
                return False
            if signal.source_signal_ids and not all(
                signal_is_in_window(source_id, next_seen) for source_id in signal.source_signal_ids
            ):
                return False
            return bool(signal.event_ids or signal.source_signal_ids)

        matched_signals = tuple(
            signal
            for signal in signals
            if signal.signal_id in requested_signals and signal_is_in_window(signal.signal_id)
        )
        event_ids = tuple(event.event_id for event in matched_events)
        signal_ids = tuple(signal.signal_id for signal in matched_signals)
        evidence_refs = tuple(sorted({event.raw_evidence_ref for event in matched_events} | {
            ref for signal in matched_signals for ref in signal.raw_evidence_refs
        }))
        disposition = HuntDisposition.SUPPORTS if event_ids or signal_ids else HuntDisposition.REFUTES
        query_digest = content_digest(plan.query)
        execution_id = stable_id(
            "HUNT-EXEC-", plan.plan_id, hypothesis.hypothesis_id, plan.scope.key(), query_digest, event_ids, signal_ids
        )
        result_id = stable_id("HUNT-RESULT-", execution_id)
        existing_execution = self._executions.get(execution_id)
        existing_result = self._results.get(result_id)
        if existing_execution is not None or existing_result is not None:
            if existing_execution is None or existing_result is None:
                raise DetectionInputError("hunt execution identity has incomplete canonical state")
            if (
                existing_execution.plan_id != plan.plan_id
                or existing_execution.scope != plan.scope
                or existing_execution.query_digest != query_digest
                or existing_execution.input_event_ids != event_ids
                or existing_execution.input_signal_ids != signal_ids
                or existing_execution.result_id != result_id
                or existing_result.execution_id != execution_id
                or existing_result.hypothesis_id != hypothesis.hypothesis_id
                or existing_result.scope != plan.scope
                or existing_result.disposition != disposition
                or existing_result.event_ids != event_ids
                or existing_result.signal_ids != signal_ids
                or existing_result.supporting_evidence_refs
                != (evidence_refs if disposition == HuntDisposition.SUPPORTS else ())
                or existing_result.refuting_evidence_refs
                != (() if disposition == HuntDisposition.SUPPORTS else tuple(sorted(event.raw_evidence_ref for event in available)))
            ):
                raise DetectionInputError("hunt execution identity was reused for different content")
            return existing_result
        now = self.clock().astimezone(UTC)
        execution = HuntExecution(
            execution_id=execution_id,
            plan_id=plan.plan_id,
            scope=plan.scope,
            query_digest=query_digest,
            input_event_ids=event_ids,
            input_signal_ids=signal_ids,
            started_at=now,
            completed_at=self.clock().astimezone(UTC),
            result_id=result_id,
        )
        result = HuntResult(
            result_id=result_id,
            execution_id=execution_id,
            hypothesis_id=hypothesis.hypothesis_id,
            scope=plan.scope,
            disposition=disposition,
            event_ids=event_ids,
            signal_ids=signal_ids,
            supporting_evidence_refs=evidence_refs if disposition == HuntDisposition.SUPPORTS else (),
            refuting_evidence_refs=() if disposition == HuntDisposition.SUPPORTS else tuple(
                sorted(event.raw_evidence_ref for event in available)
            ),
            result_digest=content_digest((hypothesis.hypothesis_id, plan.plan_id, disposition.value, event_ids, signal_ids)),
        )
        self._executions[execution_id] = execution
        self._results[result_id] = result
        return result

    def results(self, *, scope: Scope) -> tuple[HuntResult, ...]:
        if self.detections.scope is not None and self.detections.scope != scope:
            raise DetectionScopeError("hunt result access crossed its bound scope")
        return tuple(sorted((item for item in self._results.values() if item.scope == scope), key=lambda item: item.result_id))

    def execution(self, result_id: str, *, scope: Scope) -> HuntExecution:
        """Return the execution paired with a bounded result."""

        if self.detections.scope is not None and self.detections.scope != scope:
            raise DetectionScopeError("hunt execution access crossed its bound scope")
        result = self._results.get(result_id)
        if result is None or result.scope != scope:
            raise DetectionScopeError("hunt result is absent or outside the requested scope")
        execution = self._executions.get(result.execution_id)
        if execution is None:
            raise DetectionInputError("hunt result is missing its canonical execution")
        return execution


class IncidentAdjudicator:
    """Create operational incidents only from scoped, evidence-backed claims."""

    def __init__(
        self,
        detections: DetectionEngine,
        *,
        scope: Scope | None = None,
        canonical_adjudicator_ids: Iterable[str] = (),
        canonical_claims: Mapping[str, Claim] | None = None,
        canonical_claim_evidence_refs: Mapping[str, Iterable[str]] | None = None,
        clock: Clock = utc_now,
    ) -> None:
        self.detections = detections
        self.scope = scope or detections.scope
        self.canonical_adjudicator_ids = frozenset(canonical_adjudicator_ids)
        self.canonical_claims = {
            claim_id: claim.model_copy(deep=True) if isinstance(claim, Claim) else claim
            for claim_id, claim in (canonical_claims or {}).items()
        }
        self.canonical_claim_evidence_refs = (
            None
            if canonical_claim_evidence_refs is None
            else {claim_id: tuple(refs) for claim_id, refs in canonical_claim_evidence_refs.items()}
        )
        self.clock = clock
        self._incidents: dict[str, Incident] = {}
        self._adjudications: dict[str, IncidentAdjudication] = {}
        self._investigations: dict[str, IncidentInvestigation] = {}
        self._hypotheses: dict[str, IncidentHypothesis] = {}

    def adjudicate(
        self,
        hypothesis: IncidentHypothesis,
        *,
        supporting_claim_ids: Sequence[str],
        supporting_evidence_refs: Sequence[str],
        contradicting_claim_ids: Sequence[str] = (),
        contradicting_evidence_refs: Sequence[str] = (),
        decided_by: str,
        reason: str,
        severity: Severity,
        confidence: Confidence,
        observation_ids: Sequence[str] = (),
    ) -> Incident:
        if self.scope is not None and hypothesis.scope != self.scope:
            raise DetectionScopeError("incident hypothesis crossed its bound scope")
        if not supporting_claim_ids or not supporting_evidence_refs:
            raise AdjudicationRefused("an Incident requires supporting claims and evidence references")
        if not isinstance(decided_by, str) or decided_by not in self.canonical_adjudicator_ids:
            raise AdjudicationRefused("incident adjudication requires a canonical human authority")
        claim_ids = (*supporting_claim_ids, *contradicting_claim_ids)
        if any(not isinstance(item, str) or not item.strip() for item in claim_ids):
            raise AdjudicationRefused("incident adjudication requires non-empty claim references")
        normalized_supporting_claim_ids = tuple(sorted(set(supporting_claim_ids)))
        normalized_contradicting_claim_ids = tuple(sorted(set(contradicting_claim_ids)))
        canonical_claim_records: list[Claim] = []
        canonical_claim_by_id: dict[str, Claim] = {}
        for claim_id in claim_ids:
            claim = self.canonical_claims.get(claim_id)
            if (
                not isinstance(claim, Claim)
                or str(claim.claim_id) != claim_id
                or str(claim.engagement_id) != hypothesis.scope.case_id
                or (not claim.evidence_ids and not claim.observation_ids)
            ):
                raise AdjudicationRefused("incident adjudication requires canonical, evidence-grounded claims")
            canonical_claim_records.append(claim)
            canonical_claim_by_id[claim_id] = claim
        evidence_refs = (*supporting_evidence_refs, *contradicting_evidence_refs)
        if any(not isinstance(item, str) or not item.strip() for item in evidence_refs):
            raise AdjudicationRefused("incident adjudication requires non-empty evidence references")
        if any(token in decided_by.lower() for token in ("llm", "model", "agent-opinion")):
            raise AdjudicationRefused("incident adjudication requires an accountable authority")
        signals = tuple(self.detections.get_signal(signal_id, scope=hypothesis.scope) for signal_id in hypothesis.source_signal_ids)
        if not signals:
            raise AdjudicationRefused("incident hypothesis has no verifiable source signals")
        canonical_evidence_refs = {
            event.raw_evidence_ref for event in self.detections.events.events(scope=hypothesis.scope)
        }
        if not set(evidence_refs).issubset(canonical_evidence_refs):
            raise AdjudicationRefused("incident evidence references are not bound to canonical events")
        signal_evidence_refs = {
            evidence_ref
            for signal in signals
            for evidence_ref in signal.raw_evidence_refs
        }
        if not set(evidence_refs).issubset(signal_evidence_refs):
            raise AdjudicationRefused("incident evidence references are not bound to its source signals")
        claim_evidence_refs: dict[str, frozenset[str]] = {}
        for claim_id, claim in canonical_claim_by_id.items():
            raw_refs = (
                self.canonical_claim_evidence_refs.get(claim_id, ())
                if self.canonical_claim_evidence_refs is not None
                else tuple(str(item) for item in claim.evidence_ids)
            )
            if any(not isinstance(item, str) or not item.strip() for item in raw_refs):
                raise AdjudicationRefused("incident claim evidence references are invalid")
            refs = frozenset(raw_refs)
            if not refs:
                raise AdjudicationRefused("incident adjudication requires canonical claim evidence")
            claim_evidence_refs[claim_id] = refs
        supporting_claim_evidence_refs = set().union(
            *(claim_evidence_refs[claim_id] for claim_id in normalized_supporting_claim_ids)
        )
        if not set(supporting_evidence_refs).issubset(supporting_claim_evidence_refs):
            raise AdjudicationRefused("supporting incident evidence is not bound to its supporting claims")
        contradicting_claim_evidence_refs = set().union(
            *(claim_evidence_refs[claim_id] for claim_id in normalized_contradicting_claim_ids)
        )
        if not set(contradicting_evidence_refs).issubset(contradicting_claim_evidence_refs):
            raise AdjudicationRefused("contradicting incident evidence is not bound to its contradicting claims")
        normalized_supporting_evidence_refs = tuple(sorted(set(supporting_evidence_refs)))
        normalized_contradicting_evidence_refs = tuple(sorted(set(contradicting_evidence_refs)))
        if any(not isinstance(item, str) or not item.strip() for item in observation_ids):
            raise AdjudicationRefused("incident observation references must be non-empty strings")
        normalized_observation_ids = tuple(sorted(set(observation_ids)))
        canonical_observation_ids = {
            observation_id
            for claim in canonical_claim_records
            for observation_id in claim.observation_ids
        }
        if not set(normalized_observation_ids).issubset(canonical_observation_ids):
            raise AdjudicationRefused("incident observations are not bound to canonical claims")
        existing_hypothesis = self._hypotheses.get(hypothesis.hypothesis_id)
        if existing_hypothesis is not None and (
            existing_hypothesis.scope != hypothesis.scope
            or existing_hypothesis.question != hypothesis.question
            or existing_hypothesis.source_signal_ids != hypothesis.source_signal_ids
            or existing_hypothesis.affected_entities != hypothesis.affected_entities
        ):
            raise AdjudicationRefused("incident hypothesis identity was reused for different content")
        investigation_id = stable_id(
            "INV-", hypothesis.hypothesis_id, normalized_observation_ids, normalized_supporting_claim_ids
        )
        adjudication_id = stable_id(
            "ADJ-",
            hypothesis.scope.key(),
            hypothesis.hypothesis_id,
            normalized_supporting_claim_ids,
            normalized_supporting_evidence_refs,
            normalized_contradicting_claim_ids,
            normalized_contradicting_evidence_refs,
        )
        incident_id = stable_id("INC-", adjudication_id, hypothesis.scope.key())
        state = (
            IncidentState.CANDIDATE
            if normalized_contradicting_claim_ids or normalized_contradicting_evidence_refs
            else IncidentState.CONFIRMED
        )

        existing_adjudication = self._adjudications.get(adjudication_id)
        existing_incident = self._incidents.get(incident_id)
        if existing_adjudication is not None or existing_incident is not None:
            if existing_adjudication is None or existing_incident is None:
                raise AdjudicationRefused("adjudication identity has incomplete canonical state")
            if (
                existing_adjudication.hypothesis_id != hypothesis.hypothesis_id
                or existing_adjudication.scope != hypothesis.scope
                or existing_adjudication.supporting_claim_ids != normalized_supporting_claim_ids
                or existing_adjudication.supporting_evidence_refs != normalized_supporting_evidence_refs
                or existing_adjudication.contradicting_claim_ids != normalized_contradicting_claim_ids
                or existing_adjudication.contradicting_evidence_refs != normalized_contradicting_evidence_refs
                or existing_adjudication.decided_by != decided_by
                or existing_adjudication.reason != reason
                or existing_adjudication.confidence != confidence
                or existing_adjudication.severity != severity
                or existing_incident.hypothesis_id != hypothesis.hypothesis_id
                or existing_incident.investigation_id != investigation_id
                or existing_incident.adjudication_id != adjudication_id
                or existing_incident.scope != hypothesis.scope
                or existing_incident.state != state
                or existing_incident.severity != severity
                or existing_incident.confidence != confidence
                or existing_incident.source_signal_ids != hypothesis.source_signal_ids
                or existing_incident.observation_ids != normalized_observation_ids
                or existing_incident.claim_ids != normalized_supporting_claim_ids
                or existing_incident.supporting_evidence_refs != normalized_supporting_evidence_refs
                or existing_incident.contradicting_evidence_refs != normalized_contradicting_evidence_refs
            ):
                raise AdjudicationRefused("adjudication identity was reused for different content")
            return existing_incident
        now = self.clock().astimezone(UTC)
        investigation = IncidentInvestigation(
            investigation_id=investigation_id,
            hypothesis_id=hypothesis.hypothesis_id,
            scope=hypothesis.scope,
            observation_ids=normalized_observation_ids,
            claim_ids=normalized_supporting_claim_ids,
            opened_at=now,
        )
        adjudication = IncidentAdjudication(
            adjudication_id=adjudication_id,
            hypothesis_id=hypothesis.hypothesis_id,
            scope=hypothesis.scope,
            supporting_claim_ids=normalized_supporting_claim_ids,
            supporting_evidence_refs=normalized_supporting_evidence_refs,
            contradicting_claim_ids=normalized_contradicting_claim_ids,
            contradicting_evidence_refs=normalized_contradicting_evidence_refs,
            decided_by=decided_by,
            decided_at=now,
            reason=reason,
            confidence=confidence,
            severity=severity,
        )
        incident = Incident(
            incident_id=incident_id,
            hypothesis_id=hypothesis.hypothesis_id,
            investigation_id=investigation_id,
            adjudication_id=adjudication_id,
            scope=hypothesis.scope,
            state=state,
            severity=severity,
            confidence=confidence,
            source_signal_ids=hypothesis.source_signal_ids,
            observation_ids=normalized_observation_ids,
            claim_ids=normalized_supporting_claim_ids,
            supporting_evidence_refs=normalized_supporting_evidence_refs,
            contradicting_evidence_refs=normalized_contradicting_evidence_refs,
            adjudicated_at=now,
        )
        self._investigations[investigation_id] = investigation
        self._adjudications[adjudication_id] = adjudication
        self._incidents[incident_id] = incident
        self._hypotheses[hypothesis.hypothesis_id] = hypothesis.model_copy(deep=True)
        return incident

    def get(self, incident_id: str, *, scope: Scope) -> Incident:
        if self.scope is not None and self.scope != scope:
            raise DetectionScopeError("incident access crossed its bound scope")
        incident = self._incidents.get(incident_id)
        if incident is None or incident.scope != scope:
            raise DetectionScopeError("incident is absent or outside the requested scope")
        return incident

    def get_adjudication(self, incident_id: str, *, scope: Scope) -> IncidentAdjudication:
        """Return the adjudication paired with a canonical incident."""

        incident = self.get(incident_id, scope=scope)
        adjudication = self._adjudications.get(incident.adjudication_id)
        if adjudication is None:
            raise DetectionInputError("incident is missing its canonical adjudication")
        return adjudication

    def get_investigation(self, incident_id: str, *, scope: Scope) -> IncidentInvestigation:
        """Return the investigation paired with a canonical incident."""

        incident = self.get(incident_id, scope=scope)
        investigation = self._investigations.get(incident.investigation_id)
        if investigation is None:
            raise DetectionInputError("incident is missing its canonical investigation")
        return investigation

    def incidents(self, *, scope: Scope) -> tuple[Incident, ...]:
        if self.scope is not None and self.scope != scope:
            raise DetectionScopeError("incident access crossed its bound scope")
        return tuple(sorted((item for item in self._incidents.values() if item.scope == scope), key=lambda item: item.incident_id))


class ApprovalRequiredPolicy:
    """Deterministic policy double for unit tests; not an OPA integration."""

    def __init__(self, decision: OpaDecision = OpaDecision.REQUIRE_APPROVAL) -> None:
        self.decision = decision

    def decide(self, _context: Mapping[str, Any]) -> OpaDecision:
        return self.decision


class OpaResponsePolicy:
    """Adapt the pinned OPA authority kernel to the non-executing response seam."""

    def __init__(self, client: Any | None = None) -> None:
        if client is None:
            from secscan.platform.policy import OpaSubprocessClient

            client = OpaSubprocessClient()
        self.client = client

    def decide(self, context: Mapping[str, Any]) -> OpaDecision:
        scope = context.get("scope")
        if not isinstance(scope, Mapping):
            return OpaDecision.DENY
        target_id = context.get("target_id")
        case_id = scope.get("case")
        if not isinstance(target_id, str) or not target_id.strip() or not isinstance(case_id, str) or not case_id.strip():
            return OpaDecision.DENY
        proposal_binding = content_digest(context)
        capability_id = "CAP-V03-RESPONSE-PROPOSAL"
        principal_id = "secscan-v03-response-authority"
        request = {
            "principal": {"id": principal_id},
            "agent": {"id": "secscan-v03-response-service"},
            "engagement": {
                "id": case_id,
                "status": "adjudication",
                "authority_level": "remediation",
                "target_ids": [target_id],
            },
            "target": {"id": target_id},
            "capability": {
                "id": capability_id,
                "registered": True,
                "risk_class": "high",
                "requires_approval": True,
                "required_authority": "remediate",
            },
            "action": "remediate",
            "risk": "high",
            "authority_grant": {
                "matched": True,
                "grant_ids": [proposal_binding],
                "principal_id": principal_id,
                "engagement_id": case_id,
                "capability_id": capability_id,
                "target_id": target_id,
                "action": "remediate",
            },
            "approval": {
                "id": "",
                "recorded": False,
                "decision": "pending",
                "target_id": "",
                "capability_id": "",
                "action": "",
                "engagement_id": "",
                "decided_by_principal_id": "",
            },
            "workflow_phase": "adjudication",
            "requested_resources": {"response_proposal": proposal_binding},
        }
        try:
            decision = self.client.decide(request)
        except Exception:
            return OpaDecision.DENY
        value = getattr(decision, "value", decision)
        return OpaDecision.REQUIRE_APPROVAL if value == "require_approval" else OpaDecision.DENY


class ResponseProposalService:
    """OPA-bound proposal lifecycle with an intentionally absent executor."""

    def __init__(
        self,
        policy: ResponsePolicyPort | None = None,
        *,
        scope: Scope | None = None,
        canonical_incidents: Mapping[str, Incident] | None = None,
        canonical_approvals: Mapping[str, HumanApproval] | None = None,
        canonical_approver_ids: Iterable[str] = (),
        clock: Clock = utc_now,
    ) -> None:
        self.policy = policy or OpaResponsePolicy()
        self.scope = scope
        self.canonical_incidents = canonical_incidents if canonical_incidents is not None else {}
        self.canonical_approvals = canonical_approvals if canonical_approvals is not None else {}
        self.canonical_approver_ids = frozenset(canonical_approver_ids)
        self.clock = clock
        self._proposals: dict[str, ResponseProposal] = {}
        self._requests: dict[str, CapabilityRequest] = {}

    def _require_scope(self, scope: Scope) -> None:
        if self.scope is not None and self.scope != scope:
            raise DetectionScopeError("response access crossed the bound tenant/case/target scope")

    def propose(
        self,
        incident: Incident,
        *,
        action: ResponseAction,
        reason: str,
        expected_impact: str,
        risk: str,
        rollback_plan: str,
        expires_at: datetime,
    ) -> ResponseProposal:
        self._require_scope(incident.scope)
        canonical_incident = self.canonical_incidents.get(incident.incident_id)
        if canonical_incident is None or canonical_incident != incident:
            raise ResponseAuthorizationError("response proposal requires the canonical adjudicated incident")
        if incident.state != IncidentState.CONFIRMED:
            raise ResponseAuthorizationError("response proposals require a CONFIRMED incident")
        now = self.clock().astimezone(UTC)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ResponseAuthorizationError("response proposal expiration must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now:
            raise ResponseAuthorizationError("response proposal expiration must be in the future")
        if not incident.supporting_evidence_refs:
            raise ResponseAuthorizationError("response proposal requires incident evidence")
        base = {
            "incident_id": incident.incident_id,
            "scope": incident.scope.model_dump(mode="json", by_alias=True),
            "target_id": incident.scope.target_id,
            "action": action.value,
            "reason": reason,
            "supporting_evidence_refs": sorted(incident.supporting_evidence_refs),
            "expected_impact": expected_impact,
            "risk": risk,
            "rollback_plan": rollback_plan,
            "expires_at": expiry.isoformat(),
        }
        proposal_digest = content_digest(base)
        proposal_id = stable_id("RP-", proposal_digest)
        existing = self._proposals.get(proposal_id)
        if existing is not None:
            if (
                existing.incident_id != incident.incident_id
                or existing.scope != incident.scope
                or existing.target_id != incident.scope.target_id
                or existing.action != action
                or existing.reason != reason
                or existing.supporting_evidence_refs != tuple(sorted(incident.supporting_evidence_refs))
                or existing.expected_impact != expected_impact
                or existing.risk != risk
                or existing.rollback_plan != rollback_plan
                or existing.expires_at != expiry
                or existing.proposal_digest != proposal_digest
            ):
                raise ResponseAuthorizationError("response proposal identity was reused for different content")
            return existing
        decision = self.policy.decide(base)
        if not isinstance(decision, OpaDecision):
            decision = OpaDecision.DENY
        state = HumanApprovalState.DENIED if decision == OpaDecision.DENY else HumanApprovalState.APPROVAL_REQUIRED
        proposal = ResponseProposal(
            proposal_id=proposal_id,
            incident_id=incident.incident_id,
            scope=incident.scope,
            target_id=incident.scope.target_id,
            action=action,
            reason=reason,
            supporting_evidence_refs=tuple(sorted(incident.supporting_evidence_refs)),
            expected_impact=expected_impact,
            risk=risk,
            rollback_plan=rollback_plan,
            expires_at=expiry,
            proposal_digest=proposal_digest,
            opa_decision=decision,
            human_approval_state=state,
        )
        self._proposals[proposal_id] = proposal
        return proposal

    def capability_request(self, proposal: ResponseProposal, *, scope: Scope | None = None) -> CapabilityRequest:
        requested = scope or proposal.scope
        self._require_scope(requested)
        stored = self._proposals.get(proposal.proposal_id)
        if stored is None or stored.proposal_digest != proposal.proposal_digest or stored.scope != requested:
            raise ResponseAuthorizationError("capability request was not bound to the canonical proposal")
        if stored.human_approval_state != HumanApprovalState.APPROVAL_REQUIRED:
            raise ResponseAuthorizationError("capability request is not approval-gated")
        request_id = stable_id("CAPREQ-", stored.proposal_id, stored.proposal_digest)
        request = CapabilityRequest(
            request_id=request_id,
            proposal_id=stored.proposal_id,
            scope=stored.scope,
            target_id=stored.target_id,
            action=stored.action,
            proposal_digest=stored.proposal_digest,
            requested_at=self.clock().astimezone(UTC),
        )
        existing_request = self._requests.get(request_id)
        if existing_request is not None:
            if (
                existing_request.proposal_id != request.proposal_id
                or existing_request.scope != request.scope
                or existing_request.target_id != request.target_id
                or existing_request.action != request.action
                or existing_request.proposal_digest != request.proposal_digest
            ):
                raise ResponseAuthorizationError("capability request identity was reused for different content")
            return existing_request
        self._requests[request_id] = request
        return request

    def bind_canonical_proposal(self, proposal: ResponseProposal) -> ResponseProposal:
        """Hydrate an already OPA-evaluated proposal after a process restart."""

        self._require_scope(proposal.scope)
        canonical = self.canonical_incidents.get(proposal.incident_id)
        if canonical is None or canonical.state != IncidentState.CONFIRMED:
            raise ResponseAuthorizationError("response proposal requires the canonical adjudicated incident")
        if not proposal.supporting_evidence_refs or proposal.authorized_action_executed:
            raise ResponseAuthorizationError("canonical response proposal is not approval-eligible")
        existing = self._proposals.get(proposal.proposal_id)
        if existing is not None and existing != proposal:
            raise ResponseAuthorizationError("response proposal identity was reused for different content")
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    def approve(self, approval: HumanApproval) -> ResponseProposal:
        canonical_approval = self.canonical_approvals.get(approval.approval_id)
        if canonical_approval is None or canonical_approval != approval:
            raise ResponseAuthorizationError("approval is not the canonical approval record")
        if approval.decided_by not in self.canonical_approver_ids:
            raise ResponseAuthorizationError("approval is not bound to a canonical human approver")
        proposal = self._proposals.get(approval.proposal_id)
        if proposal is None:
            raise ResponseAuthorizationError("approval references an unknown proposal")
        now = self.clock().astimezone(UTC)
        if proposal.expires_at <= now or approval.expires_at <= now:
            raise ResponseAuthorizationError("approval or proposal is expired")
        if approval.decided_at > now:
            raise ResponseAuthorizationError("approval decision cannot be dated in the future")
        if approval.expires_at > proposal.expires_at:
            raise ResponseAuthorizationError("approval cannot outlive the response proposal")
        if approval.expires_at < approval.decided_at:
            raise ResponseAuthorizationError("approval expiration cannot precede its decision")
        if approval.source != "human_operator" or approval.decision != HumanApprovalState.APPROVED:
            raise ResponseAuthorizationError("only an exact human_operator approval can approve a proposal")
        if (
            approval.proposal_digest != proposal.proposal_digest
            or approval.scope != proposal.scope
            or approval.target_id != proposal.target_id
            or approval.action != proposal.action
        ):
            raise ResponseAuthorizationError("approval is not bound to the exact proposal scope and digest")
        if proposal.opa_decision == OpaDecision.DENY:
            raise ResponseAuthorizationError("OPA denied the response proposal")
        updated = proposal.model_copy(update={"human_approval_state": HumanApprovalState.APPROVED})
        self._proposals[proposal.proposal_id] = updated
        return updated

    def get(self, proposal_id: str, *, scope: Scope) -> ResponseProposal:
        self._require_scope(scope)
        proposal = self._proposals.get(proposal_id)
        if proposal is None or proposal.scope != scope:
            raise DetectionScopeError("response proposal is absent or outside the requested scope")
        return proposal

    def proposals(self, *, scope: Scope) -> tuple[ResponseProposal, ...]:
        self._require_scope(scope)
        return tuple(sorted((item for item in self._proposals.values() if item.scope == scope), key=lambda item: item.proposal_id))

    def execute(self, proposal_id: str, *, scope: Scope) -> None:
        self.get(proposal_id, scope=scope)
        raise ResponseExecutionDisabled("AUTHORIZED_ACTION_EXECUTED=NO: v0.3 has no response executor")
