"""Fixture-only detection evaluation helpers."""

from __future__ import annotations

from typing import Sequence

from secscan.platform.continuous_security.events import SecurityEventPlane

from .domain import (
    DetectionRule,
    EvaluationReport,
    FixtureLabel,
    LabeledFixture,
    RuleEvaluationMetrics,
    Scope,
    content_digest,
)
from .engine import BoundedSecurityEventIngestor, DetectionEngine


class DetectionEvaluator:
    """Evaluate one rule against isolated, explicitly labeled fixtures."""

    def evaluate(self, rule: DetectionRule, fixtures: Sequence[LabeledFixture]) -> RuleEvaluationMetrics:
        if not fixtures:
            raise ValueError("fixture evaluation requires at least one fixture")
        tp = fp = tn = fn = near = 0
        for fixture in fixtures:
            if fixture.rule_id != rule.rule_id:
                raise ValueError("fixture is bound to a different rule")
            plane = SecurityEventPlane()
            scope = Scope(tenant=fixture.event.tenant, case=fixture.event.case, target=fixture.event.target)
            ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
            ingestor.ingest(fixture.event, scope=scope)
            engine = DetectionEngine(ingestor, scope=scope)
            run = engine.run(rule)
            detected = bool(run.signal_ids)
            if fixture.label == FixtureLabel.EXPECTED_MATCH:
                if detected:
                    tp += 1
                else:
                    fn += 1
            elif fixture.label == FixtureLabel.EXPECTED_NO_MATCH:
                if detected:
                    fp += 1
                else:
                    tn += 1
            else:
                near += 1
        denominator_precision = tp + fp
        denominator_recall = tp + fn
        return RuleEvaluationMetrics(
            rule_id=rule.rule_id,
            true_positive=tp,
            false_positive=fp,
            true_negative=tn,
            false_negative=fn,
            precision=tp / denominator_precision if denominator_precision else 0.0,
            recall=tp / denominator_recall if denominator_recall else 0.0,
            near_miss_count=near,
        )

    @staticmethod
    def report(metrics: Sequence[RuleEvaluationMetrics], *, mutation_inputs: Sequence[object]) -> EvaluationReport:
        return EvaluationReport(
            rules=tuple(metrics),
            mutation_digests=tuple(content_digest(item) for item in mutation_inputs),
        )
