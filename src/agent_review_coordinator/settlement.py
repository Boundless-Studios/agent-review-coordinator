"""Review settlement independent of providers and PR hosts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .findings import (
    Disposition,
    Finding,
    FixCost,
    Impact,
    Reachability,
    Severity,
)
from .ledger import ReviewLedger
from .policy import ReviewPolicy, ReviewStage, ReviewStagePolicy


class FindingSettlementState(StrEnum):
    """Normalized durable outcome for one finding."""

    FIXED = "fixed"
    DECLINED_WITH_RATIONALE = "declined_with_rationale"
    DEFERRED_TO_EXISTING_ISSUE = "deferred_to_existing_issue"
    UNRESOLVED = "unresolved"


class SettlementReport(BaseModel):
    """Machine-readable work remaining for the current review snapshot."""

    model_config = ConfigDict(extra="forbid")

    settled: bool
    required_actions: list[str] = Field(default_factory=list)
    blocking_fingerprints: list[str] = Field(default_factory=list)
    finding_states: dict[str, FindingSettlementState] = Field(default_factory=dict)
    missing_slots: list[str] = Field(default_factory=list)
    allow_full_review: bool
    allow_targeted_verification: bool


def _missing_for_stage(
    *,
    stage: ReviewStage,
    stage_policy: ReviewStagePolicy,
    ledger: ReviewLedger,
) -> list[str]:
    results = [
        result
        for result in ledger.results
        if not result.stale and result.stage is stage
    ]
    results_by_slot = {
        result.slot_number: result
        for result in results
        if result.slot_number <= stage_policy.reviewer_count
    }
    required = stage_policy.required_results or stage_policy.reviewer_count
    qualifying_count = len(results_by_slot)
    if stage_policy.distinct_executions:
        qualifying_count = min(
            qualifying_count,
            len({result.reviewer_execution_id for result in results_by_slot.values()}),
        )
    missing = [
        f"{stage.value}:{slot_number}"
        for slot_number in range(qualifying_count + 1, required + 1)
    ]
    if stage_policy.distinct_providers:
        providers = {
            result.reviewer_provider
            for result in results_by_slot.values()
            if result.reviewer_provider
        }
        if len(providers) < required:
            missing.append(f"{stage.value}:provider-diversity")
    return missing


def _finding_action(finding: Finding) -> str | None:
    disposition = finding.disposition
    if finding.severity in {Severity.P0, Severity.P1}:
        if disposition is Disposition.FIXED:
            return None if finding.verification_passed else "verify_fix"
        if disposition in {Disposition.REJECT, Disposition.STALE} and finding.evidence:
            return None
        if disposition is Disposition.DUPLICATE and finding.duplicate_of:
            return None
        return f"address_{finding.severity.value}"

    if finding.severity is Severity.P3:
        return None

    if disposition is None:
        return "evaluate_p2"
    if disposition is Disposition.FIX_NOW:
        return "fix_p2"
    if disposition is Disposition.PROVE_FIRST:
        return "fix_reproduced_p2" if finding.reproduction else "prove_p2"
    if disposition is Disposition.FIXED:
        return None if finding.verification_passed else "verify_fix"
    if disposition is Disposition.DECLINED:
        if finding.p2_evidence is None:
            return "evaluate_p2"
        return "fix_p2" if _p2_requires_fix(finding) else None
    if disposition is Disposition.DEFERRED_TO_EXISTING_ISSUE:
        return None if finding.p2_evidence is not None else "evaluate_p2"
    return None


def _p2_requires_fix(finding: Finding) -> bool:
    evidence = finding.p2_evidence
    if evidence is None:
        return False
    return any(
        (
            evidence.reachability is Reachability.SUPPORTED,
            evidence.impact is Impact.MEANINGFUL,
            evidence.observed_recurrence > 0,
            evidence.interface_boundary_risk,
            evidence.security_risk,
            evidence.data_loss_risk,
            evidence.durable_state_risk,
            evidence.fix_cost is FixCost.CHEAP,
        )
    )


def _finding_state(finding: Finding) -> FindingSettlementState:
    if _finding_action(finding) is not None:
        return FindingSettlementState.UNRESOLVED
    if finding.disposition is Disposition.FIXED and finding.verification_passed:
        return FindingSettlementState.FIXED
    if finding.disposition is Disposition.DEFERRED_TO_EXISTING_ISSUE:
        return FindingSettlementState.DEFERRED_TO_EXISTING_ISSUE
    if finding.disposition in {
        Disposition.DECLINED,
        Disposition.REJECT,
        Disposition.STALE,
        Disposition.DEFER,
        Disposition.DUPLICATE,
        Disposition.WRONG_OWNER,
    }:
        return FindingSettlementState.DECLINED_WITH_RATIONALE
    return FindingSettlementState.UNRESOLVED


def _full_review_allowed(policy: ReviewPolicy, ledger: ReviewLedger) -> bool:
    local_rounds = [
        result.round_number
        for result in ledger.results
        if not result.stale and result.stage is ReviewStage.LOCAL
    ]
    last_round = max(local_rounds, default=0)
    return last_round < policy.review.local.max_generation_rounds


def evaluate(*, policy: ReviewPolicy, ledger: ReviewLedger) -> SettlementReport:
    """Apply reviewer quorum, severity, disposition, and budget rules."""

    missing_slots = [
        *_missing_for_stage(
            stage=ReviewStage.LOCAL,
            stage_policy=policy.review.local,
            ledger=ledger,
        ),
        *_missing_for_stage(
            stage=ReviewStage.BACKSTOP,
            stage_policy=policy.review.backstop,
            ledger=ledger,
        ),
    ]
    required_actions: list[str] = []
    blocking_fingerprints: list[str] = []
    for finding in ledger.current_findings:
        action = _finding_action(finding)
        if action is None:
            continue
        if action not in required_actions:
            required_actions.append(action)
        blocking_fingerprints.append(finding.fingerprint)

    allow_targeted = any(
        action in {"fix_p2", "fix_reproduced_p2", "verify_fix"}
        for action in required_actions
    )
    return SettlementReport(
        settled=not missing_slots and not required_actions,
        required_actions=required_actions,
        blocking_fingerprints=blocking_fingerprints,
        finding_states={
            finding.fingerprint: _finding_state(finding)
            for finding in ledger.current_findings
        },
        missing_slots=missing_slots,
        allow_full_review=_full_review_allowed(policy, ledger),
        allow_targeted_verification=allow_targeted,
    )
