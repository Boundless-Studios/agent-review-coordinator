"""Review settlement independent of providers and PR hosts."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .findings import Disposition, Finding, Severity
from .ledger import ReviewLedger
from .policy import ReviewPolicy, ReviewStage, ReviewStagePolicy


class SettlementReport(BaseModel):
    """Machine-readable work remaining for the current review snapshot."""

    model_config = ConfigDict(extra="forbid")

    settled: bool
    required_actions: list[str] = Field(default_factory=list)
    blocking_fingerprints: list[str] = Field(default_factory=list)
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
    if stage_policy.distinct_executions:
        qualifying_results = {
            result.reviewer_execution_id: result for result in results
        }
    else:
        qualifying_results = {result.slot_number: result for result in results}
    required = stage_policy.required_results or stage_policy.reviewer_count
    missing = [
        f"{stage.value}:{slot_number}"
        for slot_number in range(len(qualifying_results) + 1, required + 1)
    ]
    if stage_policy.distinct_providers:
        providers = {
            result.reviewer_provider
            for result in qualifying_results.values()
            if result.reviewer_provider
        }
        if len(providers) < required:
            missing.append(f"{stage.value}:provider-diversity")
    return missing


def _finding_action(finding: Finding) -> str | None:
    disposition = finding.disposition
    if finding.severity is Severity.P1:
        if disposition is Disposition.FIXED:
            return None if finding.verification_passed else "verify_fix"
        if disposition in {
            Disposition.REJECT,
            Disposition.DUPLICATE,
            Disposition.STALE,
        }:
            return None
        return "address_p1"

    if disposition is None:
        return "evaluate_p2"
    if disposition is Disposition.FIX_NOW:
        return "fix_p2"
    if disposition is Disposition.PROVE_FIRST:
        return "fix_reproduced_p2" if finding.reproduction else "prove_p2"
    if disposition is Disposition.FIXED:
        return None if finding.verification_passed else "verify_fix"
    return None


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
        missing_slots=missing_slots,
        allow_full_review=_full_review_allowed(policy, ledger),
        allow_targeted_verification=allow_targeted,
    )
