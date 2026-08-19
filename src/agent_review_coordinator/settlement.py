"""Review settlement independent of providers and PR hosts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .findings import (
    Disposition,
    EvidenceKind,
    Finding,
    FixCost,
    Impact,
    Reachability,
    Severity,
)
from .ledger import ReviewLedger
from .policy import ReviewPolicy, ReviewStage


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
    architecture_lineage_ids: list[str] = Field(default_factory=list)


def _finding_action(
    finding: Finding, *, budget_exhausted: bool = False
) -> str | None:
    disposition = finding.disposition
    if finding.severity is Severity.P3:
        return None
    if disposition is not None and not (
        finding.rationale and finding.rationale.strip()
    ):
        return (
            f"address_{finding.severity.value}"
            if finding.severity in {Severity.P0, Severity.P1}
            else "evaluate_p2"
        )
    if finding.severity in {Severity.P0, Severity.P1}:
        if disposition is Disposition.FIXED:
            return None if finding.verification_passed else "verify_fix"
        if (
            disposition in {Disposition.REJECT, Disposition.STALE}
            and finding.evidence
            and finding.evidence.strip()
        ):
            return None
        if (
            disposition is Disposition.DUPLICATE
            and finding.duplicate_of
            and finding.duplicate_of.strip()
        ):
            return None
        return f"address_{finding.severity.value}"

    if (
        budget_exhausted
        and finding.severity is Severity.P2
        and disposition is Disposition.DEFER
    ):
        return None
    if disposition is None:
        return "fix_reproduced_p2" if finding.reproduction else "evaluate_p2"
    if disposition is Disposition.FIX_NOW:
        return "fix_p2"
    if disposition is Disposition.PROVE_FIRST:
        if _p2_requires_fix(finding):
            return "fix_p2"
        return "fix_reproduced_p2" if finding.reproduction else "prove_p2"
    if disposition is Disposition.FIXED:
        return None if finding.verification_passed else "verify_fix"
    if disposition is Disposition.DECLINED:
        if finding.p2_evidence is None:
            return "evaluate_p2"
        if _p2_requires_fix(finding):
            return "fix_p2"
        return None if _p2_decline_supported(finding) else "evaluate_p2"
    if disposition is Disposition.DEFERRED_TO_EXISTING_ISSUE:
        return (
            None
            if finding.p2_evidence is not None
            and finding.deferred_to_issue
            and finding.deferred_to_issue.strip()
            else "evaluate_p2"
        )
    if disposition is Disposition.DUPLICATE:
        return (
            None
            if finding.duplicate_of and finding.duplicate_of.strip()
            else "evaluate_p2"
        )
    if disposition in {
        Disposition.REJECT,
        Disposition.STALE,
        Disposition.WRONG_OWNER,
    }:
        # These three answer whether the finding is true, or whose code it is.
        # They are terminal answers, not judgments about tolerated risk, and
        # the P0/P1 branch above already settles them on the evidence string
        # alone. Demanding a structured ``P2Evidence`` block here made
        # declining a P2 strictly harder than declining a P1 and left a
        # disproven P2 with no honest disposition at all: there is no true
        # statement to make about the fix cost or reachability of a defect
        # that does not exist. A reviewer-supplied evidence block saying the
        # finding IS real still outranks the decline.
        if finding.p2_evidence is not None and _p2_requires_fix(finding):
            return "fix_p2"
        if finding.evidence and finding.evidence.strip():
            return None
        if finding.p2_evidence is None:
            return "evaluate_p2"
        return None if _p2_decline_supported(finding) else "evaluate_p2"
    if disposition is Disposition.DEFER:
        # Deferring IS a risk judgment -- it concedes the finding may be real
        # and declines to act now -- so it keeps the structured evidence gate.
        if finding.p2_evidence is None:
            return "evaluate_p2"
        if _p2_requires_fix(finding):
            return "fix_p2"
        return None if _p2_decline_supported(finding) else "evaluate_p2"
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
            bool(finding.reproduction),
            any(
                artifact.kind is EvidenceKind.REPRODUCTION
                for artifact in finding.evidence_artifacts
            ),
        )
    )


def _p2_decline_supported(finding: Finding) -> bool:
    evidence = finding.p2_evidence
    if evidence is None:
        return False
    return (
        evidence.reachability is Reachability.UNREACHABLE
        and evidence.impact is Impact.LOW
        and evidence.observed_recurrence == 0
        and not evidence.interface_boundary_risk
        and not evidence.security_risk
        and not evidence.data_loss_risk
        and not evidence.durable_state_risk
        and evidence.fix_cost is FixCost.ARCHITECTURAL
    )


def _finding_state(
    finding: Finding, *, budget_exhausted: bool = False
) -> FindingSettlementState:
    if _finding_action(finding, budget_exhausted=budget_exhausted) is not None:
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
    return (
        ledger.next_allowed_round(
            stage=ReviewStage.LOCAL,
            stage_policy=policy.review.local,
        )
        is not None
    )


def _defer_p2_at_budget_exhaustion(
    *, policy: ReviewPolicy, ledger: ReviewLedger
) -> None:
    if _full_review_allowed(policy, ledger):
        return
    maximum = policy.review.local.max_generation_rounds
    for finding in ledger.current_findings:
        if finding.severity is not Severity.P2 or _finding_action(finding) is None:
            continue
        executions = ",".join(finding.contributing_execution_ids)
        ledger.record_disposition(
            fingerprint=finding.fingerprint,
            disposition=Disposition.DEFER,
            rationale=(
                "review_budget_exhausted "
                f"generation={maximum} max_generation_rounds={maximum} "
                f"contributing_reviewer_execution_ids={executions}"
            ),
        )


def evaluate(*, policy: ReviewPolicy, ledger: ReviewLedger) -> SettlementReport:
    """Apply reviewer quorum, severity, disposition, and budget rules."""

    _defer_p2_at_budget_exhaustion(policy=policy, ledger=ledger)
    budget_exhausted = not _full_review_allowed(policy, ledger)

    missing_slots = [
        *ledger.missing_slots_for_stage(
            stage=ReviewStage.LOCAL,
            stage_policy=policy.review.local,
        ),
        *ledger.missing_slots_for_stage(
            stage=ReviewStage.BACKSTOP,
            stage_policy=policy.review.backstop,
        ),
    ]
    required_actions: list[str] = []
    blocking_fingerprints: list[str] = []
    for finding in ledger.current_findings:
        action = _finding_action(finding, budget_exhausted=budget_exhausted)
        if action is None:
            continue
        if action not in required_actions:
            required_actions.append(action)
        blocking_fingerprints.append(finding.fingerprint)
    architecture_lineage_ids = ledger.recurring_lineage_ids()
    if architecture_lineage_ids:
        required_actions.append("architecture_reevaluation_required")
    core_fix_lineage_ids = ledger.architecture_core_fix_lineage_ids()
    if core_fix_lineage_ids:
        required_actions.append("architecture_core_fix_required")
        architecture_lineage_ids = sorted(
            {*architecture_lineage_ids, *core_fix_lineage_ids}
        )

    architecture_blocks_automation = bool(architecture_lineage_ids)
    allow_targeted = not architecture_blocks_automation and any(
        action in {"fix_p2", "fix_reproduced_p2", "verify_fix"}
        for action in required_actions
    )
    return SettlementReport(
        settled=not missing_slots and not required_actions,
        required_actions=required_actions,
        blocking_fingerprints=blocking_fingerprints,
        finding_states={
            finding.fingerprint: _finding_state(
                finding,
                budget_exhausted=budget_exhausted,
            )
            for finding in ledger.current_findings
        },
        missing_slots=missing_slots,
        allow_full_review=(
            not architecture_blocks_automation and _full_review_allowed(policy, ledger)
        ),
        allow_targeted_verification=allow_targeted,
        architecture_lineage_ids=architecture_lineage_ids,
    )
