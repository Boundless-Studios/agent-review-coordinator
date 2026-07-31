"""Versioned review result and disposition ledger."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .findings import (
    Disposition,
    Finding,
    FixCost,
    Impact,
    P2Evidence,
    Reachability,
    Severity,
)
from .policy import ReviewStage

_SEVERITY_RANK = {
    Severity.P3: 0,
    Severity.P2: 1,
    Severity.P1: 2,
    Severity.P0: 3,
}


def _merge_p2_evidence(
    current: P2Evidence | None,
    submitted: P2Evidence | None,
) -> P2Evidence | None:
    """Merge decision evidence without allowing a retry to weaken it."""

    if current is None:
        return submitted
    if submitted is None:
        return current

    reachability_rank = {
        Reachability.UNKNOWN: 0,
        Reachability.UNREACHABLE: 1,
        Reachability.SUPPORTED: 2,
    }
    impact_rank = {
        Impact.UNKNOWN: 0,
        Impact.LOW: 1,
        Impact.MEANINGFUL: 2,
    }
    fix_cost_rank = {
        FixCost.ARCHITECTURAL: 0,
        FixCost.MODERATE: 1,
        FixCost.CHEAP: 2,
    }
    if current.fix_cost is FixCost.UNKNOWN:
        fix_cost = submitted.fix_cost
    elif submitted.fix_cost is FixCost.UNKNOWN:
        fix_cost = current.fix_cost
    else:
        fix_cost = max(
            (current.fix_cost, submitted.fix_cost),
            key=fix_cost_rank.__getitem__,
        )

    return current.model_copy(
        update={
            "reachability": max(
                (current.reachability, submitted.reachability),
                key=reachability_rank.__getitem__,
            ),
            "impact": max(
                (current.impact, submitted.impact),
                key=impact_rank.__getitem__,
            ),
            "observed_recurrence": max(
                current.observed_recurrence,
                submitted.observed_recurrence,
            ),
            "interface_boundary_risk": (
                current.interface_boundary_risk or submitted.interface_boundary_risk
            ),
            "security_risk": current.security_risk or submitted.security_risk,
            "data_loss_risk": current.data_loss_risk or submitted.data_loss_risk,
            "durable_state_risk": (
                current.durable_state_risk or submitted.durable_state_risk
            ),
            "fix_cost": fix_cost,
        }
    )


def _is_retry_without_new_evidence(
    *,
    ledger: ReviewLedger,
    result: ReviewResult,
) -> bool:
    same_responsibility = any(
        not existing.stale
        and existing.head_sha == result.head_sha
        and existing.stage is result.stage
        and existing.slot_number == result.slot_number
        and existing.reviewer_provider == result.reviewer_provider
        for existing in ledger.results
    )
    if not same_responsibility:
        return False

    by_fingerprint = {item.fingerprint: item for item in ledger.findings}
    for submitted in result.findings:
        existing = by_fingerprint.get(submitted.fingerprint)
        if existing is None:
            return False
        if _SEVERITY_RANK[submitted.severity] > _SEVERITY_RANK[existing.severity]:
            return False
        if existing.evidence is None and submitted.evidence:
            return False
        if existing.reproduction is None and submitted.reproduction:
            return False
        existing_artifact_keys = {
            artifact.key for artifact in existing.evidence_artifacts
        }
        if any(
            artifact.key not in existing_artifact_keys
            for artifact in submitted.evidence_artifacts
        ):
            return False
        if (
            _merge_p2_evidence(existing.p2_evidence, submitted.p2_evidence)
            != existing.p2_evidence
        ):
            return False
    return True


class ReviewResult(BaseModel):
    """One reviewer execution result for an immutable snapshot."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    repository: str = Field(min_length=1)
    head_sha: str = Field(min_length=1)
    stage: ReviewStage
    round_number: int = Field(ge=1)
    slot_number: int = Field(ge=1)
    reviewer_execution_id: str = Field(min_length=1)
    reviewer_provider: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    stale: bool = False

    @model_validator(mode="after")
    def validate_findings_match_result(self) -> Self:
        """Reject adapter output that mixes snapshots or executions."""

        for finding in self.findings:
            if finding.repository != self.repository:
                raise ValueError("finding repository does not match review result")
            if finding.head_sha != self.head_sha:
                raise ValueError("finding head_sha does not match review result")
            if finding.reviewer_execution_id != self.reviewer_execution_id:
                raise ValueError(
                    "finding reviewer_execution_id does not match review result"
                )
        return self


class ReviewLedger(BaseModel):
    """Persistent state for one repository and current head SHA."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    repository: str = Field(min_length=1)
    head_sha: str = Field(min_length=1)
    results: list[ReviewResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_nested_identities(self) -> Self:
        """Keep persisted results and canonical findings on this ledger identity."""

        for result in self.results:
            if result.repository != self.repository:
                raise ValueError("result repository does not match ledger")
            if result.head_sha == self.head_sha and result.stale:
                raise ValueError("current-head result cannot be marked stale")
            if result.head_sha != self.head_sha and not result.stale:
                raise ValueError("older-head result must be marked stale")
        for finding in self.findings:
            if finding.repository != self.repository:
                raise ValueError("finding repository does not match ledger")
            if finding.head_sha != self.head_sha:
                raise ValueError("canonical finding head does not match ledger")
        return self

    @property
    def current_findings(self) -> list[Finding]:
        """Canonical, deduplicated findings for the ledger's current head."""

        return self.findings

    def submit(self, result: ReviewResult) -> None:
        """Record one valid result and merge its current findings."""

        if result.repository != self.repository:
            raise ValueError("review result repository does not match ledger")
        if result.head_sha != self.head_sha:
            self.results.append(result.model_copy(update={"stale": True}, deep=True))
            return

        if _is_retry_without_new_evidence(ledger=self, result=result):
            by_fingerprint = {item.fingerprint: item for item in self.findings}
            for submitted in result.findings:
                existing = by_fingerprint.get(submitted.fingerprint)
                if existing is None:
                    continue
                for execution_id in submitted.contributing_execution_ids:
                    if execution_id not in existing.contributing_execution_ids:
                        existing.contributing_execution_ids.append(execution_id)
            return

        self.results.append(result.model_copy(deep=True))
        by_fingerprint = {item.fingerprint: item for item in self.findings}
        for submitted in result.findings:
            existing = by_fingerprint.get(submitted.fingerprint)
            if existing is None:
                canonical = submitted.model_copy(
                    update={
                        "disposition": None,
                        "rationale": None,
                        "verification_passed": False,
                        "duplicate_of": None,
                    },
                    deep=True,
                )
                self.findings.append(canonical)
                by_fingerprint[canonical.fingerprint] = canonical
                continue
            materially_changed = False
            if _SEVERITY_RANK[submitted.severity] > _SEVERITY_RANK[existing.severity]:
                existing.severity = submitted.severity
                materially_changed = True
            if existing.evidence is None and submitted.evidence:
                existing.evidence = " ".join(submitted.evidence.split())
                materially_changed = True
            merged_p2_evidence = _merge_p2_evidence(
                existing.p2_evidence,
                submitted.p2_evidence,
            )
            if merged_p2_evidence != existing.p2_evidence:
                existing.p2_evidence = merged_p2_evidence
                materially_changed = True
            if existing.reproduction is None and submitted.reproduction:
                existing.reproduction = " ".join(submitted.reproduction.split())
                materially_changed = True
            existing_artifact_keys = {
                artifact.key for artifact in existing.evidence_artifacts
            }
            for artifact in submitted.evidence_artifacts:
                if artifact.key not in existing_artifact_keys:
                    existing.evidence_artifacts.append(artifact)
                    existing_artifact_keys.add(artifact.key)
                    materially_changed = True
            if materially_changed:
                existing.disposition = None
                existing.rationale = None
                existing.verification_passed = False
                existing.duplicate_of = None
                existing.deferred_to_issue = None
            for execution_id in submitted.contributing_execution_ids:
                if execution_id not in existing.contributing_execution_ids:
                    existing.contributing_execution_ids.append(execution_id)

    def record_disposition(
        self,
        *,
        fingerprint: str,
        disposition: Disposition,
        rationale: str,
        evidence: str | None = None,
        duplicate_of: str | None = None,
        deferred_to_issue: str | None = None,
    ) -> None:
        """Apply an evidence-backed disposition to a current finding."""

        if not rationale.strip():
            raise ValueError("disposition rationale is required")
        finding = self._finding(fingerprint)
        if disposition is Disposition.DEFERRED_TO_EXISTING_ISSUE and not (
            deferred_to_issue and deferred_to_issue.strip()
        ):
            raise ValueError("existing issue is required to defer a finding")
        if disposition is Disposition.DUPLICATE and not (
            duplicate_of and duplicate_of.strip()
        ):
            raise ValueError("duplicate target is required to dismiss a finding")
        if (
            finding.severity in {Severity.P0, Severity.P1}
            and disposition in {Disposition.REJECT, Disposition.STALE}
            and not (evidence and evidence.strip())
        ):
            raise ValueError("evidence is required to dismiss a P0/P1")
        if finding.disposition is not disposition:
            finding.verification_passed = False
        finding.disposition = disposition
        finding.rationale = rationale.strip()
        if evidence and evidence.strip():
            finding.evidence = evidence.strip()
        finding.duplicate_of = (
            duplicate_of.strip() if duplicate_of and duplicate_of.strip() else None
        )
        finding.deferred_to_issue = (
            deferred_to_issue.strip()
            if deferred_to_issue and deferred_to_issue.strip()
            else None
        )

    def record_reproduction(self, *, fingerprint: str, reproduction: str) -> None:
        """Attach reproduction evidence to a current finding."""

        if not reproduction.strip():
            raise ValueError("reproduction evidence is required")
        self._finding(fingerprint).reproduction = reproduction.strip()

    def record_verification(self, *, fingerprint: str, passed: bool) -> None:
        """Record targeted verification for a current finding."""

        self._finding(fingerprint).verification_passed = passed

    def _finding(self, fingerprint: str) -> Finding:
        for finding in self.findings:
            if finding.fingerprint == fingerprint:
                return finding
        raise ValueError("finding is not present on the current ledger head")
