"""Versioned review result and disposition ledger."""

from __future__ import annotations

from enum import StrEnum
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
from .policy import ReviewStage, ReviewStagePolicy

_SEVERITY_RANK = {
    Severity.P3: 0,
    Severity.P2: 1,
    Severity.P1: 2,
    Severity.P0: 3,
}

# Quorum search is exact within this supported state budget; it never truncates.
_MAX_QUORUM_SEARCH_STATES = 50_000


class HeadAttestationKind(StrEnum):
    """Why a descendant may reuse completed delivery-wide review quorum."""

    EXHAUSTED_DELIVERY_CONTINUITY = "exhausted_delivery_continuity"


class HeadAttestation(BaseModel):
    """Typed continuity evidence; deliberately not a reviewer result."""

    model_config = ConfigDict(extra="forbid")

    repository: str = Field(min_length=1)
    delivery_id: str = Field(min_length=1)
    review_charter_version: str = Field(min_length=1)
    reviewed_head_sha: str = Field(min_length=1)
    head_sha: str = Field(min_length=1)
    kind: HeadAttestationKind
    delta_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: list[str] = Field(min_length=1)
    attested_by: str = Field(min_length=1)


class ArchitectureDecisionKind(StrEnum):
    """Explicit terminal response to recurring architectural feedback."""

    CORE_FIX_PLANNED = "core_fix_planned"
    EXPLICITLY_DEFERRED = "explicitly_deferred"
    REJECTED = "rejected"


class ArchitectureDecision(BaseModel):
    """Human-owned decision that stops automatic work on one lineage."""

    model_config = ConfigDict(extra="forbid")

    repository: str = Field(min_length=1)
    delivery_id: str = Field(min_length=1)
    review_charter_version: str = Field(min_length=1)
    lineage_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: ArchitectureDecisionKind
    rationale: str = Field(min_length=1)
    decided_by: str = Field(min_length=1)


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
    same_responsibility_results = [
        existing
        for existing in ledger.results
        if (
            not existing.stale
            and existing.head_sha == result.head_sha
            and existing.stage is result.stage
            and existing.slot_number == result.slot_number
            and existing.reviewer_provider == result.reviewer_provider
        )
    ]
    if not same_responsibility_results:
        return False
    current_responsibility = same_responsibility_results[-1]
    other_execution_ids = {
        existing.reviewer_execution_id
        for existing in ledger.results
        if (
            not existing.stale
            and existing.head_sha == result.head_sha
            and existing.stage is result.stage
            and existing.slot_number != result.slot_number
        )
    }
    if (
        current_responsibility.reviewer_execution_id in other_execution_ids
        and result.reviewer_execution_id not in other_execution_ids
    ):
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

    version: Literal[2] = 2
    repository: str = Field(min_length=1)
    head_sha: str = Field(min_length=1)
    delivery_id: str = Field(min_length=1)
    review_charter_version: str = Field(min_length=1)
    results: list[ReviewResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    head_attestations: list[HeadAttestation] = Field(default_factory=list)
    architecture_decisions: list[ArchitectureDecision] = Field(default_factory=list)

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
        for attestation in self.head_attestations:
            if attestation.repository != self.repository:
                raise ValueError("attestation repository does not match ledger")
            if attestation.delivery_id != self.delivery_id:
                raise ValueError("attestation delivery_id does not match ledger")
            if attestation.review_charter_version != self.review_charter_version:
                raise ValueError(
                    "attestation review_charter_version does not match ledger"
                )
            if attestation.head_sha != self.head_sha:
                raise ValueError("attestation head does not match ledger")
        for decision in self.architecture_decisions:
            if decision.repository != self.repository:
                raise ValueError("architecture decision repository does not match ledger")
            if decision.delivery_id != self.delivery_id:
                raise ValueError("architecture decision delivery_id does not match ledger")
            if decision.review_charter_version != self.review_charter_version:
                raise ValueError(
                    "architecture decision review_charter_version does not match ledger"
                )
        return self

    @property
    def current_findings(self) -> list[Finding]:
        """Canonical, deduplicated findings for the ledger's current head."""

        return self.findings

    def next_allowed_round(
        self,
        *,
        stage: ReviewStage,
        stage_policy: ReviewStagePolicy,
    ) -> int | None:
        """Return the next generation number, or ``None`` when exhausted."""

        required = stage_policy.required_results or stage_policy.reviewer_count
        grouped: dict[int, dict[str, list[ReviewResult]]] = {}
        for result in self.results:
            if result.stage is stage:
                grouped.setdefault(result.round_number, {}).setdefault(
                    result.head_sha, []
                ).append(result)

        completed = {
            round_number
            for round_number, results_by_head in grouped.items()
            if any(
                not self._quorum_missing(
                    stage=stage,
                    results=results,
                    required=required,
                    stage_policy=stage_policy,
                )
                for results in results_by_head.values()
            )
        }
        for round_number in range(1, stage_policy.max_generation_rounds + 1):
            if round_number not in completed:
                return round_number
        return None

    def missing_slots_for_stage(
        self,
        *,
        stage: ReviewStage,
        stage_policy: ReviewStagePolicy,
    ) -> list[str]:
        """Report current-head quorum gaps using monotonic candidate selection."""

        if stage is ReviewStage.LOCAL and self._has_current_head_attestation(
            stage_policy=stage_policy
        ):
            return []
        results_by_round: dict[int, list[ReviewResult]] = {}
        for result in self.results:
            if not result.stale and result.stage is stage:
                results_by_round.setdefault(result.round_number, []).append(result)
        required = stage_policy.required_results or stage_policy.reviewer_count
        if results_by_round:
            current_round = max(results_by_round)
            return self._quorum_missing(
                stage=stage,
                results=results_by_round[current_round],
                required=required,
                stage_policy=stage_policy,
            )
        return self._quorum_missing(
            stage=stage,
            results=[],
            required=required,
            stage_policy=stage_policy,
        )

    def _completed_heads(
        self,
        *,
        stage: ReviewStage,
        stage_policy: ReviewStagePolicy,
    ) -> set[str]:
        required = stage_policy.required_results or stage_policy.reviewer_count
        grouped: dict[tuple[int, str], list[ReviewResult]] = {}
        for item in self.results:
            if item.stage is stage:
                grouped.setdefault((item.round_number, item.head_sha), []).append(item)
        return {
            head_sha
            for (_, head_sha), items in grouped.items()
            if not self._quorum_missing(
                stage=stage,
                results=items,
                required=required,
                stage_policy=stage_policy,
            )
        }

    def _has_current_head_attestation(
        self, *, stage_policy: ReviewStagePolicy
    ) -> bool:
        completed_heads = self._completed_heads(
            stage=ReviewStage.LOCAL,
            stage_policy=stage_policy,
        )
        return any(
            item.head_sha == self.head_sha
            and item.reviewed_head_sha in completed_heads
            for item in self.head_attestations
        )

    def record_head_attestation(
        self,
        attestation: HeadAttestation,
        *,
        stage_policy: ReviewStagePolicy,
    ) -> None:
        """Record descendant continuity without manufacturing a review result."""

        if attestation.repository != self.repository:
            raise ValueError("attestation repository does not match ledger")
        if attestation.delivery_id != self.delivery_id:
            raise ValueError("attestation delivery_id does not match ledger")
        if attestation.review_charter_version != self.review_charter_version:
            raise ValueError("attestation review charter does not match ledger")
        if attestation.head_sha != self.head_sha:
            raise ValueError("attestation head does not match ledger")
        if self.next_allowed_round(
            stage=ReviewStage.LOCAL,
            stage_policy=stage_policy,
        ) is not None:
            raise ValueError("local review budget is not exhausted")
        if attestation.reviewed_head_sha not in self._completed_heads(
            stage=ReviewStage.LOCAL,
            stage_policy=stage_policy,
        ):
            raise ValueError("reviewed head does not have completed local quorum")
        if attestation not in self.head_attestations:
            self.head_attestations.append(attestation.model_copy(deep=True))

    def recurring_lineage_ids(self) -> list[str]:
        """Return lineages recurring across generations or three reviewed heads."""

        observations: dict[str, set[tuple[int, str]]] = {}
        for review_result in self.results:
            for item in review_result.findings:
                observations.setdefault(item.lineage_id, set()).add(
                    (review_result.round_number, review_result.head_sha)
                )
        decided = {item.lineage_id for item in self.architecture_decisions}
        recurring: list[str] = []
        for lineage_id, seen in observations.items():
            rounds = {round_number for round_number, _ in seen}
            heads = {head_sha for _, head_sha in seen}
            if (len(rounds) >= 2 or len(heads) >= 3) and lineage_id not in decided:
                recurring.append(lineage_id)
        return sorted(recurring)

    def record_architecture_decision(self, decision: ArchitectureDecision) -> None:
        """Record an explicit terminal decision for a recurring lineage."""

        if decision.repository != self.repository:
            raise ValueError("architecture decision repository does not match ledger")
        if decision.delivery_id != self.delivery_id:
            raise ValueError("architecture decision delivery_id does not match ledger")
        if decision.review_charter_version != self.review_charter_version:
            raise ValueError("architecture decision review charter does not match ledger")
        observed = {
            finding.lineage_id
            for review_result in self.results
            for finding in review_result.findings
        }
        if decision.lineage_id not in observed:
            raise ValueError("architecture decision lineage was not observed")
        self.architecture_decisions = [
            item
            for item in self.architecture_decisions
            if item.lineage_id != decision.lineage_id
        ]
        self.architecture_decisions.append(decision.model_copy(deep=True))

    @staticmethod
    def _quorum_missing(
        *,
        stage: ReviewStage,
        results: list[ReviewResult],
        required: int,
        stage_policy: ReviewStagePolicy,
    ) -> list[str]:
        results_by_slot = [
            [result for result in results if result.slot_number == slot_number]
            for slot_number in range(1, required + 1)
        ]
        missing = [
            f"{stage.value}:{slot_number}"
            for slot_number, candidates in enumerate(results_by_slot, start=1)
            if not candidates
        ]
        if missing:
            if stage_policy.distinct_providers:
                providers = {
                    result.reviewer_provider
                    for candidates in results_by_slot
                    for result in candidates
                    if result.reviewer_provider
                }
                if len(providers) < required:
                    missing.append(f"{stage.value}:provider-diversity")
            return missing
        candidates_by_slot = [
            list(
                dict.fromkeys(
                    (
                        result.reviewer_execution_id,
                        result.reviewer_provider,
                    )
                    for result in candidates
                )
            )
            for candidates in results_by_slot
        ]
        if ReviewLedger._assignment_exists(
            candidates_by_slot=candidates_by_slot,
            distinct_executions=stage_policy.distinct_executions,
            distinct_providers=stage_policy.distinct_providers,
        ):
            return []
        execution_possible = ReviewLedger._assignment_exists(
            candidates_by_slot=candidates_by_slot,
            distinct_executions=stage_policy.distinct_executions,
            distinct_providers=False,
        )
        provider_possible = ReviewLedger._assignment_exists(
            candidates_by_slot=candidates_by_slot,
            distinct_executions=False,
            distinct_providers=stage_policy.distinct_providers,
        )
        missing = []
        if stage_policy.distinct_executions and not execution_possible:
            missing.append(f"{stage.value}:{required}")
        if stage_policy.distinct_providers and not provider_possible:
            missing.append(f"{stage.value}:provider-diversity")
        if not missing:
            missing.extend(
                [f"{stage.value}:{required}", f"{stage.value}:provider-diversity"]
            )
        return missing

    @staticmethod
    def _assignment_exists(
        *,
        candidates_by_slot: list[list[tuple[str, str | None]]],
        distinct_executions: bool,
        distinct_providers: bool,
    ) -> bool:
        """Find one valid slot assignment without enumerating the full product."""

        ordered = sorted(candidates_by_slot, key=len)
        failed: set[tuple[int, frozenset[str], frozenset[str]]] = set()
        visited_states = 0

        def search(
            index: int,
            used_executions: frozenset[str],
            used_providers: frozenset[str],
        ) -> bool:
            nonlocal visited_states
            if index == len(ordered):
                return True
            state = (index, used_executions, used_providers)
            if state in failed:
                return False
            if visited_states >= _MAX_QUORUM_SEARCH_STATES:
                raise ValueError(
                    "quorum candidate complexity exceeds supported search budget; "
                    "reduce reviewer slots or retry candidates"
                )
            visited_states += 1
            remaining = len(ordered) - index
            if distinct_executions:
                available_executions = {
                    execution_id
                    for candidates in ordered[index:]
                    for execution_id, _ in candidates
                    if execution_id not in used_executions
                }
                if len(available_executions) < remaining:
                    failed.add(state)
                    return False
            if distinct_providers:
                available_providers = {
                    provider
                    for candidates in ordered[index:]
                    for _, provider in candidates
                    if provider is not None and provider not in used_providers
                }
                if len(available_providers) < remaining:
                    failed.add(state)
                    return False
            for execution_id, provider in ordered[index]:
                if distinct_executions and execution_id in used_executions:
                    continue
                if distinct_providers and (
                    provider is None or provider in used_providers
                ):
                    continue
                if search(
                    index + 1,
                    (
                        used_executions | {execution_id}
                        if distinct_executions
                        else used_executions
                    ),
                    (
                        used_providers | {provider}
                        if distinct_providers and provider is not None
                        else used_providers
                    ),
                ):
                    return True
            failed.add(state)
            return False

        return search(0, frozenset(), frozenset())

    def advance_head(self, head_sha: str) -> None:
        """Advance to a descendant snapshot while retaining stale audit history."""

        if not head_sha:
            raise ValueError("head SHA is required")
        if head_sha == self.head_sha:
            raise ValueError("new head SHA must differ from current head SHA")
        advanced_results = [
            result.model_copy(
                update={"stale": result.head_sha != head_sha},
                deep=True,
            )
            for result in self.results
        ]
        advanced_findings = [
            Finding.model_validate(
                finding.model_dump()
                | {
                    "head_sha": head_sha,
                    "fingerprint": "",
                    "verification_passed": False,
                }
            )
            for finding in self.findings
        ]
        merge_ledger = ReviewLedger(
            repository=self.repository,
            head_sha=head_sha,
            delivery_id=self.delivery_id,
            review_charter_version=self.review_charter_version,
            findings=advanced_findings,
        )
        for result in advanced_results:
            if not result.stale:
                merge_ledger.submit(result)
        self.results = advanced_results
        self.findings = merge_ledger.findings
        self.head_attestations = []
        self.head_sha = head_sha

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
        finding = self._finding(fingerprint)
        finding.reproduction = reproduction.strip()
        finding.disposition = None
        finding.rationale = None
        finding.verification_passed = False
        finding.duplicate_of = None
        finding.deferred_to_issue = None

    def record_verification(self, *, fingerprint: str, passed: bool) -> None:
        """Record targeted verification for a current finding."""

        self._finding(fingerprint).verification_passed = passed

    def _finding(self, fingerprint: str) -> Finding:
        for finding in self.findings:
            if finding.fingerprint == fingerprint:
                return finding
        raise ValueError("finding is not present on the current ledger head")
