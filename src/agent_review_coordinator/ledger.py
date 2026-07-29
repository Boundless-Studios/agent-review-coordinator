"""Versioned review result and disposition ledger."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .findings import Disposition, Finding
from .policy import ReviewStage


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

        self.results.append(result.model_copy(deep=True))
        by_fingerprint = {item.fingerprint: item for item in self.findings}
        for submitted in result.findings:
            existing = by_fingerprint.get(submitted.fingerprint)
            if existing is None:
                canonical = submitted.model_copy(deep=True)
                self.findings.append(canonical)
                by_fingerprint[canonical.fingerprint] = canonical
                continue
            for execution_id in submitted.contributing_execution_ids:
                if execution_id not in existing.contributing_execution_ids:
                    existing.contributing_execution_ids.append(execution_id)

    def record_disposition(
        self,
        *,
        fingerprint: str,
        disposition: Disposition,
        rationale: str,
    ) -> None:
        """Apply an evidence-backed disposition to a current finding."""

        if not rationale.strip():
            raise ValueError("disposition rationale is required")
        finding = self._finding(fingerprint)
        finding.disposition = disposition
        finding.rationale = rationale.strip()

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
