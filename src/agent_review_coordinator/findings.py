"""Normalized review findings and stable identities."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    """Merge-relevant severities supported by protocol version 1."""

    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"


class Disposition(StrEnum):
    """Explicit outcomes for a review finding."""

    FIX_NOW = "fix_now"
    PROVE_FIRST = "prove_first"
    DEFER = "defer"
    REJECT = "reject"
    DUPLICATE = "duplicate"
    STALE = "stale"
    WRONG_OWNER = "wrong_owner"
    FIXED = "fixed"
    DECLINED = "declined"
    DEFERRED_TO_EXISTING_ISSUE = "deferred_to_existing_issue"


class Reachability(StrEnum):
    """Whether a finding can occur in supported use."""

    SUPPORTED = "supported"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class Impact(StrEnum):
    """Observed or expected user/system impact."""

    MEANINGFUL = "meaningful"
    LOW = "low"
    UNKNOWN = "unknown"


class FixCost(StrEnum):
    """Relative cost of defending the existing interface."""

    CHEAP = "cheap"
    MODERATE = "moderate"
    ARCHITECTURAL = "architectural"
    UNKNOWN = "unknown"


class EvidenceKind(StrEnum):
    """How a keyed evidence artifact supports a finding."""

    OBSERVATION = "observation"
    REPRODUCTION = "reproduction"


class EvidenceArtifact(BaseModel):
    """Stable evidence identity whose summary may be rephrased."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    key: str = Field(min_length=1)
    kind: EvidenceKind
    summary: str = Field(min_length=1)


class P2Evidence(BaseModel):
    """Decision inputs required for an evidence-based P2 disposition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    reachability: Reachability
    impact: Impact
    observed_recurrence: int = Field(ge=0)
    interface_boundary_risk: bool
    security_risk: bool
    data_loss_risk: bool
    durable_state_risk: bool
    fix_cost: FixCost


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())


def _normalize_path(value: str) -> str:
    return value.removeprefix("./")


def finding_fingerprint(
    *,
    repository: str,
    head_sha: str,
    path: str,
    invariant: str,
    title: str,
) -> str:
    """Return a reviewer- and line-independent finding identity."""

    normalized = {
        "repository": _normalize(repository),
        "head_sha": _normalize(head_sha),
        "path": _normalize_path(path),
        "invariant": _normalize(invariant),
        "title": _normalize(title),
    }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def finding_lineage_id(
    *, repository: str, path: str, invariant: str, title: str
) -> str:
    """Return a snapshot-independent identity for a recurring problem."""

    normalized = {
        "repository": _normalize(repository),
        "path": _normalize_path(path),
        "invariant": _normalize(invariant),
        "title": _normalize(title),
    }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Finding(BaseModel):
    """One provider-neutral finding against an immutable repository snapshot."""

    model_config = ConfigDict(extra="forbid")

    repository: str = Field(min_length=1)
    head_sha: str = Field(min_length=1)
    reviewer_execution_id: str = Field(min_length=1)
    reviewer_provider: str | None = None
    severity: Severity
    title: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    path: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)
    invariant: str = Field(min_length=1)
    evidence: str | None = None
    evidence_artifacts: list[EvidenceArtifact] = Field(default_factory=list)
    p2_evidence: P2Evidence | None = None
    reproduction: str | None = None
    duplicate_of: str | None = None
    deferred_to_issue: str | None = None
    contributing_execution_ids: list[str] = Field(default_factory=list)
    fingerprint: str = ""
    lineage_id: str = ""
    disposition: Disposition | None = None
    rationale: str | None = None
    verification_passed: bool = False

    @model_validator(mode="after")
    def populate_fingerprint(self) -> Self:
        """Calculate the stable fingerprint when an adapter did not supply it."""

        supplied_fingerprint = self.fingerprint
        calculated = finding_fingerprint(
            repository=self.repository,
            head_sha=self.head_sha,
            path=self.path,
            invariant=self.invariant,
            title=self.title,
        )
        if supplied_fingerprint and supplied_fingerprint != calculated:
            raise ValueError("finding fingerprint does not match normalized content")
        self.fingerprint = calculated
        calculated_lineage = finding_lineage_id(
            repository=self.repository,
            path=self.path,
            invariant=self.invariant,
            title=self.title,
        )
        lineage_was_supplied = "lineage_id" in self.model_fields_set
        if (
            supplied_fingerprint
            and lineage_was_supplied
            and self.lineage_id != calculated_lineage
        ):
            raise ValueError("finding lineage_id does not match normalized content")
        self.lineage_id = calculated_lineage
        if not self.contributing_execution_ids:
            self.contributing_execution_ids = [self.reviewer_execution_id]
        elif self.reviewer_execution_id not in self.contributing_execution_ids:
            self.contributing_execution_ids.append(self.reviewer_execution_id)
        return self
