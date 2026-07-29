"""Normalized review findings and stable identities."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    """Merge-relevant severities supported by protocol version 1."""

    P1 = "p1"
    P2 = "p2"


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
    reproduction: str | None = None
    duplicate_of: str | None = None
    contributing_execution_ids: list[str] = Field(default_factory=list)
    fingerprint: str = ""
    disposition: Disposition | None = None
    rationale: str | None = None
    verification_passed: bool = False

    @model_validator(mode="after")
    def populate_fingerprint(self) -> Self:
        """Calculate the stable fingerprint when an adapter did not supply it."""

        calculated = finding_fingerprint(
            repository=self.repository,
            head_sha=self.head_sha,
            path=self.path,
            invariant=self.invariant,
            title=self.title,
        )
        if self.fingerprint and self.fingerprint != calculated:
            raise ValueError("finding fingerprint does not match normalized content")
        self.fingerprint = calculated
        if not self.contributing_execution_ids:
            self.contributing_execution_ids = [self.reviewer_execution_id]
        elif self.reviewer_execution_id not in self.contributing_execution_ids:
            self.contributing_execution_ids.append(self.reviewer_execution_id)
        return self
