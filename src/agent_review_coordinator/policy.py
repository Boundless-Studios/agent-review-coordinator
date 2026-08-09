"""Declarative, provider-neutral review policy."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_REVIEWER_COUNT = 8


class ReviewStage(StrEnum):
    """A review stage whose slots are filled by an integration."""

    LOCAL = "local"
    BACKSTOP = "backstop"


class ReviewStagePolicy(BaseModel):
    """Slot and review-budget policy for one stage."""

    model_config = ConfigDict(extra="forbid")

    reviewer_count: int = Field(ge=1, le=MAX_REVIEWER_COUNT)
    required_results: int | None = Field(
        default=None,
        ge=1,
        le=MAX_REVIEWER_COUNT,
    )
    distinct_executions: bool = True
    distinct_providers: bool = False
    initial_scope: Literal["full"] = "full"
    verification_scope: Literal["changed_findings"] = "changed_findings"
    max_generation_rounds: int = Field(default=2, ge=1)
    trigger: Literal["manual", "new_head_sha"] = "manual"

    @model_validator(mode="after")
    def validate_required_results(self) -> Self:
        """Default the quorum to every slot and reject impossible quorums."""

        required = self.required_results or self.reviewer_count
        if required > self.reviewer_count:
            raise ValueError("required_results cannot exceed reviewer_count")
        self.required_results = required
        return self


class ReviewConfiguration(BaseModel):
    """Review stages supported by protocol version 1."""

    model_config = ConfigDict(extra="forbid")

    local: ReviewStagePolicy
    backstop: ReviewStagePolicy


class SettlementPolicy(BaseModel):
    """Severity handling constraints."""

    model_config = ConfigDict(extra="forbid")

    p1: Literal["address"] = "address"
    p2: Literal["evaluate"] = "evaluate"
    automatic_tracker_writes: Literal[False] = False


class ReviewerSlot(BaseModel):
    """One provider-neutral execution requested by policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: ReviewStage
    round_number: int = Field(ge=1)
    slot_number: int = Field(ge=1)
    execution_id: str
    provider: None = None


class ReviewRequirement(BaseModel):
    """One provider-neutral review responsibility."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    slot: str = Field(min_length=1)
    required: bool
    provider_constraint: str | None = Field(default=None, min_length=1)


class ReviewPolicy(BaseModel):
    """Versioned review topology and settlement policy."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    review: ReviewConfiguration
    settlement: SettlementPolicy = Field(default_factory=SettlementPolicy)

    @classmethod
    def from_yaml(cls, text: str) -> Self:
        """Parse a policy from YAML without applying repository defaults."""

        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise TypeError("review policy must be a YAML object")
        return cls.model_validate(data)

    def slots_for(
        self,
        *,
        stage: ReviewStage,
        round_number: int,
    ) -> list[ReviewerSlot]:
        """Return deterministic, provider-neutral slots for one review round."""

        stage_policy = getattr(self.review, stage.value)
        if round_number > stage_policy.max_generation_rounds:
            raise ValueError(
                f"{stage.value} round {round_number} exceeds generation budget "
                f"{stage_policy.max_generation_rounds}"
            )
        return [
            ReviewerSlot(
                stage=stage,
                round_number=round_number,
                slot_number=slot_number,
                execution_id=f"{stage.value}-r{round_number}-slot{slot_number}",
            )
            for slot_number in range(1, stage_policy.reviewer_count + 1)
        ]

    def requirements_for(self, *, stage: ReviewStage) -> list[ReviewRequirement]:
        """Return the provider-neutral responsibilities for one stage."""

        stage_policy = getattr(self.review, stage.value)
        required_results = stage_policy.required_results or stage_policy.reviewer_count
        return [
            ReviewRequirement(
                slot=f"{stage.value}:{slot_number}",
                required=slot_number <= required_results,
                provider_constraint=(
                    "distinct"
                    if stage_policy.distinct_providers
                    and slot_number <= required_results
                    else None
                ),
            )
            for slot_number in range(1, stage_policy.reviewer_count + 1)
        ]
