import unittest
from unittest.mock import patch

from pydantic import ValidationError

from agent_review_coordinator.findings import (
    Disposition,
    EvidenceArtifact,
    EvidenceKind,
    Finding,
    FixCost,
    Impact,
    P2Evidence,
    Reachability,
    Severity,
)
from agent_review_coordinator.ledger import ReviewLedger as ReviewLedgerModel
from agent_review_coordinator.ledger import ReviewResult
from agent_review_coordinator.policy import ReviewPolicy, ReviewStage
from agent_review_coordinator.settlement import evaluate

REPOSITORY = "Boundless-Studios/gaia-free"
CURRENT_HEAD = "b" * 40
DELIVERY_ID = "repo:branch:base"
REVIEW_CHARTER_VERSION = "gaia-v1"


class ReviewLedger(ReviewLedgerModel):
    """Ledger fixture carrying the required delivery identity."""

    delivery_id: str = DELIVERY_ID
    review_charter_version: str = REVIEW_CHARTER_VERSION


def finding(
    *,
    head_sha: str = CURRENT_HEAD,
    execution_id: str = "local-r1-slot1",
) -> Finding:
    return Finding(
        repository=REPOSITORY,
        head_sha=head_sha,
        reviewer_execution_id=execution_id,
        severity=Severity.P2,
        title="Do not synthesize green",
        explanation="A missing check is treated as passing.",
        path="scripts/review.py",
        invariant="CI must be terminal",
    )


def result(
    *,
    head_sha: str = CURRENT_HEAD,
    execution_id: str = "local-r1-slot1",
    round_number: int = 1,
    slot_number: int = 1,
    findings: list[Finding] | None = None,
) -> ReviewResult:
    return ReviewResult(
        repository=REPOSITORY,
        head_sha=head_sha,
        stage=ReviewStage.LOCAL,
        round_number=round_number,
        slot_number=slot_number,
        reviewer_execution_id=execution_id,
        findings=(
            findings
            if findings is not None
            else [finding(head_sha=head_sha, execution_id=execution_id)]
        ),
    )


class ReviewLedgerTest(unittest.TestCase):
    def test_large_quorum_does_not_enumerate_cartesian_product(self) -> None:
        stage_policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 8,
                        "required_results": 8,
                        "distinct_executions": True,
                        "distinct_providers": True,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        ).review.local
        results = [
            result(
                execution_id=f"execution-{candidate}",
                slot_number=slot,
                findings=[],
            ).model_copy(update={"reviewer_provider": f"provider-{candidate}"})
            for slot in range(1, 9)
            for candidate in range(10)
        ]
        ledger = ReviewLedger(
            repository=REPOSITORY,
            head_sha=CURRENT_HEAD,
            results=results,
        )

        with patch(
            "agent_review_coordinator.ledger.product",
            create=True,
            side_effect=AssertionError("Cartesian enumeration is forbidden"),
        ):
            missing = ledger.missing_slots_for_stage(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            )

        self.assertEqual(missing, [])

    def test_next_allowed_round_is_cumulative_across_heads(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        stage_policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 1,
                        "required_results": 1,
                        "max_generation_rounds": 2,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        ).review.local

        self.assertEqual(
            ledger.next_allowed_round(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            ),
            1,
        )
        ledger.submit(result(findings=[]))
        self.assertEqual(
            ledger.next_allowed_round(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            ),
            2,
        )
        next_head = "c" * 40
        ledger.advance_head(next_head)
        ledger.submit(result(head_sha=next_head, round_number=2, findings=[]))

        self.assertIsNone(
            ledger.next_allowed_round(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            )
        )

    def test_incomplete_quorum_and_retry_do_not_consume_round(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        stage_policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 2,
                        "required_results": 2,
                        "max_generation_rounds": 2,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        ).review.local
        ledger.submit(result(findings=[]))
        ledger.submit(result(execution_id="local-r1-retry", findings=[]))

        self.assertEqual(
            ledger.next_allowed_round(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            ),
            1,
        )
        ledger.submit(
            result(
                execution_id="local-r1-slot2",
                slot_number=2,
                findings=[],
            )
        )
        self.assertEqual(
            ledger.next_allowed_round(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            ),
            2,
        )

    def test_reused_round_number_on_descendant_is_one_generation(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        stage_policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 1,
                        "max_generation_rounds": 2,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        ).review.local
        ledger.submit(result(findings=[]))
        next_head = "d" * 40
        ledger.advance_head(next_head)
        ledger.submit(result(head_sha=next_head, findings=[]))

        self.assertEqual(
            ledger.next_allowed_round(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            ),
            2,
        )

    def test_later_conflicting_retry_cannot_erase_completed_quorum(self) -> None:
        stage_policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 2,
                        "required_results": 2,
                        "distinct_executions": True,
                        "distinct_providers": True,
                        "max_generation_rounds": 2,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        ).review.local
        ledger = ReviewLedger(
            repository=REPOSITORY,
            head_sha=CURRENT_HEAD,
            results=[
                result(execution_id="execution-a", slot_number=1, findings=[]).model_copy(
                    update={"reviewer_provider": "provider-a"}
                ),
                result(execution_id="execution-b", slot_number=2, findings=[]).model_copy(
                    update={"reviewer_provider": "provider-b"}
                ),
                result(execution_id="execution-a", slot_number=2, findings=[]).model_copy(
                    update={"reviewer_provider": "provider-a"}
                ),
            ],
        )

        self.assertEqual(
            ledger.next_allowed_round(
                stage=ReviewStage.LOCAL,
                stage_policy=stage_policy,
            ),
            2,
        )

    def test_delivery_identity_fields_are_required_and_nonempty(self) -> None:
        ledger = ReviewLedger(
            repository=REPOSITORY,
            head_sha=CURRENT_HEAD,
            delivery_id=DELIVERY_ID,
            review_charter_version=REVIEW_CHARTER_VERSION,
        )
        self.assertEqual(ledger.delivery_id, DELIVERY_ID)
        self.assertEqual(ledger.review_charter_version, REVIEW_CHARTER_VERSION)
        with self.assertRaises(ValidationError):
            ReviewLedgerModel(
                repository=REPOSITORY,
                head_sha=CURRENT_HEAD,
                delivery_id="",
                review_charter_version=REVIEW_CHARTER_VERSION,
            )
        with self.assertRaises(ValidationError):
            ReviewLedgerModel(
                repository=REPOSITORY,
                head_sha=CURRENT_HEAD,
                delivery_id=DELIVERY_ID,
                review_charter_version="",
            )

    def test_advance_head_carries_findings_and_resets_verification(self) -> None:
        ledger = ReviewLedger(
            repository=REPOSITORY,
            head_sha=CURRENT_HEAD,
            delivery_id=DELIVERY_ID,
            review_charter_version=REVIEW_CHARTER_VERSION,
        )
        original = result().model_copy(update={"round_number": 2})
        ledger.submit(original)
        original_fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=original_fingerprint,
            disposition=Disposition.DEFERRED_TO_EXISTING_ISSUE,
            rationale="Tracked by the existing delivery issue.",
            deferred_to_issue="BOU-1234",
        )
        ledger.record_verification(
            fingerprint=original_fingerprint,
            passed=True,
        )
        next_head = "c" * 40

        ledger.advance_head(next_head)

        self.assertEqual(ledger.head_sha, next_head)
        self.assertEqual(len(ledger.current_findings), 1)
        carried = ledger.current_findings[0]
        self.assertEqual(carried.head_sha, next_head)
        self.assertNotEqual(carried.fingerprint, original_fingerprint)
        self.assertEqual(
            carried.disposition,
            Disposition.DEFERRED_TO_EXISTING_ISSUE,
        )
        self.assertEqual(
            carried.rationale,
            "Tracked by the existing delivery issue.",
        )
        self.assertEqual(carried.deferred_to_issue, "BOU-1234")
        self.assertIsNone(carried.duplicate_of)
        self.assertFalse(carried.verification_passed)
        self.assertEqual(len(ledger.results), 1)
        self.assertTrue(ledger.results[0].stale)
        self.assertEqual(ledger.results[0].head_sha, CURRENT_HEAD)
        self.assertEqual(ledger.results[0].round_number, 2)
        self.assertFalse(original.stale)

    def test_advance_head_keeps_existing_target_head_result_current(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        next_head = "c" * 40
        target_result = result(head_sha=next_head)
        ledger.submit(target_result)
        self.assertTrue(ledger.results[0].stale)

        ledger.advance_head(next_head)

        self.assertFalse(ledger.results[0].stale)
        ReviewLedgerModel.model_validate(ledger.model_dump())

    def test_advance_head_canonicalizes_activated_target_findings(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        next_head = "c" * 40
        blocking = finding(head_sha=next_head).model_copy(
            update={"severity": Severity.P1}
        )
        target_result = result(head_sha=next_head).model_copy(
            update={"findings": [blocking]}
        )
        ledger.submit(target_result)

        ledger.advance_head(next_head)

        self.assertEqual(len(ledger.results), 1)
        self.assertFalse(ledger.results[0].stale)
        self.assertEqual(ledger.current_findings, [blocking])
        report = evaluate(
            policy=ReviewPolicy.model_validate(
                {
                    "version": 1,
                    "review": {
                        "local": {
                            "reviewer_count": 1,
                            "required_results": 1,
                            "max_generation_rounds": 2,
                        },
                        "backstop": {
                            "reviewer_count": 1,
                            "required_results": 1,
                            "trigger": "new_head_sha",
                        },
                    },
                }
            ),
            ledger=ledger,
        )
        self.assertIn("address_p1", report.required_actions)
        self.assertIn(blocking.fingerprint, report.blocking_fingerprints)

    def test_new_keyed_evidence_is_retained_and_reopens_finding(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        first_artifact = EvidenceArtifact(
            key="path-a",
            kind=EvidenceKind.OBSERVATION,
            summary="Stack trace from path A.",
        )
        original_finding = finding().model_copy(
            update={"evidence_artifacts": [first_artifact]}
        )
        original = result().model_copy(update={"findings": [original_finding]})
        ledger.submit(original)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="Only unsupported path A was known.",
        )
        second_artifact = EvidenceArtifact(
            key="supported-production-path-b",
            kind=EvidenceKind.REPRODUCTION,
            summary="Production reproduction from supported path B.",
        )
        retry_finding = original_finding.model_copy(
            update={
                "evidence_artifacts": [first_artifact, second_artifact],
            }
        )
        retry = result(execution_id="local-retry").model_copy(
            update={"round_number": 2, "findings": [retry_finding]}
        )

        ledger.submit(retry)

        canonical = ledger.current_findings[0]
        self.assertEqual(len(ledger.results), 2)
        self.assertEqual(
            [artifact.key for artifact in canonical.evidence_artifacts],
            ["path-a", "supported-production-path-b"],
        )
        self.assertIsNone(canonical.disposition)

    def test_same_evidence_key_with_rephrased_summary_is_idempotent(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        original_artifact = EvidenceArtifact(
            key="path-a",
            kind=EvidenceKind.OBSERVATION,
            summary="Stack trace from path A.",
        )
        original_finding = finding().model_copy(
            update={"evidence_artifacts": [original_artifact]}
        )
        original = result().model_copy(update={"findings": [original_finding]})
        ledger.submit(original)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="Recorded for artifact idempotency coverage.",
        )
        rephrased_artifact = original_artifact.model_copy(
            update={"summary": "Path A produced the same stack trace."}
        )
        retry_finding = original_finding.model_copy(
            update={"evidence_artifacts": [rephrased_artifact]}
        )
        retry = result(execution_id="local-retry").model_copy(
            update={"round_number": 2, "findings": [retry_finding]}
        )

        ledger.submit(retry)

        self.assertEqual(len(ledger.results), 1)
        self.assertEqual(
            ledger.current_findings[0].disposition,
            Disposition.DECLINED,
        )

    def test_rephrased_text_evidence_does_not_reopen_or_consume_a_run(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        original_finding = finding().model_copy(
            update={"evidence": "Observed on a supported path."}
        )
        original = result().model_copy(update={"findings": [original_finding]})
        ledger.submit(original)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="Recorded for retry-idempotency coverage.",
        )
        rephrased = original_finding.model_copy(
            update={"evidence": "Seen through the supported path."}
        )
        retry = result(execution_id="local-retry").model_copy(
            update={"round_number": 2, "findings": [rephrased]}
        )

        ledger.submit(retry)

        self.assertEqual(len(ledger.results), 1)
        self.assertEqual(
            ledger.current_findings[0].disposition,
            Disposition.DECLINED,
        )
        self.assertEqual(
            ledger.current_findings[0].evidence,
            "Observed on a supported path.",
        )

    def test_weaker_structured_evidence_cannot_reopen_or_overwrite(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        stronger = P2Evidence(
            reachability=Reachability.SUPPORTED,
            impact=Impact.MEANINGFUL,
            observed_recurrence=2,
            interface_boundary_risk=True,
            security_risk=True,
            data_loss_risk=False,
            durable_state_risk=True,
            fix_cost=FixCost.CHEAP,
        )
        original_finding = finding().model_copy(update={"p2_evidence": stronger})
        original = result().model_copy(update={"findings": [original_finding]})
        ledger.submit(original)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DEFERRED_TO_EXISTING_ISSUE,
            rationale="The existing security redesign owns the fix.",
            deferred_to_issue="BOU-1234",
        )
        weaker = P2Evidence(
            reachability=Reachability.UNREACHABLE,
            impact=Impact.LOW,
            observed_recurrence=0,
            interface_boundary_risk=False,
            security_risk=False,
            data_loss_risk=False,
            durable_state_risk=False,
            fix_cost=FixCost.ARCHITECTURAL,
        )
        retry_finding = original_finding.model_copy(update={"p2_evidence": weaker})
        retry = result(execution_id="local-retry").model_copy(
            update={"round_number": 2, "findings": [retry_finding]}
        )

        ledger.submit(retry)

        canonical = ledger.current_findings[0]
        self.assertEqual(len(ledger.results), 1)
        self.assertEqual(canonical.p2_evidence, stronger)
        self.assertEqual(
            canonical.disposition,
            Disposition.DEFERRED_TO_EXISTING_ISSUE,
        )

    def test_stronger_structured_evidence_merges_monotonically(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        initial = P2Evidence(
            reachability=Reachability.UNREACHABLE,
            impact=Impact.LOW,
            observed_recurrence=0,
            interface_boundary_risk=False,
            security_risk=False,
            data_loss_risk=False,
            durable_state_risk=False,
            fix_cost=FixCost.ARCHITECTURAL,
        )
        original_finding = finding().model_copy(update={"p2_evidence": initial})
        original = result().model_copy(update={"findings": [original_finding]})
        ledger.submit(original)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="Initially unreachable and expensive.",
        )
        stronger = P2Evidence(
            reachability=Reachability.SUPPORTED,
            impact=Impact.MEANINGFUL,
            observed_recurrence=3,
            interface_boundary_risk=False,
            security_risk=True,
            data_loss_risk=False,
            durable_state_risk=True,
            fix_cost=FixCost.CHEAP,
        )
        retry_finding = original_finding.model_copy(update={"p2_evidence": stronger})
        retry = result(execution_id="local-retry").model_copy(
            update={"round_number": 2, "findings": [retry_finding]}
        )

        ledger.submit(retry)

        canonical = ledger.current_findings[0]
        self.assertEqual(len(ledger.results), 2)
        self.assertEqual(canonical.p2_evidence, stronger)
        self.assertIsNone(canonical.disposition)

    def test_identical_resubmission_is_idempotent(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        review_result = result()

        ledger.submit(review_result)
        ledger.submit(review_result)

        self.assertEqual(len(ledger.results), 1)
        self.assertEqual(len(ledger.current_findings), 1)

    def test_retry_with_new_execution_and_round_is_idempotent(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result(execution_id="local-attempt-one"))
        retry = result(execution_id="local-attempt-two").model_copy(
            update={"round_number": 2}
        )

        ledger.submit(retry)

        self.assertEqual(len(ledger.results), 1)
        self.assertEqual(
            ledger.results[0].reviewer_execution_id,
            "local-attempt-one",
        )

    def test_retry_can_repair_duplicate_execution_identity_across_slots(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        first = result(execution_id="shared-execution")
        second = result(execution_id="shared-execution").model_copy(
            update={"slot_number": 2}
        )
        ledger.submit(first)
        ledger.submit(second)
        repaired = result(execution_id="independent-execution").model_copy(
            update={"slot_number": 2, "round_number": 2}
        )

        ledger.submit(repaired)

        self.assertEqual(len(ledger.results), 3)
        self.assertEqual(
            ledger.results[-1].reviewer_execution_id,
            "independent-execution",
        )

    def test_materially_new_evidence_is_retained(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        original = result()
        new_finding = original.findings[0].model_copy(
            update={"evidence": "Observed twice on an exact-head required-check run."}
        )
        new_result = original.model_copy(update={"findings": [new_finding]})

        ledger.submit(original)
        ledger.submit(new_result)

        self.assertEqual(len(ledger.results), 2)
        self.assertEqual(
            ledger.current_findings[0].evidence,
            "Observed twice on an exact-head required-check run.",
        )

    def test_stale_findings_are_excluded_from_current_snapshot(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)

        ledger.submit(result(head_sha="a" * 40))

        self.assertEqual(ledger.current_findings, [])
        self.assertTrue(ledger.results[0].stale)

    def test_mismatched_repository_is_rejected(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        foreign = result().model_copy(update={"repository": "other/repository"})

        with self.assertRaisesRegex(ValueError, "repository"):
            ledger.submit(foreign)

    def test_duplicate_findings_preserve_contributing_executions(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)

        ledger.submit(result(execution_id="local-r1-slot1"))
        ledger.submit(result(execution_id="local-r1-slot2"))

        self.assertEqual(len(ledger.current_findings), 1)
        self.assertEqual(
            set(ledger.current_findings[0].contributing_execution_ids),
            {"local-r1-slot1", "local-r1-slot2"},
        )

    def test_duplicate_findings_preserve_highest_severity(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        p2_result = result(execution_id="local-r1-slot1")
        p1_finding = finding(execution_id="local-r1-slot2").model_copy(
            update={"severity": Severity.P1}
        )
        p1_result = ReviewResult(
            repository=REPOSITORY,
            head_sha=CURRENT_HEAD,
            stage=ReviewStage.LOCAL,
            round_number=1,
            slot_number=2,
            reviewer_execution_id="local-r1-slot2",
            findings=[p1_finding],
        )

        ledger.submit(p2_result)
        ledger.submit(p1_result)

        self.assertEqual(ledger.current_findings[0].severity, Severity.P1)

    def test_duplicate_findings_can_promote_to_p0(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result(execution_id="local-r1-slot1"))
        p0_finding = finding(execution_id="local-r1-slot2").model_copy(
            update={"severity": Severity.P0}
        )
        p0_result = ReviewResult(
            repository=REPOSITORY,
            head_sha=CURRENT_HEAD,
            stage=ReviewStage.LOCAL,
            round_number=1,
            slot_number=2,
            reviewer_execution_id="local-r1-slot2",
            findings=[p0_finding],
        )

        ledger.submit(p0_result)

        self.assertEqual(ledger.current_findings[0].severity, Severity.P0)

    def test_materially_new_evidence_reopens_a_settled_finding(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        original = result()
        ledger.submit(original)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="No supported path was known.",
        )

        new_finding = original.findings[0].model_copy(
            update={"evidence": "Observed on a supported exact-head path."}
        )
        ledger.submit(original.model_copy(update={"findings": [new_finding]}))

        self.assertIsNone(ledger.current_findings[0].disposition)
        self.assertIsNone(ledger.current_findings[0].rationale)

    def test_reviewer_submission_cannot_set_settlement_state(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        submitted = finding().model_copy(
            update={
                "severity": Severity.P1,
                "disposition": Disposition.FIXED,
                "rationale": "Reviewer says it is fixed.",
                "verification_passed": True,
            }
        )
        review_result = result().model_copy(update={"findings": [submitted]})

        ledger.submit(review_result)

        canonical = ledger.current_findings[0]
        self.assertIsNone(canonical.disposition)
        self.assertIsNone(canonical.rationale)
        self.assertFalse(canonical.verification_passed)

    def test_disposition_requires_rationale(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result())
        fingerprint = ledger.current_findings[0].fingerprint

        with self.assertRaisesRegex(ValueError, "rationale"):
            ledger.record_disposition(
                fingerprint=fingerprint,
                disposition=Disposition.DEFER,
                rationale="",
            )

    def test_declined_p2_records_rationale(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result())
        fingerprint = ledger.current_findings[0].fingerprint

        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="The path is unreachable in supported configurations.",
        )

        self.assertEqual(
            ledger.current_findings[0].disposition,
            Disposition.DECLINED,
        )

    def test_deferred_p2_requires_and_records_existing_issue(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result())
        fingerprint = ledger.current_findings[0].fingerprint

        with self.assertRaisesRegex(ValueError, "existing issue"):
            ledger.record_disposition(
                fingerprint=fingerprint,
                disposition=Disposition.DEFERRED_TO_EXISTING_ISSUE,
                rationale="The durable-state redesign belongs to existing work.",
            )

        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DEFERRED_TO_EXISTING_ISSUE,
            rationale="The durable-state redesign belongs to existing work.",
            deferred_to_issue="BOU-1234",
        )

        self.assertEqual(
            ledger.current_findings[0].deferred_to_issue,
            "BOU-1234",
        )

    def test_ledger_round_trip_preserves_disposition(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result())
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DEFER,
            rationale="Requires an unsupported status provider.",
        )

        restored = ReviewLedger.model_validate_json(ledger.model_dump_json())

        self.assertEqual(restored.current_findings[0].disposition, Disposition.DEFER)
        self.assertEqual(
            restored.current_findings[0].rationale,
            "Requires an unsupported status provider.",
        )

    def test_loading_ledger_rejects_foreign_current_result(self) -> None:
        foreign = result().model_copy(
            update={"repository": "other/repository", "findings": []}
        )

        with self.assertRaisesRegex(ValueError, "result repository"):
            ReviewLedger(
                repository=REPOSITORY,
                head_sha=CURRENT_HEAD,
                results=[foreign],
            )

    def test_loading_ledger_requires_old_head_result_to_be_stale(self) -> None:
        old = result(head_sha="a" * 40)

        with self.assertRaisesRegex(ValueError, "older-head"):
            ReviewLedger(
                repository=REPOSITORY,
                head_sha=CURRENT_HEAD,
                results=[old],
            )

    def test_reopening_finding_invalidates_verification(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result())
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.FIXED,
            rationale="The first fix landed.",
        )
        ledger.record_verification(fingerprint=fingerprint, passed=True)

        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.FIX_NOW,
            rationale="The finding reproduced after the first fix.",
        )

        self.assertFalse(ledger.current_findings[0].verification_passed)

    def test_recording_reproduction_reopens_declined_finding(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        ledger.submit(result())
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="No reproduction was known.",
        )

        ledger.record_reproduction(
            fingerprint=fingerprint,
            reproduction="Reproduced through a supported exact-head path.",
        )

        self.assertIsNone(ledger.current_findings[0].disposition)
        self.assertIsNone(ledger.current_findings[0].rationale)

    def test_declining_incorrect_p0_requires_evidence(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        critical = result().model_copy(
            update={
                "findings": [finding().model_copy(update={"severity": Severity.P0})]
            }
        )
        ledger.submit(critical)
        fingerprint = ledger.current_findings[0].fingerprint

        with self.assertRaisesRegex(ValueError, "evidence"):
            ledger.record_disposition(
                fingerprint=fingerprint,
                disposition=Disposition.REJECT,
                rationale="The report is factually incorrect.",
            )


if __name__ == "__main__":
    unittest.main()
