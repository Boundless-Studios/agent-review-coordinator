import unittest

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
from agent_review_coordinator.ledger import ReviewLedger, ReviewResult
from agent_review_coordinator.policy import ReviewStage

REPOSITORY = "Boundless-Studios/gaia-free"
CURRENT_HEAD = "b" * 40


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
) -> ReviewResult:
    return ReviewResult(
        repository=REPOSITORY,
        head_sha=head_sha,
        stage=ReviewStage.LOCAL,
        round_number=1,
        slot_number=1,
        reviewer_execution_id=execution_id,
        findings=[finding(head_sha=head_sha, execution_id=execution_id)],
    )


class ReviewLedgerTest(unittest.TestCase):
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
