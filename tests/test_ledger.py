import unittest

from agent_review_coordinator.findings import Disposition, Finding, Severity
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
    def test_identical_resubmission_is_idempotent(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        review_result = result()

        ledger.submit(review_result)
        ledger.submit(review_result)

        self.assertEqual(len(ledger.results), 1)
        self.assertEqual(len(ledger.current_findings), 1)

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

    def test_declining_incorrect_p0_requires_evidence(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=CURRENT_HEAD)
        critical = result().model_copy(
            update={
                "findings": [
                    finding().model_copy(update={"severity": Severity.P0})
                ]
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
