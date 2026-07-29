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


if __name__ == "__main__":
    unittest.main()
