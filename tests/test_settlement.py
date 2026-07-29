import unittest

from agent_review_coordinator.findings import Disposition, Finding, Severity
from agent_review_coordinator.ledger import ReviewLedger, ReviewResult
from agent_review_coordinator.policy import ReviewPolicy, ReviewStage
from agent_review_coordinator.settlement import evaluate

REPOSITORY = "Boundless-Studios/gaia-free"
HEAD = "c" * 40


def policy(
    *,
    max_rounds: int = 2,
    distinct_executions: bool = True,
    distinct_providers: bool = False,
    reviewer_count: int = 1,
) -> ReviewPolicy:
    return ReviewPolicy.model_validate(
        {
            "version": 1,
            "review": {
                "local": {
                    "reviewer_count": reviewer_count,
                    "required_results": reviewer_count,
                    "max_generation_rounds": max_rounds,
                    "distinct_executions": distinct_executions,
                    "distinct_providers": distinct_providers,
                },
                "backstop": {
                    "reviewer_count": 1,
                    "required_results": 1,
                    "trigger": "new_head_sha",
                },
            },
        }
    )


def finding(severity: Severity = Severity.P2) -> Finding:
    return Finding(
        repository=REPOSITORY,
        head_sha=HEAD,
        reviewer_execution_id="local-review",
        severity=severity,
        title="Do not synthesize green",
        explanation="A missing check is treated as passing.",
        path="scripts/review.py",
        invariant="CI must be terminal",
    )


def result(
    *,
    stage: ReviewStage,
    round_number: int = 1,
    findings: list[Finding] | None = None,
    execution_id: str | None = None,
    provider: str | None = None,
) -> ReviewResult:
    identifier = execution_id or f"{stage.value}-review"
    normalized = [
        item.model_copy(
            update={
                "reviewer_execution_id": identifier,
                "reviewer_provider": provider,
                "contributing_execution_ids": [identifier],
            }
        )
        for item in (findings or [])
    ]
    return ReviewResult(
        repository=REPOSITORY,
        head_sha=HEAD,
        stage=stage,
        round_number=round_number,
        slot_number=1,
        reviewer_execution_id=identifier,
        reviewer_provider=provider,
        findings=normalized,
    )


def reviewed_ledger(item: Finding, *, round_number: int = 1) -> ReviewLedger:
    ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
    ledger.submit(
        result(
            stage=ReviewStage.LOCAL,
            round_number=round_number,
            findings=[item],
            execution_id="local-review",
        )
    )
    ledger.submit(result(stage=ReviewStage.BACKSTOP, execution_id="backstop-review"))
    return ledger


class SettlementTest(unittest.TestCase):
    def test_p1_blocks_after_generation_budget_is_exhausted(self) -> None:
        report = evaluate(
            policy=policy(max_rounds=2),
            ledger=reviewed_ledger(finding(Severity.P1), round_number=2),
        )

        self.assertFalse(report.settled)
        self.assertIn("address_p1", report.required_actions)
        self.assertFalse(report.allow_full_review)

    def test_deferred_p2_allows_settlement(self) -> None:
        ledger = reviewed_ledger(finding())
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DEFER,
            rationale="Requires an unsupported status provider.",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertTrue(report.settled)

    def test_unevaluated_p2_blocks_for_evaluation_not_implementation(self) -> None:
        report = evaluate(policy=policy(), ledger=reviewed_ledger(finding()))

        self.assertFalse(report.settled)
        self.assertEqual(report.required_actions, ["evaluate_p2"])

    def test_fix_now_requires_targeted_verification(self) -> None:
        ledger = reviewed_ledger(finding())
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.FIX_NOW,
            rationale="Reproduced on a supported required-check path.",
        )

        self.assertIn(
            "fix_p2",
            evaluate(policy=policy(), ledger=ledger).required_actions,
        )

        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.FIXED,
            rationale="Missing required checks now block settlement.",
        )
        self.assertIn(
            "verify_fix",
            evaluate(policy=policy(), ledger=ledger).required_actions,
        )

        ledger.record_verification(fingerprint=fingerprint, passed=True)
        self.assertTrue(evaluate(policy=policy(), ledger=ledger).settled)

    def test_prove_first_promotes_after_reproduction(self) -> None:
        ledger = reviewed_ledger(finding())
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.PROVE_FIRST,
            rationale="Impact is high but the path has not been observed.",
        )

        self.assertIn(
            "prove_p2",
            evaluate(policy=policy(), ledger=ledger).required_actions,
        )

        ledger.record_reproduction(
            fingerprint=fingerprint,
            reproduction="Required check absence returns a clean result.",
        )
        self.assertIn(
            "fix_reproduced_p2",
            evaluate(policy=policy(), ledger=ledger).required_actions,
        )

    def test_missing_reviewer_result_blocks_settlement(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
        ledger.submit(result(stage=ReviewStage.LOCAL))

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertEqual(report.missing_slots, ["backstop:1"])

    def test_distinct_provider_policy_requires_provider_identity(self) -> None:
        ledger = reviewed_ledger(finding())
        report = evaluate(policy=policy(distinct_providers=True), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("local:provider-diversity", report.missing_slots)

    def test_non_distinct_execution_policy_counts_filled_slots(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="shared-review",
            )
        )
        second = result(
            stage=ReviewStage.LOCAL,
            execution_id="shared-review",
        ).model_copy(update={"slot_number": 2})
        ledger.submit(second)
        ledger.submit(result(stage=ReviewStage.BACKSTOP))

        report = evaluate(
            policy=policy(distinct_executions=False, reviewer_count=2),
            ledger=ledger,
        )

        self.assertTrue(report.settled)


if __name__ == "__main__":
    unittest.main()
