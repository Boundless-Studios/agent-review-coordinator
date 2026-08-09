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
from agent_review_coordinator.ledger import ReviewLedger as ReviewLedgerModel
from agent_review_coordinator.ledger import ReviewResult
from agent_review_coordinator.policy import ReviewPolicy, ReviewStage
from agent_review_coordinator.settlement import FindingSettlementState, evaluate

REPOSITORY = "Boundless-Studios/gaia-free"
HEAD = "c" * 40


class ReviewLedger(ReviewLedgerModel):
    """Ledger fixture carrying the required delivery identity."""

    delivery_id: str = "repo:branch:base"
    review_charter_version: str = "gaia-v1"


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


def p2_evidence(
    *,
    reachability: Reachability = Reachability.UNKNOWN,
    impact: Impact = Impact.UNKNOWN,
    observed_recurrence: int = 0,
    interface_boundary_risk: bool = False,
    security_risk: bool = False,
    data_loss_risk: bool = False,
    durable_state_risk: bool = False,
    fix_cost: FixCost = FixCost.UNKNOWN,
) -> P2Evidence:
    return P2Evidence(
        reachability=reachability,
        impact=impact,
        observed_recurrence=observed_recurrence,
        interface_boundary_risk=interface_boundary_risk,
        security_risk=security_risk,
        data_loss_risk=data_loss_risk,
        durable_state_risk=durable_state_risk,
        fix_cost=fix_cost,
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
    for completed_round in range(1, round_number):
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                round_number=completed_round,
                execution_id=f"local-review-r{completed_round}",
            )
        )
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
    def test_p0_blocks_like_p1(self) -> None:
        report = evaluate(
            policy=policy(),
            ledger=reviewed_ledger(finding(Severity.P0)),
        )

        self.assertFalse(report.settled)
        self.assertIn("address_p0", report.required_actions)

    def test_p3_never_blocks_settlement(self) -> None:
        report = evaluate(
            policy=policy(),
            ledger=reviewed_ledger(finding(Severity.P3)),
        )

        self.assertTrue(report.settled)

    def test_p3_with_malformed_disposition_metadata_remains_nonblocking(self) -> None:
        ledger = reviewed_ledger(finding(Severity.P3))
        canonical = ledger.current_findings[0]
        canonical.disposition = Disposition.DECLINED
        canonical.rationale = None

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertTrue(report.settled)

    def test_p2_fix_signals_reject_a_decline(self) -> None:
        evidence_cases = [
            p2_evidence(reachability=Reachability.SUPPORTED),
            p2_evidence(impact=Impact.MEANINGFUL),
            p2_evidence(observed_recurrence=1),
            p2_evidence(interface_boundary_risk=True),
            p2_evidence(security_risk=True),
            p2_evidence(data_loss_risk=True),
            p2_evidence(durable_state_risk=True),
            p2_evidence(fix_cost=FixCost.CHEAP),
        ]

        for evidence in evidence_cases:
            with self.subTest(evidence=evidence):
                item = finding().model_copy(update={"p2_evidence": evidence})
                ledger = reviewed_ledger(item)
                fingerprint = ledger.current_findings[0].fingerprint
                ledger.record_disposition(
                    fingerprint=fingerprint,
                    disposition=Disposition.DECLINED,
                    rationale="The change is not worthwhile.",
                )

                report = evaluate(policy=policy(), ledger=ledger)

                self.assertFalse(report.settled)
                self.assertIn("fix_p2", report.required_actions)
                self.assertEqual(
                    report.finding_states[fingerprint],
                    FindingSettlementState.UNRESOLVED,
                )

    def test_unreachable_architectural_p2_can_be_declined(self) -> None:
        item = finding().model_copy(
            update={
                "p2_evidence": p2_evidence(
                    reachability=Reachability.UNREACHABLE,
                    impact=Impact.LOW,
                    fix_cost=FixCost.ARCHITECTURAL,
                )
            }
        )
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="Unsupported path and disproportionate architecture.",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertTrue(report.settled)
        self.assertEqual(
            report.finding_states[fingerprint],
            FindingSettlementState.DECLINED_WITH_RATIONALE,
        )

    def test_keyed_reproduction_requires_a_fix(self) -> None:
        item = finding().model_copy(
            update={
                "p2_evidence": p2_evidence(
                    reachability=Reachability.UNREACHABLE,
                    impact=Impact.LOW,
                    fix_cost=FixCost.ARCHITECTURAL,
                ),
                "evidence_artifacts": [
                    EvidenceArtifact(
                        key="supported-production-reproduction",
                        kind=EvidenceKind.REPRODUCTION,
                        summary="Reproduced through the supported production path.",
                    )
                ],
            }
        )
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="Structured evidence predates the reproduction.",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("fix_p2", report.required_actions)

    def test_unknown_p2_evidence_cannot_be_declined(self) -> None:
        item = finding().model_copy(update={"p2_evidence": p2_evidence()})
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DECLINED,
            rationale="Nothing is known yet.",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("evaluate_p2", report.required_actions)
        self.assertEqual(
            report.finding_states[fingerprint],
            FindingSettlementState.UNRESOLVED,
        )

    def test_p2_can_defer_to_an_existing_issue(self) -> None:
        item = finding().model_copy(
            update={
                "p2_evidence": p2_evidence(
                    reachability=Reachability.SUPPORTED,
                    durable_state_risk=True,
                )
            }
        )
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DEFERRED_TO_EXISTING_ISSUE,
            rationale="The owning durable-state redesign is already tracked.",
            deferred_to_issue="BOU-1234",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertTrue(report.settled)
        self.assertEqual(
            report.finding_states[fingerprint],
            FindingSettlementState.DEFERRED_TO_EXISTING_ISSUE,
        )

    def test_deferral_without_p2_evidence_remains_unresolved(self) -> None:
        ledger = reviewed_ledger(finding())
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DEFERRED_TO_EXISTING_ISSUE,
            rationale="The redesign is tracked elsewhere.",
            deferred_to_issue="BOU-1234",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertEqual(
            report.finding_states[fingerprint],
            FindingSettlementState.UNRESOLVED,
        )

    def test_persisted_deferral_without_issue_reference_is_unresolved(self) -> None:
        item = finding().model_copy(
            update={
                "p2_evidence": p2_evidence(
                    reachability=Reachability.UNREACHABLE,
                    impact=Impact.LOW,
                    fix_cost=FixCost.ARCHITECTURAL,
                ),
            }
        )
        ledger = reviewed_ledger(item)
        canonical = ledger.current_findings[0]
        canonical.disposition = Disposition.DEFERRED_TO_EXISTING_ISSUE
        canonical.rationale = "Tracked elsewhere."
        canonical.deferred_to_issue = None

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("evaluate_p2", report.required_actions)

    def test_late_exact_head_feedback_reopens_settlement(self) -> None:
        ledger = reviewed_ledger(finding(Severity.P3))
        self.assertTrue(evaluate(policy=policy(), ledger=ledger).settled)
        late = finding().model_copy(
            update={
                "title": "Late exact-head security finding",
                "invariant": "Untrusted input must remain bounded",
                "p2_evidence": p2_evidence(security_risk=True),
                "fingerprint": "",
            }
        )
        late_result = result(
            stage=ReviewStage.LOCAL,
            findings=[Finding.model_validate(late.model_dump())],
            execution_id="late-exact-head-review",
        ).model_copy(update={"slot_number": 2})

        ledger.submit(late_result)
        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn(
            late_result.findings[0].fingerprint,
            report.blocking_fingerprints,
        )
        self.assertEqual(
            report.finding_states[late_result.findings[0].fingerprint],
            FindingSettlementState.UNRESOLVED,
        )

    def test_p1_blocks_after_generation_budget_is_exhausted(self) -> None:
        report = evaluate(
            policy=policy(max_rounds=2),
            ledger=reviewed_ledger(finding(Severity.P1), round_number=2),
        )

        self.assertFalse(report.settled)
        self.assertIn("address_p1", report.required_actions)
        self.assertFalse(report.allow_full_review)

    def test_final_generation_defers_p2_even_when_evidence_requires_fix(self) -> None:
        item = finding().model_copy(
            update={"p2_evidence": p2_evidence(security_risk=True)}
        )
        ledger = reviewed_ledger(item, round_number=2)
        fingerprint = ledger.current_findings[0].fingerprint

        report = evaluate(policy=policy(max_rounds=2), ledger=ledger)

        deferred = ledger.current_findings[0]
        self.assertTrue(report.settled)
        self.assertEqual(deferred.disposition, Disposition.DEFER)
        self.assertIn("review_budget_exhausted", deferred.rationale or "")
        self.assertIn("generation=2", deferred.rationale or "")
        self.assertIn("max_generation_rounds=2", deferred.rationale or "")
        self.assertIn("local-review", deferred.rationale or "")
        self.assertNotIn(fingerprint, report.blocking_fingerprints)


    def test_deferred_p2_allows_settlement(self) -> None:
        item = finding().model_copy(
            update={
                "p2_evidence": p2_evidence(
                    reachability=Reachability.UNREACHABLE,
                    impact=Impact.LOW,
                    fix_cost=FixCost.ARCHITECTURAL,
                )
            }
        )
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.DEFER,
            rationale="Requires an unsupported status provider.",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertTrue(report.settled)

    def test_legacy_p2_dispositions_cannot_bypass_missing_evidence(self) -> None:
        for disposition in (
            Disposition.DEFER,
            Disposition.REJECT,
            Disposition.STALE,
            Disposition.WRONG_OWNER,
        ):
            with self.subTest(disposition=disposition):
                ledger = reviewed_ledger(finding())
                fingerprint = ledger.current_findings[0].fingerprint
                ledger.record_disposition(
                    fingerprint=fingerprint,
                    disposition=disposition,
                    rationale="Legacy wire value without decision evidence.",
                )

                report = evaluate(policy=policy(), ledger=ledger)

                self.assertFalse(report.settled)
                self.assertIn("evaluate_p2", report.required_actions)

    def test_legacy_decline_cannot_override_a_fix_signal(self) -> None:
        item = finding().model_copy(
            update={"p2_evidence": p2_evidence(security_risk=True)}
        )
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.REJECT,
            rationale="Legacy decline value.",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("fix_p2", report.required_actions)

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
        report = evaluate(policy=policy(), ledger=ledger)
        self.assertTrue(report.settled)
        self.assertEqual(
            report.finding_states[fingerprint],
            FindingSettlementState.FIXED,
        )

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

    def test_prove_first_with_a_fix_signal_requires_fix(self) -> None:
        item = finding().model_copy(
            update={"p2_evidence": p2_evidence(security_risk=True)}
        )
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.record_disposition(
            fingerprint=fingerprint,
            disposition=Disposition.PROVE_FIRST,
            rationale="Legacy disposition.",
        )

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertIn("fix_p2", report.required_actions)

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

    def test_two_providers_satisfy_two_required_slots(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="review-one",
                provider="provider-one",
            )
        )
        second = result(
            stage=ReviewStage.LOCAL,
            execution_id="review-two",
            provider="provider-two",
        ).model_copy(update={"slot_number": 2})
        ledger.submit(second)
        ledger.submit(result(stage=ReviewStage.BACKSTOP))

        report = evaluate(
            policy=policy(
                distinct_providers=True,
                reviewer_count=2,
            ),
            ledger=ledger,
        )

        self.assertTrue(report.settled)

    def test_one_provider_can_fill_two_independent_executions(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="review-one",
                provider="one-provider",
            )
        )
        second = result(
            stage=ReviewStage.LOCAL,
            execution_id="review-two",
            provider="one-provider",
        ).model_copy(update={"slot_number": 2})
        ledger.submit(second)
        ledger.submit(result(stage=ReviewStage.BACKSTOP))

        report = evaluate(
            policy=policy(reviewer_count=2),
            ledger=ledger,
        )

        self.assertTrue(report.settled)

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

    def test_distinct_execution_policy_requires_distinct_slots(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="review-one",
            )
        )
        retry_same_slot = result(
            stage=ReviewStage.LOCAL,
            execution_id="review-two",
        )
        ledger.submit(retry_same_slot)
        ledger.submit(result(stage=ReviewStage.BACKSTOP))

        report = evaluate(policy=policy(reviewer_count=2), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("local:2", report.missing_slots)

    def test_specific_required_slot_cannot_be_replaced_by_optional_slot(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
        required_slot_two = result(
            stage=ReviewStage.LOCAL,
            execution_id="required-two",
        ).model_copy(update={"slot_number": 2})
        optional_slot_three = result(
            stage=ReviewStage.LOCAL,
            execution_id="optional-three",
        ).model_copy(update={"slot_number": 3})
        ledger.submit(required_slot_two)
        ledger.submit(optional_slot_three)
        ledger.submit(result(stage=ReviewStage.BACKSTOP))
        custom_policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 3,
                        "required_results": 2,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        )

        report = evaluate(policy=custom_policy, ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("local:1", report.missing_slots)

    def test_provider_diversity_ignores_optional_and_out_of_policy_slots(self) -> None:
        ledger = ReviewLedger(repository=REPOSITORY, head_sha=HEAD)
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="required-one",
                provider="provider-a",
            )
        )
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="required-two",
                provider="provider-a",
            ).model_copy(update={"slot_number": 2})
        )
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="optional-three",
                provider="provider-b",
            ).model_copy(update={"slot_number": 3})
        )
        ledger.submit(
            result(
                stage=ReviewStage.LOCAL,
                execution_id="undeclared-four",
                provider="provider-c",
            ).model_copy(update={"slot_number": 4})
        )
        ledger.submit(result(stage=ReviewStage.BACKSTOP))
        custom_policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 3,
                        "required_results": 2,
                        "distinct_providers": True,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        )

        report = evaluate(
            policy=custom_policy,
            ledger=ledger,
        )

        self.assertFalse(report.settled)
        self.assertIn("local:provider-diversity", report.missing_slots)

    def test_persisted_p0_p1_dismissal_requires_nonblank_evidence(self) -> None:
        for severity in (Severity.P0, Severity.P1):
            for disposition in (Disposition.REJECT, Disposition.STALE):
                with self.subTest(severity=severity, disposition=disposition):
                    ledger = reviewed_ledger(finding(severity))
                    canonical = ledger.current_findings[0]
                    canonical.disposition = disposition
                    canonical.rationale = "Persisted dismissal."
                    canonical.evidence = "   "

                    report = evaluate(policy=policy(), ledger=ledger)

                    self.assertFalse(report.settled)
                    self.assertIn(
                        f"address_{severity.value}",
                        report.required_actions,
                    )

    def test_persisted_duplicate_requires_nonblank_target(self) -> None:
        ledger = reviewed_ledger(finding())
        canonical = ledger.current_findings[0]
        canonical.disposition = Disposition.DUPLICATE
        canonical.rationale = "Covered by another finding."
        canonical.duplicate_of = "   "

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertIn("evaluate_p2", report.required_actions)

    def test_persisted_decline_without_rationale_is_unresolved(self) -> None:
        item = finding().model_copy(
            update={
                "p2_evidence": p2_evidence(
                    reachability=Reachability.UNREACHABLE,
                    impact=Impact.LOW,
                    fix_cost=FixCost.ARCHITECTURAL,
                ),
            }
        )
        ledger = reviewed_ledger(item)
        fingerprint = ledger.current_findings[0].fingerprint
        ledger.current_findings[0].disposition = Disposition.DECLINED
        ledger.current_findings[0].rationale = None

        report = evaluate(policy=policy(), ledger=ledger)

        self.assertFalse(report.settled)
        self.assertEqual(
            report.finding_states[fingerprint],
            FindingSettlementState.UNRESOLVED,
        )

    def test_rejected_p1_requires_evidence(self) -> None:
        ledger = reviewed_ledger(finding(Severity.P1))
        fingerprint = ledger.current_findings[0].fingerprint

        with self.assertRaisesRegex(ValueError, "evidence"):
            ledger.record_disposition(
                fingerprint=fingerprint,
                disposition=Disposition.REJECT,
                rationale="The finding is incorrect.",
            )

    def test_duplicate_p1_requires_duplicate_target(self) -> None:
        ledger = reviewed_ledger(finding(Severity.P1))
        fingerprint = ledger.current_findings[0].fingerprint

        with self.assertRaisesRegex(ValueError, "duplicate"):
            ledger.record_disposition(
                fingerprint=fingerprint,
                disposition=Disposition.DUPLICATE,
                rationale="Covered by another finding.",
            )

    def test_duplicate_p2_requires_duplicate_target(self) -> None:
        ledger = reviewed_ledger(finding())
        fingerprint = ledger.current_findings[0].fingerprint

        with self.assertRaisesRegex(ValueError, "duplicate"):
            ledger.record_disposition(
                fingerprint=fingerprint,
                disposition=Disposition.DUPLICATE,
                rationale="Covered by another finding.",
            )


if __name__ == "__main__":
    unittest.main()
