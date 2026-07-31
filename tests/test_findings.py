import unittest

from agent_review_coordinator.findings import (
    Disposition,
    Finding,
    FixCost,
    Impact,
    P2Evidence,
    Reachability,
    Severity,
)


def finding(
    *,
    reviewer_execution_id: str = "local-1",
    line: int | None = 21,
    invariant: str = "CI must be terminal",
) -> Finding:
    return Finding(
        repository="Boundless-Studios/gaia-free",
        head_sha="a" * 40,
        reviewer_execution_id=reviewer_execution_id,
        severity=Severity.P2,
        title="Do not synthesize green",
        explanation="A missing check is currently treated as passing.",
        path="scripts/review.py",
        line=line,
        invariant=invariant,
    )


class FindingTest(unittest.TestCase):
    def test_protocol_accepts_nonblocking_and_critical_severities(self) -> None:
        self.assertEqual(
            {
                Finding.model_validate(
                    finding().model_copy(update={"severity": severity}).model_dump()
                ).severity
                for severity in (Severity.P0, Severity.P3)
            },
            {Severity.P0, Severity.P3},
        )

    def test_p2_evidence_round_trips_decision_inputs(self) -> None:
        evidence = P2Evidence(
            reachability=Reachability.SUPPORTED,
            impact=Impact.MEANINGFUL,
            observed_recurrence=2,
            interface_boundary_risk=True,
            security_risk=False,
            data_loss_risk=False,
            durable_state_risk=True,
            fix_cost=FixCost.CHEAP,
        )
        item = finding().model_copy(update={"p2_evidence": evidence})

        restored = Finding.model_validate_json(item.model_dump_json())

        self.assertEqual(
            restored.p2_evidence.model_dump(mode="json"),
            {
                "schema_version": 1,
                "reachability": "supported",
                "impact": "meaningful",
                "observed_recurrence": 2,
                "interface_boundary_risk": True,
                "security_risk": False,
                "data_loss_risk": False,
                "durable_state_risk": True,
                "fix_cost": "cheap",
            },
        )

    def test_explicit_settlement_dispositions_are_available(self) -> None:
        self.assertIn(Disposition.DECLINED, Disposition)
        self.assertIn(Disposition.DEFERRED_TO_EXISTING_ISSUE, Disposition)

    def test_independent_reviewers_share_fingerprint(self) -> None:
        first = finding(reviewer_execution_id="local-1", line=21)
        second = finding(reviewer_execution_id="local-2", line=27)

        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_changed_invariant_changes_fingerprint(self) -> None:
        self.assertNotEqual(
            finding(invariant="CI must be terminal").fingerprint,
            finding(invariant="PR must be mergeable").fingerprint,
        )

    def test_tracker_write_disposition_does_not_exist(self) -> None:
        self.assertNotIn("file_ticket", {item.value for item in Disposition})

    def test_fingerprint_normalizes_case_and_whitespace(self) -> None:
        first = finding(invariant=" CI   must be terminal ")
        second = finding(invariant="ci must be TERMINAL")

        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_fingerprint_preserves_path_case(self) -> None:
        first = finding().model_copy(update={"path": "src/Foo.py", "fingerprint": ""})
        second = finding().model_copy(update={"path": "src/foo.py", "fingerprint": ""})

        reparsed_first = Finding.model_validate(first.model_dump())
        reparsed_second = Finding.model_validate(second.model_dump())

        self.assertNotEqual(reparsed_first.fingerprint, reparsed_second.fingerprint)


if __name__ == "__main__":
    unittest.main()
