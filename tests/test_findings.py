import unittest

from agent_review_coordinator.findings import Disposition, Finding, Severity


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


if __name__ == "__main__":
    unittest.main()
