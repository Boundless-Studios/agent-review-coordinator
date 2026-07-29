import unittest

from pydantic import ValidationError

from agent_review_coordinator.policy import (
    ReviewPolicy,
    ReviewStage,
    ReviewStagePolicy,
)


class ReviewPolicyTest(unittest.TestCase):
    def test_double_review_policy_creates_provider_neutral_slots(self) -> None:
        policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 2,
                        "required_results": 2,
                        "distinct_executions": True,
                        "distinct_providers": False,
                        "max_generation_rounds": 2,
                    },
                    "backstop": {
                        "reviewer_count": 1,
                        "trigger": "new_head_sha",
                    },
                },
            }
        )

        slots = policy.slots_for(stage=ReviewStage.LOCAL, round_number=1)

        self.assertEqual(len(slots), 2)
        self.assertTrue(all(slot.provider is None for slot in slots))
        self.assertEqual(len({slot.execution_id for slot in slots}), 2)

    def test_invalid_required_results_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ReviewStagePolicy(reviewer_count=1, required_results=2)

    def test_policy_loads_from_yaml(self) -> None:
        policy = ReviewPolicy.from_yaml(
            """
            version: 1
            review:
              local:
                reviewer_count: 2
              backstop:
                reviewer_count: 1
                trigger: new_head_sha
            settlement:
              p1: address
              p2: evaluate
              automatic_tracker_writes: false
            """
        )

        self.assertEqual(policy.review.local.required_results, 2)
        self.assertFalse(policy.settlement.automatic_tracker_writes)

    def test_policy_rejects_non_object_yaml(self) -> None:
        with self.assertRaisesRegex(TypeError, "YAML object"):
            ReviewPolicy.from_yaml("- one\n- two\n")


if __name__ == "__main__":
    unittest.main()
