import unittest

from pydantic import ValidationError

from agent_review_coordinator.policy import (
    ReviewPolicy,
    ReviewRequirement,
    ReviewStage,
    ReviewStagePolicy,
)


class ReviewPolicyTest(unittest.TestCase):
    def test_double_review_policy_publishes_versioned_requirements(self) -> None:
        policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 2,
                        "required_results": 2,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        )

        requirements = policy.requirements_for(stage=ReviewStage.LOCAL)

        self.assertEqual(
            [
                requirement.model_dump(mode="json", exclude_none=True)
                for requirement in requirements
            ],
            [
                {"schema_version": 1, "slot": "local:1", "required": True},
                {"schema_version": 1, "slot": "local:2", "required": True},
            ],
        )

    def test_requirement_accepts_an_explicit_provider_constraint(self) -> None:
        requirement = ReviewRequirement(
            slot="security-review",
            required=True,
            provider_constraint="trusted-security-provider",
        )

        self.assertEqual(
            requirement.model_dump(mode="json"),
            {
                "schema_version": 1,
                "slot": "security-review",
                "required": True,
                "provider_constraint": "trusted-security-provider",
            },
        )

    def test_policy_marks_non_quorum_slots_optional(self) -> None:
        policy = ReviewPolicy.model_validate(
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

        requirements = policy.requirements_for(stage=ReviewStage.LOCAL)

        self.assertEqual(
            [requirement.required for requirement in requirements],
            [True, True, False],
        )

    def test_provider_diversity_is_part_of_requirement_contract(self) -> None:
        policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 2,
                        "required_results": 2,
                        "distinct_providers": True,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        )

        requirements = policy.requirements_for(stage=ReviewStage.LOCAL)

        self.assertEqual(
            [requirement.provider_constraint for requirement in requirements],
            ["distinct", "distinct"],
        )

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

    def test_reviewer_count_is_capped_at_supported_maximum(self) -> None:
        self.assertEqual(ReviewStagePolicy(reviewer_count=8).reviewer_count, 8)
        with self.assertRaises(ValidationError):
            ReviewStagePolicy(reviewer_count=9)

    def test_required_results_is_capped_at_supported_maximum(self) -> None:
        self.assertEqual(
            ReviewStagePolicy(reviewer_count=8, required_results=8).required_results,
            8,
        )
        with self.assertRaises(ValidationError):
            ReviewStagePolicy(reviewer_count=9, required_results=9)

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

    def test_slots_reject_round_over_generation_budget(self) -> None:
        policy = ReviewPolicy.model_validate(
            {
                "version": 1,
                "review": {
                    "local": {
                        "reviewer_count": 2,
                        "max_generation_rounds": 2,
                    },
                    "backstop": {"reviewer_count": 1},
                },
            }
        )

        with self.assertRaisesRegex(ValueError, "generation budget"):
            policy.slots_for(stage=ReviewStage.LOCAL, round_number=3)


if __name__ == "__main__":
    unittest.main()
