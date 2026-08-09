import unittest


class ImportTest(unittest.TestCase):
    def test_package_exports_public_contract(self) -> None:
        import agent_review_coordinator

        self.assertEqual(agent_review_coordinator.__version__, "0.3.0")
        self.assertTrue(agent_review_coordinator.ReviewRequirement)
        self.assertTrue(agent_review_coordinator.P2Evidence)
        self.assertTrue(agent_review_coordinator.FindingSettlementState)
