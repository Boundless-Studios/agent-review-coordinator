import unittest
from pathlib import Path


class ReadmeContractTest(unittest.TestCase):
    def test_submit_documents_delivery_identity_and_budget_settlement(self) -> None:
        readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")

        self.assertIn("--delivery-id", readme)
        self.assertIn("--review-charter-version", readme)
        self.assertIn("cumulative", readme)
        self.assertIn("Disposition.DEFER", readme)
        self.assertIn("P0 and P1", readme)

    def test_package_versions_are_published_as_0_3_0(self) -> None:
        root = Path(__file__).parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('version = "0.3.0"', pyproject)


if __name__ == "__main__":
    unittest.main()
