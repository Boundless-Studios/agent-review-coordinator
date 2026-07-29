import unittest


class ImportTest(unittest.TestCase):
    def test_package_exports_version(self) -> None:
        import agent_review_coordinator

        self.assertEqual(agent_review_coordinator.__version__, "0.1.0")
