import unittest

from segmentation_audit.engine import SegmentationAnalyzer
from segmentation_audit.models import FlowRecord, Policy, PolicyRule


class SegmentationAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy((
            PolicyRule("internet", "dmz", frozenset({443})),
            PolicyRule("server", "database", frozenset({5432})),
            PolicyRule("management", "server", frozenset({3389})),
        ))
        self.analyzer = SegmentationAnalyzer(self.policy)

    def test_allowed_flow_has_no_policy_violation(self):
        flow = FlowRecord("web", "server", "db", "database", "tcp", 5432, "App")
        findings = self.analyzer.analyze([flow])
        self.assertFalse(any("violates declared segmentation policy" in f.title for f in findings))

    def test_denied_flow_is_detected(self):
        flow = FlowRecord("user1", "user", "db", "database", "tcp", 5432, "App")
        findings = self.analyzer.analyze([flow])
        self.assertTrue(any("violates declared segmentation policy" in f.title for f in findings))

    def test_internet_sensitive_zone_is_detected(self):
        flow = FlowRecord("internet", "internet", "dc1", "identity", "tcp", 636, "Identity", True)
        findings = self.analyzer.analyze([flow])
        self.assertTrue(any("Internet path reaches" in f.title for f in findings))

    def test_sensitive_service_cross_boundary_is_detected(self):
        flow = FlowRecord("user1", "user", "srv", "server", "tcp", 3389, "Ops")
        findings = self.analyzer.analyze([flow])
        self.assertTrue(any("Sensitive service crosses" in f.title for f in findings))

    def test_missing_owner_on_denied_flow_is_detected(self):
        flow = FlowRecord("user1", "user", "db", "database", "tcp", 5432, None)
        findings = self.analyzer.analyze([flow])
        self.assertTrue(any("lacks accountable ownership" in f.title for f in findings))

    def test_finding_ids_are_deterministic(self):
        flow = FlowRecord("user1", "user", "db", "database", "tcp", 5432, None)
        first = [f.finding_id for f in self.analyzer.analyze([flow])]
        second = [f.finding_id for f in self.analyzer.analyze([flow])]
        self.assertEqual(first, second)

    def test_results_are_sorted_by_descending_score(self):
        flows = [
            FlowRecord("user1", "user", "srv", "server", "tcp", 8080, "App"),
            FlowRecord("internet", "internet", "dc", "identity", "tcp", 636, "Identity", True),
        ]
        scores = [f.score for f in self.analyzer.analyze(flows)]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ValueError):
            FlowRecord("a", "user", "b", "server", "tcp", 70000)


if __name__ == "__main__":
    unittest.main()
