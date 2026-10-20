import unittest

from morpheus.detection import DetectionConfig, FlowDetector
from morpheus.monitoring import FlowObservation


def obs(source="10.0.0.200", destination="10.0.0.1", port=9000, **kwargs):
    values = dict(source_ip=source, destination_ip=destination, protocol=6,
                  source_port=40000, destination_port=port, packet_count=1,
                  byte_count=64, duration_seconds=0.1, observed_at="test-time")
    values.update(kwargs)
    return FlowObservation(**values)


class FlowDetectorTests(unittest.TestCase):
    def make_detector(self, **kwargs):
        values = dict(observation_window_seconds=10,
                      minimum_distinct_hosts=3,
                      minimum_distinct_ports=3,
                      designated_hosts=frozenset({"10.0.0.1", "10.0.0.2", "10.0.0.3"}))
        values.update(kwargs)
        config = DetectionConfig(**values)
        return FlowDetector(config)

    def test_normal_single_server_traffic_is_not_suspicious(self):
        detector = self.make_detector()
        self.assertIsNone(detector.observe(obs("10.0.0.1", "10.0.0.100", 9000), 1))
        self.assertIsNone(detector.observe(obs("10.0.0.1", "10.0.0.100", 9000), 2))

    def test_multiple_designated_hosts_triggers_suspicious_event(self):
        detector = self.make_detector()
        self.assertIsNone(detector.observe(obs(destination="10.0.0.1", port=80), 1))
        self.assertIsNone(detector.observe(obs(destination="10.0.0.2", port=80), 2))
        event = detector.observe(obs(destination="10.0.0.3", port=80), 3)
        self.assertEqual("suspicious", event.decision)
        self.assertEqual(3, event.distinct_hosts)
        self.assertIn("multiple designated hosts", event.reason)

    def test_distinct_port_threshold_triggers(self):
        detector = self.make_detector(minimum_distinct_hosts=99)
        for index, port in enumerate((80, 443), start=1):
            self.assertIsNone(detector.observe(obs(destination="10.0.0.1", port=port), index))
        event = detector.observe(obs(destination="10.0.0.1", port=9000), 3)
        self.assertEqual(3, event.distinct_ports)
        self.assertIn("multiple destination ports", event.reason)

    def test_threshold_is_inclusive_and_expired_observations_are_removed(self):
        detector = self.make_detector(minimum_distinct_hosts=2)
        detector.observe(obs(destination="10.0.0.1", port=1), 0)
        event = detector.observe(obs(destination="10.0.0.2", port=1), 10)
        self.assertIsNotNone(event)
        detector = self.make_detector(minimum_distinct_hosts=2)
        detector.observe(obs(destination="10.0.0.1", port=1), 0)
        self.assertIsNone(detector.observe(obs(destination="10.0.0.2", port=1), 10.01))

    def test_incomplete_records_are_ignored(self):
        detector = self.make_detector()
        self.assertIsNone(detector.observe(obs(source=None), 1))
        self.assertIsNone(detector.observe(obs(destination=None), 1))

    def test_non_designated_destination_is_ignored(self):
        self.assertIsNone(self.make_detector().observe(obs(destination="192.0.2.1"), 1))

    def test_repeated_observations_emit_once_until_window_rearms(self):
        detector = self.make_detector(minimum_distinct_hosts=2)
        detector.observe(obs(destination="10.0.0.1", port=1, flow_id="a"), 1)
        event = detector.observe(obs(destination="10.0.0.2", port=1, flow_id="b"), 2)
        self.assertIsNotNone(event)
        self.assertEqual(("10.0.0.1", "10.0.0.2"), event.destination_hosts)
        self.assertIsNone(detector.observe(obs(destination="10.0.0.2", port=1, flow_id="b",
                                               packet_count=0), 3))
        # Once the old evidence expires, a fresh threshold crossing emits again.
        detector.observe(obs(destination="10.0.0.1", port=1, flow_id="c"), 13)
        self.assertIsNotNone(detector.observe(obs(destination="10.0.0.2", port=1, flow_id="d"), 14))

    def test_malformed_observation_and_clock_are_ignored(self):
        detector = self.make_detector()
        self.assertIsNone(detector.observe({"source_ip": "bad"}, 1))
        self.assertIsNone(detector.observe(obs(), float("nan")))

    def test_detection_config_rejects_invalid_bounds(self):
        with self.assertRaises(ValueError):
            FlowDetector(DetectionConfig(observation_window_seconds=float("inf")))
        with self.assertRaises(ValueError):
            FlowDetector(DetectionConfig(maximum_sources=0))


if __name__ == "__main__":
    unittest.main()
