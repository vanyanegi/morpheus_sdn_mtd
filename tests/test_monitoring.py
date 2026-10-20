import unittest
from types import SimpleNamespace

from morpheus.monitoring import FlowObservation, observation_from_openflow, observation_to_dict


class MonitoringTests(unittest.TestCase):
    def test_openflow_record_normalizes_ipv4_tcp_fields_and_identity(self):
        stat = SimpleNamespace(match={"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.100",
                                      "ip_proto": 6, "tcp_src": 1234, "tcp_dst": 9000},
                               packet_count=7, byte_count=512, duration_sec=2, duration_nsec=5,
                               table_id=0, priority=1, cookie=0)
        observed = observation_from_openflow(stat, "fixed-time", datapath_id=1)
        repeated = observation_from_openflow(stat, "later-time", datapath_id=1)
        self.assertEqual("10.0.0.1", observed.source_ip)
        self.assertEqual(9000, observed.destination_port)
        self.assertEqual(7, observed.packet_count)
        self.assertAlmostEqual(2.000000005, observed.duration_seconds)
        self.assertEqual("fixed-time", observed.observed_at)
        self.assertEqual(1, observed.datapath_id)
        self.assertEqual("1:0:1:0:", observed.flow_id[:8])
        self.assertEqual(observed.flow_id, repeated.flow_id)
        self.assertIn("flow_id", observation_to_dict(observed))

    def test_distinct_matches_have_distinct_flow_identifiers(self):
        left = SimpleNamespace(match={"ipv4_src": "10.0.0.1", "tcp_dst": 80})
        right = SimpleNamespace(match={"ipv4_src": "10.0.0.1", "tcp_dst": 443})
        self.assertNotEqual(observation_from_openflow(left, datapath_id=1).flow_id,
                            observation_from_openflow(right, datapath_id=1).flow_id)

    def test_missing_and_malformed_fields_are_safe(self):
        observed = FlowObservation.from_dict({"packet_count": "bad", "byte_count": -5,
                                             "duration_seconds": float("inf")})
        self.assertIsNone(observed.source_ip)
        self.assertEqual(0, observed.packet_count)
        self.assertEqual(0, observed.byte_count)
        self.assertEqual(0, observed.duration_seconds)
        self.assertIsInstance(observed.observed_at, str)
        self.assertIn("destination_ip", observation_to_dict(observed))

    def test_empty_or_unexpected_stats_objects_normalize_safely(self):
        observation = observation_from_openflow(SimpleNamespace(match=None, packet_count=None))
        self.assertIsNone(observation.source_ip)
        self.assertEqual(0, observation.packet_count)
        self.assertEqual(0, observation.byte_count)


if __name__ == "__main__":
    unittest.main()
