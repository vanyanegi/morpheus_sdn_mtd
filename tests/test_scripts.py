import unittest
from unittest import mock

from morpheus.lab_config import HOSTS, SENSOR_IPS, SERVER_TCP_PORT, SERVER_UDP_PORT
from scripts import reconnaissance, traffic_generator, traffic_server


class LabConfigurationTests(unittest.TestCase):
    def test_host_configuration_has_expected_unique_lab_addresses(self):
        self.assertEqual(12, len(HOSTS))
        self.assertEqual(12, len(set(HOSTS.values())))
        self.assertEqual("10.0.0.100", HOSTS["server"])
        self.assertEqual("10.0.0.200", HOSTS["attacker"])
        self.assertEqual(8, len(SENSOR_IPS))
        self.assertEqual((9000, 9001), (SERVER_TCP_PORT, SERVER_UDP_PORT))

    def test_traffic_options_reject_external_hosts_and_bad_rates(self):
        with self.assertRaises(ValueError):
            traffic_generator.validate_options("10.0.0.1", "192.0.2.4", 1, 1, 1)
        with self.assertRaises(ValueError):
            traffic_generator.validate_options("10.0.0.1", HOSTS["server"], float("nan"), 1, 1)
        with self.assertRaises(ValueError):
            traffic_generator.validate_options("10.0.0.1", HOSTS["server"], 1, -1, 1)
        with mock.patch("scripts.traffic_generator.socket.socket") as create_socket:
            with self.assertRaises(ValueError):
                traffic_generator.run("10.0.0.1", "192.0.2.4", 1, 1, 1)
            create_socket.assert_not_called()

    def test_server_bind_and_ports_are_checked(self):
        with self.assertRaises(ValueError):
            traffic_server.validate_options("0.0.0.0", 9000, 9001)
        with self.assertRaises(ValueError):
            traffic_server.validate_options(HOSTS["server"], 9000, 9000)

    def test_recon_rejects_non_lab_targets_before_resolution(self):
        with mock.patch("scripts.reconnaissance.socket.getaddrinfo") as getaddrinfo:
            with self.assertRaises(ValueError):
                reconnaissance.probe(["192.0.2.1"], logger=lambda *_: None)
            getaddrinfo.assert_not_called()

    def test_recon_pins_hostname_to_configured_ip_before_connecting(self):
        fake_connection = mock.MagicMock()
        with mock.patch("scripts.reconnaissance.socket.getaddrinfo",
                        side_effect=AssertionError("recon must not use DNS")) as resolver, \
                mock.patch("scripts.reconnaissance.socket.create_connection",
                           return_value=fake_connection) as connect, \
                mock.patch("scripts.reconnaissance.time.sleep"):
            outcomes = reconnaissance.probe(["sensor1"], ports=(80,), delay=0.25,
                                            logger=lambda *_: None)
        connect.assert_called_once_with((HOSTS["sensor1"], 80), timeout=0.5)
        resolver.assert_not_called()
        self.assertEqual("sensor1", outcomes[0]["target"])
        self.assertEqual(HOSTS["sensor1"], outcomes[0]["ip"])
        self.assertEqual("open", outcomes[0]["outcome"])

    def test_configured_ip_is_a_safe_target_for_mininet_cli_substitution(self):
        with mock.patch("scripts.reconnaissance.socket.create_connection",
                        return_value=mock.MagicMock()) as connect, \
                mock.patch("scripts.reconnaissance.time.sleep"), \
                mock.patch("scripts.reconnaissance.socket.getaddrinfo",
                           side_effect=AssertionError("recon must not use DNS")) as resolver:
            outcomes = reconnaissance.probe([HOSTS["sensor1"]], ports=(80,),
                                            logger=lambda *_: None)
        connect.assert_called_once_with((HOSTS["sensor1"], 80), timeout=0.5)
        resolver.assert_not_called()
        self.assertEqual("sensor1", outcomes[0]["target"])

    def test_hostname_mapping_uses_config_without_dns(self):
        self.assertEqual(HOSTS["sensor1"], reconnaissance.configured_target_ip("sensor1"))
        with self.assertRaises(ValueError):
            reconnaissance.configured_target_ip("192.0.2.1")

    def test_recon_rate_and_timeout_bounds(self):
        for kwargs in ({"delay": 0}, {"delay": float("inf")},
                       {"timeout": 0}, {"timeout": 5.1}, {"ports": (0,)}):
            with self.assertRaises(ValueError):
                reconnaissance.validate_options(["sensor1"], **kwargs)


if __name__ == "__main__":
    unittest.main()
