"""Shared addressing, service ports, and Phase 1 detection thresholds."""

HOSTS = {
    "sensor1": "10.0.0.1", "sensor2": "10.0.0.2",
    "sensor3": "10.0.0.3", "sensor4": "10.0.0.4",
    "sensor5": "10.0.0.5", "sensor6": "10.0.0.6",
    "sensor7": "10.0.0.7", "sensor8": "10.0.0.8",
    "actuator1": "10.0.0.21", "actuator2": "10.0.0.22",
    "server": "10.0.0.100", "attacker": "10.0.0.200",
}

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
SERVER_TCP_PORT = 9000
SERVER_UDP_PORT = 9001
STATS_INTERVAL_SECONDS = 10
DETECTION_WINDOW_SECONDS = 30
MINIMUM_DISTINCT_HOSTS = 3
MINIMUM_DISTINCT_PORTS = 3
MAXIMUM_SOURCES = 64
MAXIMUM_FLOWS_PER_SOURCE = 256

# The detector compares destinations to the virtual lab's complete host list.
DESIGNATED_HOST_IPS = frozenset(HOSTS.values())
SENSOR_IPS = frozenset(HOSTS["sensor{}".format(index)] for index in range(1, 9))
