"""Deterministic flow-aware heuristic for lab reconnaissance observations."""

from collections import deque
from dataclasses import dataclass
import math
from typing import Deque, Dict, FrozenSet, Optional, Tuple

from .monitoring import FlowObservation


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds for connection fan-out in a bounded time window."""

    observation_window_seconds: float = 30.0
    minimum_distinct_hosts: int = 3
    minimum_distinct_ports: int = 3
    designated_hosts: FrozenSet[str] = frozenset()
    maximum_sources: int = 64
    maximum_flows_per_source: int = 256


@dataclass(frozen=True)
class DetectionEvent:
    """One explainable transition into suspicious behavior."""

    source_ip: str
    decision: str
    reason: str
    distinct_hosts: int
    distinct_ports: int
    destination_hosts: Tuple[str, ...]
    destination_ports: Tuple[int, ...]
    window_seconds: float
    observed_at: str


class FlowDetector:
    """Track unique recent destinations and emit suspicion events only.

    Counter values are intentionally not thresholds: flow counters are
    cumulative and can reset when switch rules expire. This heuristic uses
    destination fan-out, so counter resets cannot inflate its decision.
    """

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()
        try:
            window = float(self.config.observation_window_seconds)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("observation_window_seconds must be finite and positive")
        if not math.isfinite(window) or window <= 0:
            raise ValueError("observation_window_seconds must be finite and positive")
        if (not isinstance(self.config.minimum_distinct_hosts, int)
                or not isinstance(self.config.minimum_distinct_ports, int)
                or self.config.minimum_distinct_hosts < 1
                or self.config.minimum_distinct_ports < 1):
            raise ValueError("thresholds must be positive integers")
        if (not isinstance(self.config.maximum_sources, int)
                or not isinstance(self.config.maximum_flows_per_source, int)
                or self.config.maximum_sources < 1
                or self.config.maximum_flows_per_source < 1):
            raise ValueError("memory limits must be positive integers")
        self.window_seconds = window
        self._recent: Dict[str, Deque[Tuple[float, str, Optional[int], Optional[int], str]]] = {}
        self._active_sources = set()

    def observe(self, observation: FlowObservation, now: float) -> Optional[DetectionEvent]:
        """Consume one observation; `now` is monotonic seconds for testability."""
        if not isinstance(observation, FlowObservation):
            return None
        try:
            now = float(now)
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(now):
            return None

        source = observation.source_ip
        destination = observation.destination_ip
        if (not isinstance(source, str) or not isinstance(destination, str)
                or not source or not destination or source == destination):
            return None
        if self.config.designated_hosts and destination not in self.config.designated_hosts:
            return None

        if source not in self._recent:
            if len(self._recent) >= self.config.maximum_sources:
                oldest_key = next(iter(self._recent))
                del self._recent[oldest_key]
                self._active_sources.discard(oldest_key)
            self._recent[source] = deque()
        events = self._recent[source]
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

        destination_port = observation.destination_port
        if type(destination_port) is not int or not 0 <= destination_port <= 65535:
            destination_port = None
        protocol = observation.protocol
        if type(protocol) is not int or not 0 <= protocol <= 255:
            protocol = None
        flow_identity = observation.flow_id or "{}:{}:{}".format(
            destination, destination_port, protocol)
        if not any(item[4] == flow_identity for item in events):
            events.append((now, destination, destination_port, protocol, flow_identity))
        while len(events) > self.config.maximum_flows_per_source:
            events.popleft()

        hosts = tuple(sorted({item[1] for item in events}))
        ports = tuple(sorted({item[2] for item in events if item[2] is not None}))
        host_trigger = len(hosts) >= self.config.minimum_distinct_hosts
        port_trigger = len(ports) >= self.config.minimum_distinct_ports
        triggered = host_trigger or port_trigger
        if not triggered:
            self._active_sources.discard(source)
            return None
        if source in self._active_sources:
            return None

        reasons = []
        if host_trigger:
            reasons.append("multiple designated hosts contacted")
        if port_trigger:
            reasons.append("multiple destination ports contacted")
        self._active_sources.add(source)
        return DetectionEvent(
            source_ip=source,
            decision="suspicious",
            reason=" and ".join(reasons),
            distinct_hosts=len(hosts),
            distinct_ports=len(ports),
            destination_hosts=hosts,
            destination_ports=ports,
            window_seconds=self.window_seconds,
            observed_at=observation.observed_at,
        )
