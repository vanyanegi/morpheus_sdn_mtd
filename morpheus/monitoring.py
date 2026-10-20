"""Normalized OpenFlow flow observations and safe statistics conversion."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class FlowObservation:
    """A normalized view of one flow-statistics entry at one observation time."""

    source_ip: Optional[str]
    destination_ip: Optional[str]
    protocol: Optional[int]
    source_port: Optional[int]
    destination_port: Optional[int]
    packet_count: int
    byte_count: int
    duration_seconds: float
    observed_at: str
    datapath_id: Optional[int] = None
    flow_id: Optional[str] = None
    table_id: Optional[int] = None
    priority: Optional[int] = None
    cookie: Optional[int] = None

    @classmethod
    def from_dict(cls, record: Dict[str, Any]) -> "FlowObservation":
        """Build from a dictionary, tolerating absent or invalid telemetry."""
        if not isinstance(record, dict):
            record = {}

        return cls(
            source_ip=_text(record.get("source_ip")),
            destination_ip=_text(record.get("destination_ip")),
            protocol=_integer(record.get("protocol")),
            source_port=_integer(record.get("source_port")),
            destination_port=_integer(record.get("destination_port")),
            packet_count=int(_nonnegative(record.get("packet_count"))),
            byte_count=int(_nonnegative(record.get("byte_count"))),
            duration_seconds=_nonnegative(record.get("duration_seconds")),
            observed_at=str(record.get("observed_at") or utc_now()),
            datapath_id=_integer(record.get("datapath_id")),
            flow_id=_text(record.get("flow_id")),
            table_id=_integer(record.get("table_id")),
            priority=_integer(record.get("priority")),
            cookie=_integer(record.get("cookie")),
        )


def _integer(value: Any) -> Optional[int]:
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _nonnegative(value: Any) -> float:
    try:
        parsed = float(value)
        if parsed != parsed or parsed == float("inf"):
            return 0.0
        return max(0.0, parsed)
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _text(value: Any) -> Optional[str]:
    return str(value) if value not in (None, "") else None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def observation_from_openflow(stat: Any, timestamp: Optional[str] = None,
                              datapath_id: Optional[int] = None) -> FlowObservation:
    """Convert an OFPFlowStats-like object into the common representation.

    The stable flow identifier includes switch/table/priority/cookie and a hash
    of match fields, since cookies alone are not unique in this controller.
    """
    match = getattr(stat, "match", {}) or {}
    match = dict(match)
    duration = _nonnegative(getattr(stat, "duration_sec", 0))
    duration += _nonnegative(getattr(stat, "duration_nsec", 0)) / 1_000_000_000
    table_id = _integer(getattr(stat, "table_id", None))
    priority = _integer(getattr(stat, "priority", None))
    cookie = _integer(getattr(stat, "cookie", None))
    normalized_dpid = _integer(datapath_id)
    match_text = json.dumps(sorted((str(key), str(value)) for key, value in match.items()))
    match_hash = hashlib.sha256(match_text.encode("utf-8")).hexdigest()[:16]
    flow_id = "{}:{}:{}:{}:{}".format(
        normalized_dpid if normalized_dpid is not None else "unknown",
        table_id if table_id is not None else "unknown",
        priority if priority is not None else "unknown",
        cookie if cookie is not None else "unknown",
        match_hash,
    )
    record = {
        "source_ip": match.get("ipv4_src") or match.get("ipv6_src"),
        "destination_ip": match.get("ipv4_dst") or match.get("ipv6_dst"),
        "protocol": match.get("ip_proto"),
        "source_port": match.get("tcp_src", match.get("udp_src", match.get("sctp_src"))),
        "destination_port": match.get("tcp_dst", match.get("udp_dst", match.get("sctp_dst"))),
        "packet_count": getattr(stat, "packet_count", 0),
        "byte_count": getattr(stat, "byte_count", 0),
        "duration_seconds": duration,
        "observed_at": timestamp or utc_now(),
        "datapath_id": normalized_dpid,
        "flow_id": flow_id,
        "table_id": table_id,
        "priority": priority,
        "cookie": cookie,
    }
    return FlowObservation.from_dict(record)


def observation_to_dict(observation: FlowObservation) -> Dict[str, Any]:
    """Return a JSON-friendly mapping with stable field names."""
    return {name: getattr(observation, name) for name in observation.__dataclass_fields__}
