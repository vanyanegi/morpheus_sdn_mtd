#!/usr/bin/env python3
"""Opt-in low-rate TCP probes pinned to explicitly selected Mininet hosts."""

import argparse
import math
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from morpheus.lab_config import HOSTS

ALLOWED_TARGETS = dict(HOSTS)
IP_TO_HOST = {address: hostname for hostname, address in HOSTS.items()}
TARGET_CHOICES = tuple(sorted(set(ALLOWED_TARGETS) | set(IP_TO_HOST)))
DEFAULT_PORTS = (22, 80, 9000)
MIN_DELAY_SECONDS = 0.25
MAX_TIMEOUT_SECONDS = 5.0


def validate_options(target_names, ports=DEFAULT_PORTS, delay=1.0, timeout=0.5):
    if isinstance(target_names, str):
        target_names = (target_names,)
    try:
        requested = tuple(target_names)
        ports = tuple(ports)
        delay = float(delay)
        timeout = float(timeout)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("targets, ports, delay, or timeout have an invalid type")
    if not requested or any(not isinstance(name, str) for name in requested):
        raise ValueError("select at least one designated Mininet hostname or IP")
    invalid = set(requested) - set(TARGET_CHOICES)
    if invalid:
        raise ValueError("targets must be configured Mininet hostnames or IPs: {}".format(sorted(invalid)))
    targets = tuple(IP_TO_HOST.get(value, value) for value in requested)
    if len(set(targets)) != len(targets):
        raise ValueError("duplicate target hosts are not allowed")
    if not ports:
        raise ValueError("at least one TCP port is required")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("ports must be integers between 1 and 65535")
    if not math.isfinite(delay) or delay < MIN_DELAY_SECONDS:
        raise ValueError("delay must be finite and at least {:.2f}s".format(MIN_DELAY_SECONDS))
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError("timeout must be greater than 0 and at most {:.1f}s".format(MAX_TIMEOUT_SECONDS))
    return targets, tuple(ports), delay, timeout


def configured_target_ip(target):
    """Map only a configured lab hostname to its fixed address (no DNS lookup)."""
    try:
        return ALLOWED_TARGETS[target]
    except KeyError:
        raise ValueError("target is not a configured Mininet hostname: {}".format(target))


def probe(target_names, ports=DEFAULT_PORTS, delay=1.0, timeout=0.5, logger=print):
    """Probe only configured host/IP pairs; report outcomes without hiding errors."""
    targets, ports, delay, timeout = validate_options(target_names, ports, delay, timeout)
    resolved_targets = {name: configured_target_ip(name) for name in targets}
    logger("Reconnaissance targets={} ports={} delay={}s timeout={}s".format(
        tuple((name, resolved_targets[name]) for name in targets), ports, delay, timeout))
    outcomes = []
    attempts = [(target, port) for target in targets for port in ports]
    try:
        for index, (target, port) in enumerate(attempts):
            try:
                with socket.create_connection((resolved_targets[target], port), timeout=timeout):
                    outcome = "open"
            except (OSError, socket.timeout) as exc:
                outcome = "closed_or_filtered ({})".format(type(exc).__name__)
            item = {"target": target, "ip": resolved_targets[target],
                    "port": port, "outcome": outcome}
            outcomes.append(item)
            logger("probe target={} ip={} port={} outcome={}".format(
                target, resolved_targets[target], port, outcome))
            if index + 1 < len(attempts):
                time.sleep(delay)
    except KeyboardInterrupt:
        logger("Reconnaissance stopped by operator after {} of {} attempts".format(
            len(outcomes), len(attempts)))
    return outcomes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", nargs="+", required=True,
                        choices=TARGET_CHOICES,
                        help="configured Mininet hostnames or their exact lab IPs")
    parser.add_argument("--ports", nargs="+", type=int, default=list(DEFAULT_PORTS))
    parser.add_argument("--delay", type=float, default=1.0, help="at least 0.25 seconds per attempt")
    parser.add_argument("--timeout", type=float, default=0.5)
    args = parser.parse_args()
    try:
        probe(args.targets, args.ports, args.delay, args.timeout)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
