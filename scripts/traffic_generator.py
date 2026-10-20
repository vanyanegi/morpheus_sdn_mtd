#!/usr/bin/env python3
"""Periodic UDP sensor updates plus optional TCP request-response traffic."""

import argparse
import math
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from morpheus.lab_config import (SENSOR_IPS, SERVER_TCP_PORT, SERVER_UDP_PORT,
                                 HOSTS)

SERVER_IP = HOSTS["server"]
MIN_INTERVAL_SECONDS = 0.05


def validate_options(source, server, interval, duration, tcp_every,
                     tcp_port=SERVER_TCP_PORT, udp_port=SERVER_UDP_PORT):
    """Validate destination confinement and traffic parameters before sockets."""
    if not isinstance(source, str) or not isinstance(server, str):
        raise ValueError("source and server must be lab address strings")
    try:
        interval = float(interval)
        duration = float(duration)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("interval and duration must be numbers")
    if source not in SENSOR_IPS or server != SERVER_IP:
        raise ValueError("source must be a configured sensor and server must be {}".format(SERVER_IP))
    if not math.isfinite(interval) or interval < MIN_INTERVAL_SECONDS:
        raise ValueError("interval must be finite and at least {:.2f}s".format(MIN_INTERVAL_SECONDS))
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("duration must be finite and nonnegative")
    if type(tcp_every) is not int or tcp_every < 0:
        raise ValueError("tcp-every must be a nonnegative integer")
    for name, port in (("TCP", tcp_port), ("UDP", udp_port)):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("{} port must be between 1 and 65535".format(name))


def run(source, server, interval, duration, tcp_every,
        tcp_port=SERVER_TCP_PORT, udp_port=SERVER_UDP_PORT):
    """Emit configured lab traffic; duration 0 runs until interrupted."""
    try:
        interval = float(interval)
        duration = float(duration)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("interval and duration must be numbers")
    validate_options(source, server, interval, duration, tcp_every, tcp_port, udp_port)
    deadline = time.monotonic() + duration if duration > 0 else None
    sequence = 0
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while deadline is None or time.monotonic() < deadline:
            sequence += 1
            payload = "sensor={} seq={} time={:.3f}".format(source, sequence, time.time()).encode()
            udp.sendto(payload, (server, udp_port))
            if tcp_every > 0 and sequence % tcp_every == 0:
                with socket.create_connection((server, tcp_port), timeout=2) as conn:
                    conn.sendall(payload)
                    response = conn.recv(1024)
                    print("TCP response:", response.decode(errors="replace"), flush=True)
            print("UDP update {} -> {}:{}".format(source, server, udp_port), flush=True)
            remaining = interval if deadline is None else min(interval, deadline - time.monotonic())
            if remaining > 0:
                time.sleep(remaining)
    except KeyboardInterrupt:
        print("Traffic generator stopped by operator", flush=True)
    except OSError as exc:
        print("Traffic generator network error: {}".format(exc), file=sys.stderr, flush=True)
        return False
    finally:
        udp.close()
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=HOSTS["sensor1"])
    parser.add_argument("--server", default=SERVER_IP)
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between updates (minimum 0.05)")
    parser.add_argument("--duration", type=float, default=60.0, help="seconds; 0 runs until Ctrl-C")
    parser.add_argument("--tcp-every", type=int, default=5, help="TCP request every N updates; 0 disables")
    parser.add_argument("--tcp-port", type=int, default=SERVER_TCP_PORT)
    parser.add_argument("--udp-port", type=int, default=SERVER_UDP_PORT)
    args = parser.parse_args()
    try:
        validate_options(args.source, args.server, args.interval, args.duration,
                         args.tcp_every, args.tcp_port, args.udp_port)
    except ValueError as exc:
        parser.error(str(exc))
    sys.exit(0 if run(args.source, args.server, args.interval, args.duration,
                      args.tcp_every, args.tcp_port, args.udp_port) else 1)
