#!/usr/bin/env python3
"""Start the isolated Morpheus Mininet topology (requires root to run)."""

import argparse
import ipaddress
import logging
import sys

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

from morpheus.lab_config import CONTROLLER_IP, CONTROLLER_PORT, HOSTS

LOG = logging.getLogger("morpheus.topology")


class MorpheusIoTTopology(Topo):
    """One OpenFlow 1.3 OVS switch and the 12 configured virtual hosts."""

    def build(self):
        self.addSwitch("s1", protocols="OpenFlow13", failMode="secure")
        for name, address in HOSTS.items():
            host = self.addHost(name, ip=address + "/24")
            self.addLink(host, "s1")


def validate_controller(controller_ip, controller_port):
    """Reject malformed remote-controller endpoint settings before setup."""
    try:
        ipaddress.ip_address(controller_ip)
    except (TypeError, ValueError):
        raise ValueError("controller-ip must be a literal IPv4 or IPv6 address")
    if type(controller_port) is not int or not 1 <= controller_port <= 65535:
        raise ValueError("controller-port must be between 1 and 65535")


def run(controller_ip=CONTROLLER_IP, controller_port=CONTROLLER_PORT):
    validate_controller(controller_ip, controller_port)
    topology = MorpheusIoTTopology()
    net = Mininet(topo=topology, controller=None, switch=OVSSwitch,
                  autoSetMacs=True, build=False)
    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)
    try:
        net.build()
        net.start()
        info("*** Morpheus lab running; traffic is not started automatically.\n")
        info("*** Hosts are isolated Mininet namespaces; attacker is virtual.\n")
        CLI(net)
    finally:
        original_error_active = sys.exc_info()[0] is not None
        try:
            net.stop()
        except Exception:
            # Keep the original startup/CLI exception intact while reporting
            # an incomplete cleanup. On normal shutdown, surface stop failures.
            if not original_error_active:
                raise
            LOG.exception("Topology cleanup failed while handling another error")
        info("*** Morpheus virtual lab stopped.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-ip", default=CONTROLLER_IP)
    parser.add_argument("--controller-port", type=int, default=CONTROLLER_PORT)
    args = parser.parse_args()
    try:
        validate_controller(args.controller_ip, args.controller_port)
    except ValueError as exc:
        parser.error(str(exc))
    setLogLevel("info")
    run(args.controller_ip, args.controller_port)
