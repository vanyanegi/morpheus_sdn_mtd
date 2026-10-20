#!/usr/bin/env python3
"""TCP request-response server and UDP receiver for the Mininet server host."""

import argparse
import selectors
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from morpheus.lab_config import HOSTS, SERVER_TCP_PORT, SERVER_UDP_PORT


class LabTrafficServer:
    """Serve the two lab protocols using sockets closed on every exit path."""

    def __init__(self, bind, tcp_port, udp_port):
        self.bind = bind
        self.tcp_port = tcp_port
        self.udp_port = udp_port

    def serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket, \
                selectors.DefaultSelector() as selector:
            tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp_socket.bind((self.bind, self.tcp_port))
            tcp_socket.listen(16)
            udp_socket.bind((self.bind, self.udp_port))
            selector.register(tcp_socket, selectors.EVENT_READ, "tcp")
            selector.register(udp_socket, selectors.EVENT_READ, "udp")
            print("Morpheus server listening TCP {} and UDP {} on {}".format(
                self.tcp_port, self.udp_port, self.bind), flush=True)
            while True:
                for key, _ in selector.select():
                    if key.data == "tcp":
                        self._handle_tcp(key.fileobj)
                    else:
                        self._handle_udp(key.fileobj)

    @staticmethod
    def _handle_tcp(listener):
        connection, address = listener.accept()
        with connection:
            connection.settimeout(2.0)
            try:
                data = connection.recv(1024)
                if data:
                    connection.sendall(b"ACK " + data[:256])
                    print("TCP request from {}:{} ({} bytes)".format(
                        address[0], address[1], len(data)), flush=True)
            except OSError as exc:
                print("TCP client {}:{} error: {}".format(address[0], address[1], exc), flush=True)

    @staticmethod
    def _handle_udp(listener):
        data, address = listener.recvfrom(2048)
        print("UDP update from {}:{} ({} bytes)".format(
            address[0], address[1], len(data)), flush=True)


def validate_options(bind, tcp_port, udp_port):
    if bind != HOSTS["server"]:
        raise ValueError("server bind must match configured Mininet server {}".format(HOSTS["server"]))
    for name, port in (("TCP", tcp_port), ("UDP", udp_port)):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("{} port must be between 1 and 65535".format(name))
    if tcp_port == udp_port:
        raise ValueError("TCP and UDP ports must be different")


def serve(bind=HOSTS["server"], tcp_port=SERVER_TCP_PORT, udp_port=SERVER_UDP_PORT):
    validate_options(bind, tcp_port, udp_port)
    LabTrafficServer(bind, tcp_port, udp_port).serve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default=HOSTS["server"])
    parser.add_argument("--tcp-port", type=int, default=SERVER_TCP_PORT)
    parser.add_argument("--udp-port", type=int, default=SERVER_UDP_PORT)
    args = parser.parse_args()
    try:
        validate_options(args.bind, args.tcp_port, args.udp_port)
        serve(args.bind, args.tcp_port, args.udp_port)
    except KeyboardInterrupt:
        print("Morpheus server stopped by operator", flush=True)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
