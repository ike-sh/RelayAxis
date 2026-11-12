"""Actual upstream Realm processes and real TCP/UDP payloads, without root."""

import json
import os
import secrets
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from relayaxis.core.realm import Endpoint, render


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(8192):
            self.request.sendall(data)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def unused_port():
    for _ in range(20):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            # Stay outside the ordinary client ephemeral range to avoid racing
            # Realm's outgoing UDP associations between reserving and starting.
            try:
                tcp.bind(("127.0.0.1", 20000 + secrets.randbelow(10000)))
                value = tcp.getsockname()[1]
                udp.bind(("127.0.0.1", value))
                return value
            except OSError:
                continue
    raise RuntimeError("cannot find a TCP/UDP port")


class RealmLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get("RELAYAXIS_REALM") or shutil.which("realm")
        if not cls.binary or not Path(cls.binary).is_file():
            raise unittest.SkipTest("需要真实 Realm：设置 RELAYAXIS_REALM=/absolute/path/realm")
        if os.name != "posix":
            raise unittest.SkipTest("真实 Realm 监听测试需要 Linux/Unix")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.processes = []
        self.logs = []
        self.addCleanup(self.stop_all)
        for _ in range(20):
            self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", unused_port()), TCPHandler)
            self.tcp.daemon_threads = True
            try:
                self.udp = socketserver.ThreadingUDPServer(self.tcp.server_address, UDPHandler)
                break
            except OSError:
                self.tcp.server_close()
        else:
            raise RuntimeError("cannot reserve a common TCP/UDP echo port")
        self.target_port = self.tcp.server_address[1]
        for server in (self.tcp, self.udp):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(self.close_echo)
        self.loopback_device = "lo"
        if shutil.which("ip"):
            routes = json.loads(
                subprocess.check_output(
                    ["ip", "-j", "-4", "route", "get", "127.0.0.1", "from", "127.0.0.1"], text=True
                )
            )
            self.loopback_device = routes[0]["dev"]

    def close_echo(self):
        for server in (self.tcp, self.udp):
            server.shutdown()
            server.server_close()

    def stop_all(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for handle in self.logs:
            handle.close()

    def launch(self, identity, address, number, remote_port, protocol="both"):
        endpoint = Endpoint(
            identity,
            "r",
            address,
            number,
            "127.0.0.1",
            remote_port,
            protocol,
            "127.0.0.1",
            self.loopback_device,
        )
        path = Path(self.temp.name) / f"{identity}.toml"
        path.write_text(render(endpoint))
        log = (Path(self.temp.name) / f"{identity}.log").open("wb")
        self.logs.append(log)
        process = subprocess.Popen([self.binary, "-c", str(path)], stdout=log, stderr=log)
        self.processes.append(process)
        deadline = time.monotonic() + 5
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        if protocol != "udp":
            while time.monotonic() < deadline:
                with socket.socket(family) as sock:
                    sock.settimeout(0.2)
                    try:
                        sock.connect((address, number))
                        return process
                    except OSError:
                        if process.poll() is not None:
                            self.fail((Path(self.temp.name) / f"{identity}.log").read_text())
                        time.sleep(0.05)
            self.fail("Realm TCP listener did not become ready")
        time.sleep(0.2)
        self.assertIsNone(process.poll())
        return process

    def tcp_echo(self, address, number):
        payload = b"relayaxis actual two-hop TCP\x00" * 80
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family) as sock:
            sock.settimeout(3)
            sock.connect((address, number))
            sock.sendall(payload)
            received = b""
            while len(received) < len(payload):
                part = sock.recv(len(payload) - len(received))
                if not part:
                    break
                received += part
        self.assertEqual(received, payload)

    def udp_echo(self, address, number):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        for size in (1, 512, 1200):
            payload = os.urandom(size)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(payload, (address, number))
                data, _ = sock.recvfrom(65535)
                self.assertEqual(data, payload)

    def test_two_ingresses_double_realm_tcp_udp_and_isolated_restart(self):
        internal, public_a, public_b = unused_port(), unused_port(), unused_port()
        controller = self.launch("controller", "127.0.0.1", internal, self.target_port)
        a = self.launch("ingress-a", "127.0.0.1", public_a, internal)
        b = self.launch("ingress-b", "127.0.0.1", public_b, internal)
        for number in (public_a, public_b):
            self.tcp_echo("127.0.0.1", number)
            self.udp_echo("127.0.0.1", number)
        a.terminate()
        a.wait(timeout=3)
        self.tcp_echo("127.0.0.1", public_b)
        self.udp_echo("127.0.0.1", public_b)
        self.assertIsNone(controller.poll())
        self.assertIsNone(b.poll())
        a = self.launch("ingress-a-restarted", "127.0.0.1", public_a, internal)
        self.tcp_echo("127.0.0.1", public_a)
        self.udp_echo("127.0.0.1", public_a)
        self.assertIsNone(a.poll())

    def test_direct_ipv6_to_ipv4_tcp_udp(self):
        with socket.socket(socket.AF_INET6) as probe:
            try:
                probe.bind(("::1", 0))
                number = probe.getsockname()[1]
            except OSError:
                self.skipTest("当前内核没有 IPv6 loopback")
        self.launch("direct-v6", "::1", number, self.target_port)
        self.tcp_echo("::1", number)
        self.udp_echo("::1", number)

    def test_tcp_only_and_udp_only_can_share_numeric_port(self):
        internal, public = unused_port(), unused_port()
        self.launch("internal-both", "127.0.0.1", internal, self.target_port)
        self.launch("front-tcp", "127.0.0.1", public, internal, "tcp")
        self.launch("front-udp", "127.0.0.1", public, internal, "udp")
        self.tcp_echo("127.0.0.1", public)
        self.udp_echo("127.0.0.1", public)
