"""Opt-in real WG + PBR + Realm test. No host firewall or host route changes."""

import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from relayaxis.core.network import Network
from relayaxis.core.realm import Endpoint, render
from relayaxis.core.system import Runner
from relayaxis.core.wg_link import WireGuardLink, load_config
from relayaxis.core.wireguard import render as render_wg
from relayaxis.errors import ValidationError
from relayaxis.models import Egress, Tunnel
from relayaxis.storage import Store


class NamespaceRunner(Runner):
    def __init__(self, namespace):
        self.namespace = namespace

    def run(self, argv, **kwargs):
        return super().run(["ip", "netns", "exec", self.namespace, *argv], **kwargs)


class NamespaceIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("RELAYAXIS_NETNS") != "1":
            raise unittest.SkipTest("特权 WG/PBR 测试未授权启用：设置 RELAYAXIS_NETNS=1")
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise unittest.SkipTest("真实 namespace/WireGuard 测试需要 root")
        for tool in ("ip", "wg", "ping", "sysctl"):
            if not shutil.which(tool):
                raise unittest.SkipTest(f"缺少网络测试依赖: {tool}")
        cls.realm = os.environ.get("RELAYAXIS_REALM") or shutil.which("realm")
        if not cls.realm:
            raise unittest.SkipTest("需要真实 Realm 可执行文件")

    def command(self, argv, check=True):
        result = subprocess.run(argv, text=True, capture_output=True, timeout=15)
        if check and result.returncode:
            self.fail(f"Command failed: {argv[:5]}: {result.stderr}")
        return result

    def nscommand(self, ns, argv, check=True):
        return self.command(["ip", "netns", "exec", self.ns[ns], *argv], check)

    def setUp(self):
        self.prefix = "ra" + uuid.uuid4().hex[:6]
        self.ns = {key: f"{self.prefix}-{key}" for key in ("c", "a", "b", "t")}
        self.created = []
        self.host_links = []
        self.processes = []
        self.logs = []
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.cleanup_network)
        for name in self.ns.values():
            result = self.command(["ip", "netns", "add", name], False)
            if result.returncode:
                if not self.created:
                    self.skipTest("内核/容器没有 namespace 能力: " + result.stderr.strip())
                self.fail(result.stderr)
            self.created.append(name)
            self.command(["ip", "-n", name, "link", "set", "lo", "up"])
            self.command(
                [
                    "ip",
                    "netns",
                    "exec",
                    name,
                    "sysctl",
                    "-q",
                    "-w",
                    "net.ipv4.conf.all.rp_filter=0",
                    "net.ipv4.conf.default.rp_filter=0",
                ]
            )
        probe = self.nscommand("c", ["ip", "link", "add", "ra-probe", "type", "wireguard"], False)
        if probe.returncode:
            self.skipTest("内核没有可用 WireGuard 支持: " + probe.stderr.strip())
        self.nscommand("c", ["ip", "link", "del", "ra-probe"])
        self.pair("c", "wan-a", "172.29.240.1/30", "a", "wan0", "172.29.240.2/30", 1)
        self.pair("c", "wan-b", "172.29.240.5/30", "b", "wan0", "172.29.240.6/30", 2)
        self.pair("c", "egress0", "172.29.241.1/30", "t", "e0", "172.29.241.2/30", 3)
        self.pair("c", "egress1", "172.29.241.5/30", "t", "e1", "172.29.241.6/30", 4)
        self.nscommand("t", ["ip", "addr", "add", "192.0.2.88/32", "dev", "lo"])
        self.nscommand(
            "c", ["ip", "route", "add", "default", "via", "172.29.241.2", "dev", "egress0"]
        )
        self.nscommand(
            "c",
            [
                "ip",
                "route",
                "add",
                "172.29.241.4/30",
                "dev",
                "egress1",
                "src",
                "172.29.241.5",
                "table",
                "108",
            ],
        )
        self.nscommand(
            "c",
            [
                "ip",
                "route",
                "add",
                "default",
                "via",
                "172.29.241.6",
                "dev",
                "egress1",
                "src",
                "172.29.241.5",
                "table",
                "108",
            ],
        )
        self.nscommand(
            "c",
            ["ip", "rule", "add", "priority", "18080", "from", "172.29.241.5/32", "table", "108"],
        )
        self.make_wg("a", "172.29.240.2", "10.203.0.1", "10.203.0.2", 53001)
        self.make_wg("b", "172.29.240.6", "10.203.0.5", "10.203.0.6", 53002)
        self.echo_script = str(Path(__file__).with_name("netns_echo.py"))
        echo = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                self.ns["t"],
                sys.executable,
                self.echo_script,
                "serve",
                "192.0.2.88",
                "45000",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.processes.append(echo)
        selector = selectors.DefaultSelector()
        selector.register(echo.stdout, selectors.EVENT_READ)
        try:
            self.assertTrue(selector.select(timeout=5), "echo server did not start")
            self.assertEqual(echo.stdout.readline().strip(), "READY")
        finally:
            selector.close()

    def pair(self, a, dev_a, address_a, b, dev_b, address_b, index):
        host_a, host_b = f"{self.prefix}{index}a", f"{self.prefix}{index}b"
        self.command(["ip", "link", "add", host_a, "type", "veth", "peer", "name", host_b])
        self.host_links.extend([host_a, host_b])
        for ns, host, device, address in (
            (a, host_a, dev_a, address_a),
            (b, host_b, dev_b, address_b),
        ):
            self.command(["ip", "link", "set", host, "netns", self.ns[ns]])
            self.nscommand(ns, ["ip", "link", "set", host, "name", device])
            self.nscommand(ns, ["ip", "addr", "add", address, "dev", device])
            self.nscommand(ns, ["ip", "link", "set", device, "up"])

    def make_wg(self, ingress, endpoint, controller_address, ingress_address, controller_port):
        private_c = self.command(["wg", "genkey"]).stdout.strip()
        private_i = self.command(["wg", "genkey"]).stdout.strip()
        public_c = subprocess.check_output(
            ["wg", "pubkey"], input=private_c + "\n", text=True
        ).strip()
        public_i = subprocess.check_output(
            ["wg", "pubkey"], input=private_i + "\n", text=True
        ).strip()
        for ns, role, local, peer, private, public, peer_public, listen, outer in (
            (
                "c",
                "controller",
                controller_address,
                ingress_address,
                private_c,
                public_c,
                public_i,
                controller_port,
                endpoint + ":53000",
            ),
            (
                ingress,
                "ingress",
                ingress_address,
                controller_address,
                private_i,
                public_i,
                public_c,
                53000,
                "",
            ),
        ):
            directory = Path(self.temp.name) / ns
            directory.mkdir(exist_ok=True)
            directory.chmod(0o700)
            device = f"ra-{ingress}"
            tunnel = Tunnel(
                ingress,
                device,
                role,
                local + "/32",
                peer + "/32",
                listen_port=listen,
                endpoint=outer,
                public_key=public,
                peer_public_key=peer_public,
            )
            path = directory / f"{device}.conf"
            path.write_text(render_wg(tunnel, private))
            path.chmod(0o600)
            parsed, secret = load_config(path.read_text(encoding="utf-8"), tunnel.__dict__)
            WireGuardLink(NamespaceRunner(self.ns[ns]), Store(directory / "state.sqlite3")).up(
                parsed, secret
            )
        deadline = time.monotonic() + 10
        while True:
            response = self.nscommand("c", ["ping", "-c", "1", "-W", "1", ingress_address], False)
            if response.returncode == 0:
                break
            if time.monotonic() >= deadline:
                self.fail("Controller 发起后 WG 未在 10 秒内完成握手")
            time.sleep(0.2)
        handshakes = self.nscommand(
            "c", ["wg", "show", f"ra-{ingress}", "latest-handshakes"]
        ).stdout.split()
        self.assertTrue(handshakes and int(handshakes[-1]) > 0)
        learned = self.nscommand(ingress, ["wg", "show", f"ra-{ingress}", "endpoints"]).stdout
        self.assertNotIn(
            "(none)", learned, "Ingress must learn NAT-side endpoint from initiated packets"
        )

    def realm_process(self, ns, endpoint):
        path = Path(self.temp.name) / (ns + "-" + endpoint.endpoint_id + ".toml")
        path.write_text(render(endpoint))
        log = path.with_suffix(".log").open("wb")
        self.logs.append(log)
        process = subprocess.Popen(
            ["ip", "netns", "exec", self.ns[ns], self.realm, "-c", str(path)],
            stdout=log,
            stderr=log,
        )
        self.processes.append(process)
        time.sleep(0.15)
        self.assertIsNone(process.poll(), path.with_suffix(".log").read_text())
        return process

    def probe(self, ns, host, number, expected_source):
        result = self.nscommand(
            ns, [sys.executable, self.echo_script, "probe", host, str(number), expected_source]
        )
        self.assertIn("TCP+UDP PASS", result.stdout)

    def test_real_wg_dual_egress_multi_rules_direct_ipv6_and_failure_isolation(self):
        network = Network(NamespaceRunner(self.ns["c"]))
        line0 = Egress("main", "main", "egress0", "172.29.241.1", "172.29.241.2")
        line1 = Egress("pbr", "pbr", "egress1", "172.29.241.5", "172.29.241.6", "108", 18080)
        network.validate_egress(line0, "192.0.2.88", 45000)
        network.validate_egress(line1, "192.0.2.88", 45000)
        fronts = {}
        for index, egress in enumerate((line0, line1), 1):
            internal, public = 20000 + index, 41000 + index
            for ns, local, peer in (
                ("a", "10.203.0.1", "10.203.0.2"),
                ("b", "10.203.0.5", "10.203.0.6"),
            ):
                self.realm_process(
                    "c",
                    Endpoint(
                        f"backend-{ns}-{index}",
                        f"r{index}",
                        local,
                        internal,
                        "192.0.2.88",
                        45000,
                        "both",
                        egress.source,
                        egress.interface,
                    ),
                )
                fronts[(ns, index)] = self.realm_process(
                    ns,
                    Endpoint(
                        f"front-{ns}-{index}",
                        f"r{index}",
                        "0.0.0.0",
                        public,
                        local,
                        internal,
                        "both",
                        peer,
                        f"ra-{ns}",
                    ),
                )
            self.realm_process(
                "c",
                Endpoint(
                    f"direct-{index}",
                    f"r{index}",
                    "::1",
                    43000 + index,
                    "192.0.2.88",
                    45000,
                    "both",
                    egress.source,
                    egress.interface,
                ),
            )
            self.probe("a", "127.0.0.1", public, egress.source)
            self.probe("b", "127.0.0.1", public, egress.source)
            self.probe("c", "::1", 43000 + index, egress.source)
        self.nscommand(
            "c",
            ["ip", "rule", "del", "priority", "18080", "from", "172.29.241.5/32", "table", "108"],
        )
        with self.assertRaises(ValidationError):
            network.validate_egress(line1, "192.0.2.88", 45000)
        self.nscommand(
            "c",
            ["ip", "rule", "add", "priority", "18080", "from", "172.29.241.5/32", "table", "108"],
        )
        fronts[("a", 1)].terminate()
        fronts[("a", 1)].wait(timeout=3)
        self.probe("b", "127.0.0.1", 41001, line0.source)
        self.probe("a", "127.0.0.1", 41002, line1.source)
        self.probe("c", "::1", 43001, line0.source)

    def cleanup_network(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
        for name in reversed(self.created):
            self.command(["ip", "netns", "del", name], False)
        for link in self.host_links:
            self.command(["ip", "link", "del", link], False)
        for handle in self.logs:
            handle.close()
