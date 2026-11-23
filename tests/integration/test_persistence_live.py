"""Real Netplan generation and isolated systemd-networkd restart regression."""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from relayaxis.config import Paths
from relayaxis.core.persistence import NetplanBackend, NetworkdBackend
from relayaxis.models import Egress

try:
    import pwd
except ImportError:  # pragma: no cover - exercised by cross-platform collection
    pwd = None


class NetplanGenerateIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("RELAYAXIS_NETPLAN") != "1":
            raise unittest.SkipTest("设置 RELAYAXIS_NETPLAN=1 启用真实 Netplan generate")
        if not shutil.which("netplan"):
            raise RuntimeError("CI 已要求 Netplan 测试，但系统缺少 netplan")

    def test_real_generate_merges_fragment_without_losing_base_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "etc/netplan"
            directory.mkdir(parents=True)
            base = directory / "50-cloud-init.yaml"
            base.write_text(
                """network:
  version: 2
  renderer: networkd
  ethernets:
    uplink:
      match:
        macaddress: 02:00:00:00:00:02
      set-name: eth1
      addresses: [10.8.0.212/24, 2001:db8:8::212/64]
      nameservers:
        addresses: [192.0.2.53, 2001:db8::53]
      routes:
        - to: 2001:db8:ffff::/48
          via: 2001:db8:8::1
""",
                encoding="utf-8",
            )
            egress = Egress(
                "live",
                "测试线路",
                "eth1",
                "10.8.0.212",
                "10.8.0.1",
                "108",
                18080,
                managed=True,
                backend="netplan",
            ).validate()
            fragment = directory / "90-relayaxis-egress-live.yaml"
            fragment.write_text(
                NetplanBackend(Paths(root), runner=None).candidate(egress), encoding="utf-8"
            )
            base.chmod(0o600)
            fragment.chmod(0o600)
            command = ["netplan", "generate", "--root-dir", str(root)]
            subprocess.run(command, check=True, text=True, capture_output=True, timeout=30)
            generated = sorted((root / "run/systemd/network").glob("*.network"))
            self.assertTrue(generated)
            text = "\n".join(path.read_text(encoding="utf-8") for path in generated)
            for value in (
                "02:00:00:00:00:02",
                "10.8.0.212/24",
                "2001:db8:8::212/64",
                "192.0.2.53",
                "2001:db8::53",
                "2001:db8:ffff::/48",
                "Table=108",
                "From=10.8.0.212/32",
                "Priority=18080",
            ):
                self.assertIn(value, text)
            before = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in generated
            }
            subprocess.run(command, check=True, text=True, capture_output=True, timeout=30)
            after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in generated}
            self.assertEqual(after, before)


class NetworkdRestartIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("RELAYAXIS_NETWORKD_NETNS") != "1":
            raise unittest.SkipTest("设置 RELAYAXIS_NETWORKD_NETNS=1 启用隔离 networkd 重启测试")
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise RuntimeError("CI 已要求 networkd netns 测试，但当前不是 root")
        required = ("ip", "unshare", "mount")
        missing = [tool for tool in required if not shutil.which(tool)]
        cls.networkd = shutil.which("systemd-networkd") or "/usr/lib/systemd/systemd-networkd"
        if missing or not Path(cls.networkd).is_file():
            raise RuntimeError(f"networkd netns 测试依赖缺失: {missing}")
        if pwd is None:
            raise RuntimeError("CI 已要求 networkd netns 测试，但平台缺少 POSIX pwd")
        try:
            cls.network_user = pwd.getpwnam("systemd-network")
        except KeyError as exc:
            raise RuntimeError("系统缺少 systemd-network 运行账户") from exc

    def command(self, argv, check=True):
        result = subprocess.run(argv, text=True, capture_output=True, timeout=15)
        if check and result.returncode:
            self.fail(f"command failed: {argv[:5]}: {result.stderr}")
        return result

    def setUp(self):
        suffix = uuid.uuid4().hex[:6]
        self.namespace = f"rand{suffix}"
        self.host = f"rah{suffix}"
        self.peer = f"rap{suffix}"
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.processes = []
        self.logs = []
        self.addCleanup(self.cleanup_network)
        self.command(["ip", "netns", "add", self.namespace])
        self.command(["ip", "link", "add", self.host, "type", "veth", "peer", "name", self.peer])
        self.command(["ip", "link", "set", self.peer, "netns", self.namespace])
        self.command(["ip", "addr", "add", "10.8.0.1/24", "dev", self.host])
        self.command(["ip", "link", "set", self.host, "up"])
        self.command(["ip", "-n", self.namespace, "link", "set", "lo", "up"])
        self.command(["ip", "-n", self.namespace, "link", "set", self.peer, "name", "eth1"])
        self.command(["ip", "-n", self.namespace, "link", "set", "eth1", "up"])

        root = Path(self.temp.name)
        self.config = root / "network"
        self.etc_config = root / "etc-network"
        self.netif = root / "netif"
        self.empty_usr = root / "empty-usr"
        self.empty_dbus = root / "empty-dbus"
        self.empty_resolve = root / "empty-resolve"
        for directory in (
            self.config,
            self.etc_config / "10-relayaxis-lab.network.d",
            self.netif,
            self.empty_usr,
            self.empty_dbus,
            self.empty_resolve,
        ):
            directory.mkdir(parents=True)
        (self.config / "10-relayaxis-lab.network").write_text(
            "[Match]\nName=eth1\n\n[Network]\nAddress=10.8.0.212/24\n",
            encoding="utf-8",
        )
        egress = Egress(
            "live",
            "隔离线路",
            "eth1",
            "10.8.0.212",
            "10.8.0.1",
            "108",
            18080,
            managed=True,
            backend="networkd",
        ).validate()
        (self.etc_config / "10-relayaxis-lab.network.d/90-relayaxis-egress-live.conf").write_text(
            NetworkdBackend.render(egress), encoding="utf-8"
        )
        for directory in (
            root,
            self.config,
            self.etc_config,
            self.etc_config / "10-relayaxis-lab.network.d",
        ):
            directory.chmod(0o755)
        for path in (*self.config.rglob("*"), *self.etc_config.rglob("*")):
            if path.is_file():
                path.chmod(0o644)
        os.chown(self.netif, self.network_user.pw_uid, self.network_user.pw_gid)
        self.netif.chmod(0o755)

    def start_networkd(self):
        script = """
set -eu
mkdir -p /run/systemd/network /run/systemd/netif /run/dbus /run/systemd/resolve
mount --bind "$1" /run/systemd/network
mount --bind "$2" /run/systemd/netif
mount --bind "$3" /etc/systemd/network
mount --bind "$4" /usr/lib/systemd/network
mount --bind "$5" /run/dbus
mount --bind "$6" /run/systemd/resolve
exec "$7"
"""
        log = (Path(self.temp.name) / f"networkd-{len(self.logs)}.log").open("wb")
        self.logs.append(log)
        process = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                self.namespace,
                "unshare",
                "--mount",
                "--propagation",
                "private",
                "--kill-child=TERM",
                "--fork",
                "/bin/sh",
                "-c",
                script,
                "sh",
                str(self.config),
                str(self.netif),
                str(self.etc_config),
                str(self.empty_usr),
                str(self.empty_dbus),
                str(self.empty_resolve),
                self.networkd,
            ],
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        self.processes.append(process)
        return process

    def wait_ready(self, process):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            rules = self.command(["ip", "-n", self.namespace, "-4", "rule", "show"]).stdout
            routes = self.command(
                ["ip", "-n", self.namespace, "-4", "route", "show", "table", "108"],
                check=False,
            ).stdout
            if "18080:" in rules and "default via 10.8.0.1 dev eth1" in routes:
                return
            if process.poll() is not None:
                break
            time.sleep(0.1)
        for log in self.logs:
            log.flush()
        details = "\n".join(
            Path(log.name).read_text(encoding="utf-8", errors="replace") for log in self.logs
        )
        self.fail("isolated systemd-networkd did not restore PBR:\n" + details)

    def stop_networkd(self, process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)

    def test_networkd_restart_restores_rule_table_and_effective_lookup(self):
        first = self.start_networkd()
        self.wait_ready(first)
        self.stop_networkd(first)
        self.command(
            [
                "ip",
                "-n",
                self.namespace,
                "-4",
                "rule",
                "del",
                "priority",
                "18080",
                "from",
                "10.8.0.212/32",
                "table",
                "108",
            ]
        )
        self.command(["ip", "-n", self.namespace, "-4", "route", "flush", "table", "108"])
        self.assertNotIn(
            "18080:",
            self.command(["ip", "-n", self.namespace, "-4", "rule", "show"]).stdout,
        )
        second = self.start_networkd()
        self.wait_ready(second)
        lookup = json.loads(
            self.command(
                [
                    "ip",
                    "netns",
                    "exec",
                    self.namespace,
                    "ip",
                    "-j",
                    "-4",
                    "route",
                    "get",
                    "198.51.100.1",
                    "from",
                    "10.8.0.212",
                ]
            ).stdout
        )[0]
        self.assertEqual(lookup["dev"], "eth1")
        self.assertEqual(lookup["gateway"], "10.8.0.1")
        self.assertEqual(str(lookup.get("table")), "108")

    def cleanup_network(self):
        for process in self.processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        for handle in self.logs:
            handle.close()
        self.command(["ip", "netns", "del", self.namespace], check=False)
        self.command(["ip", "link", "del", self.host], check=False)
