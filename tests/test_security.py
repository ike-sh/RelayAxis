import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from relayaxis.core.sync import SSHTransport, authorized_key, envelope
from relayaxis.core.system import Result, atomic_write, file_lock
from relayaxis.errors import ApplyError, SystemError

from .helpers import FakeRunner, Lab


class SecurityTests(unittest.TestCase):
    def test_parent_symlink_cannot_redirect_config_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            foreign = root / "foreign"
            foreign.mkdir()
            (foreign / "config").write_text("preserve")
            link = root / "keys"
            try:
                link.symlink_to(foreign, target_is_directory=True)
            except OSError:
                self.skipTest("当前平台不允许创建测试符号链接")
            with self.assertRaises(SystemError):
                atomic_write(link / "config", "candidate")
            self.assertEqual((foreign / "config").read_text(), "preserve")

    def test_forced_key_disables_shell_pty_and_forwarding_and_limits_source(self):
        raw = b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + b"a" * 32
        line = authorized_key("ssh-ed25519 " + base64.b64encode(raw).decode(), "10.203.0.1")
        self.assertIn('restrict,from="10.203.0.1/32"', line)
        self.assertIn('command="/usr/local/bin/ra agent receive"', line)

    @unittest.skipUnless(os.name == "posix", "POSIX SSH file permissions")
    def test_ssh_uses_wg_target_strict_host_keys_and_fixed_command(self):
        with tempfile.TemporaryDirectory() as temp:
            lab = Lab(Path(temp))
            lab.add_server("a", 1)
            server = lab.store.get("server", "a")
            private = Path(temp) / "identity"
            private.write_text("test-only non-key material")
            private.chmod(0o600)
            hosts = Path(temp) / "known_hosts"
            hosts.write_text("test-only")
            server.update(identity_file=str(private), known_hosts_file=str(hosts))
            snapshot = envelope("a", 1, [])

            class Capture(FakeRunner):
                def run(self, argv, **kwargs):
                    self.calls.append(list(argv))
                    return Result(
                        stdout=json.dumps(
                            {
                                "server_id": "a",
                                "revision": 1,
                                "sha256": snapshot["sha256"],
                                "state": "ACTIVE",
                            }
                        )
                    )

            runner = Capture()
            transport = SSHTransport(lab.store, runner, retries=0)
            transport.send(server, snapshot)
            argv = runner.calls[0]
            self.assertEqual(argv[-2:], ["root@10.203.1.2", "ra-agent-v1"])
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
            self.assertIn("ClearAllForwardings=yes", argv)
            private.chmod(0o644)
            with self.assertRaises(ApplyError):
                transport.send(server, snapshot)

    def test_lock_file_inode_survives_multiple_uses(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.lock"
            with file_lock(path):
                inode = path.stat().st_ino
            self.assertTrue(path.exists())
            with file_lock(path):
                self.assertEqual(path.stat().st_ino, inode)
