import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Bash 安装器只在 Linux/Unix 测试")
class InstallerTests(unittest.TestCase):
    def test_failed_candidate_restores_command_and_previous_program(self):
        with tempfile.TemporaryDirectory() as temp:
            root, broken = Path(temp) / "root", Path(temp) / "broken"
            source = Path(__file__).resolve().parents[1]
            good = [
                "bash",
                str(source / "install.sh"),
                "--staging",
                str(root),
                "--role",
                "controller",
                "--node-id",
                "test",
            ]
            run = subprocess.run(good, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            before = (root / "opt/relayaxis/current").readlink()
            shutil.copytree(
                source,
                broken,
                ignore=shutil.ignore_patterns(
                    ".git", ".venv", "__pycache__", ".ruff_cache", "dist", "build"
                ),
            )
            (broken / "relayaxis/__init__.py").write_text(
                'raise RuntimeError("injected broken upgrade")\n'
            )
            bad = [
                "bash",
                str(broken / "install.sh"),
                *good[2:],
                "--realm-binary",
                "/usr/local/bin/realm",
            ]
            run = subprocess.run(bad, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual((root / "opt/relayaxis/current").readlink(), before)
            run = subprocess.run(
                [str(root / "usr/local/bin/ra"), "version", "--json"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual(json.loads(run.stdout)["version"], "0.1.0")

    def test_idempotent_staging_upgrade_and_uninstall_preserve_external(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            source = Path(__file__).resolve().parents[1]
            args = [
                "bash",
                str(source / "install.sh"),
                "--staging",
                str(root),
                "--role",
                "controller",
                "--node-id",
                "test",
            ]
            for _ in range(2):
                run = subprocess.run(args, capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            command = root / "usr/local/bin/ra"
            run = subprocess.run(
                [str(command), "version", "--json"], capture_output=True, text=True, timeout=5
            )
            self.assertEqual(json.loads(run.stdout)["version"], "0.1.0")
            external = root / "etc/systemd/system/realm-manual.service"
            external.parent.mkdir(parents=True, exist_ok=True)
            external.write_text("external realm")
            pbr = external.with_name("ipv4-eth1-pbr.service")
            pbr.write_text("external pbr")
            ipv6 = external.with_name("ipv6_manager.service")
            ipv6.write_text("official ipv6")
            run = subprocess.run(
                ["bash", str(source / "uninstall.sh"), "--staging", str(root)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertTrue((root / "etc/relayaxis/settings.json").exists())
            self.assertTrue((root / "var/lib/relayaxis/state.sqlite3").exists())
            self.assertFalse(command.exists())
            self.assertEqual(external.read_text(), "external realm")
            self.assertEqual(pbr.read_text(), "external pbr")
            self.assertEqual(ipv6.read_text(), "official ipv6")
            run = subprocess.run(args, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            run = subprocess.run(
                [
                    "bash",
                    str(source / "uninstall.sh"),
                    "--staging",
                    str(root),
                    "--purge",
                    "--confirm-purge",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertFalse((root / "etc/relayaxis").exists())
            self.assertTrue(external.exists())
            self.assertTrue(pbr.exists())
            self.assertTrue(ipv6.exists())

    def test_installer_refuses_foreign_global_command(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            command = root / "usr/local/bin/ra"
            command.parent.mkdir(parents=True)
            command.write_text("foreign program")
            source = Path(__file__).resolve().parents[1]
            run = subprocess.run(
                [
                    "bash",
                    str(source / "install.sh"),
                    "--staging",
                    str(root),
                    "--role",
                    "controller",
                    "--node-id",
                    "test",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(command.read_text(), "foreign program")
