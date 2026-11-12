import shlex
import tempfile
import unittest
from pathlib import Path

from relayaxis.core.realm import import_existing, scan_existing
from relayaxis.core.system import Result
from relayaxis.errors import ConflictError

from .helpers import FakeRunner, Lab


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lab = Lab(self.root / "state")
        self.directory = self.root / "external"
        self.directory.mkdir()
        self.config = self.directory / "realm.toml"
        self.config.write_text("""[network]
no_tcp = false
use_udp = true
ipv6_only = true
[[endpoints]]
listen = "[::]:5203"
remote = "192.0.2.80:5203"
through = "192.0.2.10"
interface = "eth0"
""")
        self.unit = self.directory / "realm-old.service"
        self.unit.write_text(
            f"[Service]\nExecStart=/usr/local/bin/realm -c {shlex.quote(str(self.config))}\n"
        )
        self.runner = FakeRunner(
            {("systemctl", "is-active", "realm-old.service"): Result(stdout="active\n")}
        )

    def test_scan_and_import_leave_external_files_unchanged_and_service_running(self):
        before = {p: p.read_bytes() for p in (self.unit, self.config)}
        found = scan_existing(self.runner, [self.directory])
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["active"])
        backup = self.root / "import-backup"
        rules = import_existing(self.lab.store, self.lab.rules, found[0], "line-a", backup)
        self.assertEqual(len(rules), 1)
        self.assertFalse(rules[0]["enabled"])
        self.assertEqual(rules[0]["external_service"], "realm-old.service")
        self.assertEqual((backup / "realm.toml").read_bytes(), before[self.config])
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assertFalse(
            any("stop" in c or "restart" in c or "disable" in c for c in self.runner.calls)
        )

    def test_import_blocks_race_with_external_change(self):
        found = scan_existing(self.runner, [self.directory])[0]
        self.config.write_text(self.config.read_text() + "\n# changed\n")
        with self.assertRaises(ConflictError):
            import_existing(
                self.lab.store, self.lab.rules, found, "line-a", self.root / "import-backup"
            )
        self.assertEqual(self.lab.rules.list(), [])
