import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from relayaxis.core.migration import Migration
from relayaxis.core.realm import import_existing, scan_existing
from relayaxis.core.recovery import Backups
from relayaxis.errors import ApplyError

from .helpers import FakeRunner, Lab, LabTransport, coordinator


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.lab = Lab(root / "managed")
        self.runner = FakeRunner()
        external = root / "external"
        external.mkdir()
        config = external / "r.toml"
        config.write_text(
            '[network]\nuse_udp=true\nipv6_only=true\n[[endpoints]]\nlisten="[::]:5203"\nremote="192.0.2.80:5203"\nthrough="192.0.2.10"\ninterface="eth0"\n'
        )
        self.unit = external / "realm-manual.service"
        self.unit.write_text(f"[Service]\nExecStart=/usr/bin/realm -c {shlex.quote(str(config))}\n")
        record = scan_existing(self.runner, [external])[0]
        imported = import_existing(
            self.lab.store, self.lab.rules, record, "line-a", root / "import-backup"
        )
        self.rule_id = imported[0]["rule_id"]
        self.lab.store.set_runtime("import:" + self.unit.name, record)
        self.lab.services.states[self.unit.name] = {"active": True, "enabled": True}
        app = SimpleNamespace(
            paths=self.lab.paths,
            store=self.lab.store,
            services=self.lab.services,
            runner=self.runner,
            compiler=self.lab.compiler,
            rules=self.lab.rules,
            deployment=self.lab.deployment,
            backups=Backups(self.lab.paths, self.lab.store, self.runner),
            coordinator=coordinator(self.lab, LabTransport([])),
        )
        self.migration = Migration(app)

    def test_migration_stops_original_before_new_listener_and_keeps_original_unit_file(self):
        original = self.unit.read_bytes()
        result = self.migration.migrate(self.unit.name)
        self.assertEqual(result["state"], "ACTIVE")
        self.assertEqual(self.unit.read_bytes(), original)
        self.assertFalse(self.lab.services.state(self.unit.name)["active"])
        calls = self.lab.services.calls
        old_stop = calls.index(("stop", self.unit.name))
        new_start = next(
            i for i, (a, u) in enumerate(calls) if a == "start" and u.startswith("relayaxis-")
        )
        self.assertLess(old_stop, new_start)

    def test_failed_migration_restores_original_service_and_external_marker(self):
        self.lab.services.fail_next = True
        with self.assertRaises(ApplyError):
            self.migration.migrate(self.unit.name)
        self.assertEqual(self.lab.services.state(self.unit.name), {"active": True, "enabled": True})
        self.assertEqual(self.lab.rules.get(self.rule_id)["external_service"], self.unit.name)
        self.assertEqual(self.lab.deployment.manifest("rule-" + self.rule_id), {})
