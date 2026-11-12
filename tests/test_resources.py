import json
import tempfile
import unittest
from pathlib import Path

from relayaxis.core.resources import ResourceFiles
from relayaxis.core.system import atomic_write
from relayaxis.errors import ApplyError

from .helpers import Lab


class ResourceTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name))
        self.resources = ResourceFiles(self.lab.paths, self.lab.store, self.lab.services)
        self.config = self.lab.paths.config / "wireguard/ra-a.conf"
        self.unit = "relayaxis-wg-a.service"
        self.unit_path = self.lab.paths.units / self.unit
        atomic_write(self.config, "old config")
        atomic_write(self.unit_path, "old unit")
        self.lab.services.action("start", self.unit)
        self.lab.services.action("enable", self.unit)

    def test_failed_resource_transaction_restores_old_enabled_service(self):
        with self.assertRaises(ApplyError):
            with self.resources.transaction(self.unit, [self.config, self.unit_path]):
                self.lab.services.action("stop", self.unit)
                atomic_write(self.config, "candidate")
                raise RuntimeError("crash simulation")
        self.assertEqual(self.config.read_text(), "old config")
        self.assertEqual(self.lab.services.state(self.unit), {"active": True, "enabled": True})

    def test_crash_resource_journal_restores_previous_config_on_restart(self):
        with self.resources.transaction(self.unit, [self.config, self.unit_path]) as identity:
            atomic_write(self.config, "new config")
            self.resources.commit(identity)
        backup = self.lab.paths.backups / f"resource-{identity}.json"
        journal = json.loads(backup.read_text())
        self.lab.store.set_runtime("resource-commit:" + identity, False)
        atomic_write(self.lab.paths.state / "resource-journals/crash.json", json.dumps(journal))
        self.resources.recover()
        self.assertEqual(self.config.read_text(), "old config")
        self.assertTrue(self.lab.services.state(self.unit)["active"])
