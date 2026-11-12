import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from relayaxis.core.recovery import Backups
from relayaxis.errors import ValidationError

from .helpers import FakeRunner, Lab


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name))
        self.backups = Backups(self.lab.paths, self.lab.store, FakeRunner())

    def test_snapshot_restore_creates_new_revision_and_preserves_runtime(self):
        rule = self.lab.rule()
        backup = self.backups.create()
        self.lab.rules.update(rule["rule_id"], {"name": "changed"})
        self.lab.store.set_runtime("sync:a", {"desired_revision": 50, "applied_revision": 49})
        self.backups.restore(backup["backup"])
        restored = self.lab.rules.get(rule["rule_id"])
        self.assertEqual(restored["name"], "test")
        self.assertEqual(restored["revision"], 3)
        self.assertEqual(self.lab.store.runtime("sync:a")["desired_revision"], 50)

    def test_restore_marks_newer_rules_for_ordered_deletion(self):
        backup = self.backups.create()
        newer = self.lab.rule()
        self.backups.restore(backup["backup"])
        self.assertTrue(self.lab.rules.get(newer["rule_id"])["deleted"])
        self.assertEqual(
            self.lab.store.runtime("rule:" + newer["rule_id"])["state"], "PENDING_SYNC"
        )

    def test_deleted_history_does_not_require_resources_already_removed(self):
        rule = self.lab.rule()
        self.lab.rules.delete(rule["rule_id"])
        self.lab.store.remove("egress", "line-a")
        backup = self.backups.create()
        result = self.backups.restore(backup["backup"])
        self.assertTrue(result["restored_desired_state"])
        self.assertTrue(self.lab.rules.get(rule["rule_id"])["deleted"])

    def test_archive_path_traversal_links_and_duplicate_members_rejected(self):
        for variant in ("../outside", "/root/outside", "symlink", "duplicate"):
            path = Path(self.temp.name) / "bad.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                info = tarfile.TarInfo(
                    "config/key" if variant in ("symlink", "duplicate") else variant
                )
                if variant == "symlink":
                    info.type, info.linkname = tarfile.SYMTYPE, "/etc/shadow"
                    archive.addfile(info)
                else:
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"a"))
                    if variant == "duplicate":
                        archive.addfile(info, io.BytesIO(b"a"))
            with self.subTest(variant=variant), self.assertRaises(ValidationError):
                self.backups.inspect(path)

    def test_rules_export_import_disabled(self):
        rule = self.lab.rule()
        self.lab.rules.update(rule["rule_id"], {"name": "日本节点 / 香港节点"})
        destination = Path(self.temp.name) / "rules.json"
        self.backups.export_rules(destination)
        self.backups.import_rules(destination, self.lab.rules)
        self.assertFalse(self.lab.rules.list()[0]["enabled"])
        self.assertEqual(self.lab.rules.list()[0]["name"], "日本节点 / 香港节点")

    def test_rule_export_checksum_failure_does_not_change_database(self):
        rule = self.lab.rule()
        destination = Path(self.temp.name) / "rules.json"
        self.backups.export_rules(destination)
        payload = json.loads(destination.read_text())
        payload["payload"]["rules"][0]["name"] = "tampered"
        destination.write_text(json.dumps(payload))
        with self.assertRaises(ValidationError):
            self.backups.import_rules(destination, self.lab.rules)
        self.assertEqual(self.lab.rules.get(rule["rule_id"])["revision"], 1)
