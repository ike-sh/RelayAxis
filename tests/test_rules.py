import tempfile
import unittest
from pathlib import Path

from relayaxis.errors import ConflictError, ValidationError
from relayaxis.models import Binding, Rule

from .helpers import Lab


class RulesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name))

    def test_crud_search_history_and_rollback(self):
        manager = self.lab.rules
        first = self.lab.rule()
        second = manager.update(first["rule_id"], {"name": "日本", "remote_port": 5203})
        self.assertEqual(second["revision"], 2)
        self.assertEqual(manager.list("日本")[0]["rule_id"], first["rule_id"])
        manager.enable(first["rule_id"], False)
        rolled = manager.rollback(first["rule_id"], 1)
        self.assertEqual(rolled["revision"], 4)
        self.assertEqual(rolled["remote_port"], 443)
        self.assertTrue(rolled["enabled"])
        deleted = manager.delete(first["rule_id"])
        self.assertTrue(deleted["deleted"])
        self.assertEqual(manager.list(), [])
        self.assertEqual(len(manager.list(include_deleted=True)), 1)
        self.assertEqual(len(manager.store.history("rule", first["rule_id"])), 5)

    def test_optimistic_revision_prevents_lost_updates(self):
        rule = self.lab.rule()
        self.lab.rules.update(rule["rule_id"], {"remark": "new"})
        with self.assertRaises(ConflictError):
            self.lab.rules.update(rule["rule_id"], {"remark": "stale"}, expected=1)

    def test_conflict_does_not_commit(self):
        self.lab.rule()
        with self.assertRaises(ConflictError):
            self.lab.rule()
        self.assertEqual(len(self.lab.rules.list()), 1)

    def test_tcp_and_udp_can_share_port_in_independent_units(self):
        self.lab.rule(protocol="tcp")
        self.lab.rule(protocol="udp")
        self.assertEqual(len(self.lab.rules.list()), 2)

    def test_auto_internal_allocation_preserves_public_port(self):
        self.lab.add_server("a", 1)
        a = self.lab.rule(12345, ["a"])
        b = self.lab.rule(12346, ["a"])
        self.assertEqual(a["bindings"][1]["listen_port"], 12345)
        self.assertNotEqual(
            a["bindings"][1]["wg_internal_port"], b["bindings"][1]["wg_internal_port"]
        )
        changed = self.lab.rules.update(a["rule_id"], {"remote_port": 80})
        self.assertEqual(a["bindings"], changed["bindings"])

    def test_copy_requires_nonconflicting_new_bindings(self):
        a = self.lab.rule()
        b = self.lab.rules.copy(
            a["rule_id"], "copy", [{"listen_address": "::", "listen_port": 23456}]
        )
        self.assertNotEqual(a["rule_id"], b["rule_id"])
        self.assertEqual(b["revision"], 1)

    def test_failed_reference_validation_is_atomic(self):
        data = Rule("bad", "192.0.2.80", 80, "absent", [Binding("::", 1000)]).to_dict()
        with self.assertRaises(ValidationError):
            self.lab.rules.create(data)
        self.assertEqual(self.lab.rules.list(), [])
