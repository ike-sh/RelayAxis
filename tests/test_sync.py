import copy
import tempfile
import unittest
from pathlib import Path

from relayaxis.core.sync import diff, envelope
from relayaxis.errors import ValidationError

from .helpers import Lab, LabTransport, coordinator


class SyncIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.c = Lab(root / "controller")
        self.a, self.b = Lab(root / "a"), Lab(root / "b")
        self.c.add_server("a", 1)
        self.c.add_server("b", 2)
        self.transport = LabTransport([("a", self.a, 1), ("b", self.b, 2)])
        self.sync = coordinator(self.c, self.transport)

    def test_controller_two_ingresses_crud_restart_and_protocols(self):
        for number, protocol in ((31000, "both"), (31001, "tcp"), (31002, "udp")):
            rule = self.c.rule(number, ["a", "b"], protocol)
            self.assertEqual(self.sync.apply_rule(rule["rule_id"])["state"], "ACTIVE")
        self.assertEqual(len(self.a.deployment.manifest("agent")), 3)
        self.assertEqual(len(self.b.deployment.manifest("agent")), 3)
        first = self.c.rules.list()[0]
        self.c.services.calls.clear()
        self.c.rules.update(first["rule_id"], {"remote_port": 444})
        self.assertEqual(self.sync.apply_rule(first["rule_id"])["state"], "ACTIVE")
        self.assertTrue(
            all(first["rule_id"] in unit or not unit for action, unit in self.c.services.calls)
        )
        self.assertEqual(self.sync.apply_rule(first["rule_id"], True)["state"], "ACTIVE")
        self.c.rules.delete(first["rule_id"])
        self.assertEqual(self.sync.apply_rule(first["rule_id"])["state"], "DISABLED")
        self.assertEqual(len(self.a.deployment.manifest("agent")), 2)
        self.assertEqual(len(self.b.deployment.manifest("agent")), 2)

    def test_offline_ingress_does_not_block_other_or_direct_ipv6(self):
        rule = self.c.rule(31000, ["a", "b"])
        self.transport.offline.add("b")
        result = self.sync.apply_rule(rule["rule_id"])
        self.assertEqual(result["state"], "OUT_OF_SYNC")
        self.assertEqual(len(self.a.deployment.manifest("agent")), 1)
        self.assertEqual(len(self.c.deployment.manifest("rule-" + rule["rule_id"])), 3)
        self.transport.offline.clear()
        self.assertEqual(self.sync.reconcile()[0]["state"], "ACTIVE")

    def test_delete_waits_for_remote_withdrawal_before_local_cleanup(self):
        rule = self.c.rule(31000, ["a", "b"])
        self.sync.apply_rule(rule["rule_id"])
        self.transport.offline.add("b")
        self.c.rules.delete(rule["rule_id"])
        result = self.sync.apply_rule(rule["rule_id"])
        self.assertEqual(result["state"], "OUT_OF_SYNC")
        self.assertEqual(len(self.a.deployment.manifest("agent")), 0)
        self.assertEqual(len(self.b.deployment.manifest("agent")), 1)
        self.assertEqual(len(self.c.deployment.manifest("rule-" + rule["rule_id"])), 3)
        self.transport.offline.clear()
        self.assertEqual(self.sync.reconcile()[0]["state"], "DISABLED")
        self.assertEqual(self.c.deployment.manifest("rule-" + rule["rule_id"]), {})

    def test_agent_failure_restores_previous_version(self):
        rule = self.c.rule(31000, ["a", "b"])
        self.sync.apply_rule(rule["rule_id"])
        before = self.a.store.runtime("agent-applied")
        update = copy.deepcopy(rule["bindings"])
        update[1]["listen_port"] = 32000
        self.c.rules.update(rule["rule_id"], {"bindings": update})
        self.a.services.fail_next = True
        self.assertEqual(self.sync.apply_rule(rule["rule_id"])["state"], "OUT_OF_SYNC")
        self.assertEqual(self.a.store.runtime("agent-applied"), before)
        self.assertEqual(self.sync.reconcile()[0]["state"], "ACTIVE")

    def test_unprepared_unrelated_edit_never_published(self):
        first = self.c.rule(31000, ["a"])
        second = self.c.rule(32000, ["a"])
        self.sync.apply_rule(first["rule_id"])
        ids = {d["rule_id"] for d in self.a.deployment.manifest("agent").values()}
        self.assertNotIn(second["rule_id"], ids)

    def test_removed_offline_binding_remains_pending_until_it_acknowledges(self):
        rule = self.c.rule(31000, ["a", "b"])
        self.sync.apply_rule(rule["rule_id"])
        self.transport.offline.add("b")
        self.c.rules.update(
            rule["rule_id"], {"bindings": [b for b in rule["bindings"] if b["server_id"] != "b"]}
        )
        self.assertEqual(self.sync.apply_rule(rule["rule_id"])["state"], "OUT_OF_SYNC")
        self.assertIn("b", self.c.store.runtime("rule:" + rule["rule_id"])["affected_servers"])
        self.assertEqual(self.sync.reconcile()[0]["state"], "OUT_OF_SYNC")
        self.assertEqual(len(self.c.deployment.manifest("rule-" + rule["rule_id"])), 3)
        self.transport.offline.clear()
        self.assertEqual(self.sync.reconcile()[0]["state"], "ACTIVE")
        self.assertEqual(self.b.deployment.manifest("agent"), {})
        self.assertEqual(len(self.c.deployment.manifest("rule-" + rule["rule_id"])), 2)

    def test_failed_active_source_route_pauses_only_that_rule_and_recovers(self):
        rule = self.c.rule(31000, ["a"])
        self.sync.apply_rule(rule["rule_id"])
        self.c.network.invalid = True
        self.assertEqual(self.sync.reconcile()[0]["state"], "FAILED")
        units = [v for k, v in self.c.services.states.items() if rule["rule_id"] in k]
        self.assertTrue(all(not state["active"] for state in units))
        self.c.network.invalid = False
        self.assertEqual(self.sync.reconcile()[0]["state"], "ACTIVE")

    def test_agent_replay_recovers_only_one_stopped_rule(self):
        first = self.c.rule(31000, ["a"])
        second = self.c.rule(32000, ["a"])
        self.sync.apply_rule(first["rule_id"])
        self.sync.apply_rule(second["rule_id"])
        endpoint = next(
            e
            for e in self.a.deployment.manifest("agent").values()
            if e["rule_id"] == first["rule_id"]
        )
        unit = f"relayaxis-realm-{endpoint['endpoint_id']}.service"
        self.a.services.action("stop", unit)
        self.a.services.calls.clear()
        self.sync.sync_server("a")
        restarts = [u for a, u in self.a.services.calls if a == "start"]
        self.assertEqual(restarts, [unit])

    def test_missing_wg_interface_preserves_other_ingress_and_direct_ipv6(self):
        rule = self.c.rule(31000, ["a", "b"])
        self.sync.apply_rule(rule["rule_id"])
        self.c.network.missing_addresses.add("10.203.2.1")
        result = self.sync.reconcile()[0]
        self.assertEqual(result["state"], "OUT_OF_SYNC")
        manifest = self.c.deployment.manifest("rule-" + rule["rule_id"])
        self.assertEqual({e["listen_address"] for e in manifest.values()}, {"::", "10.203.1.1"})
        for endpoint in manifest.values():
            self.assertTrue(
                self.c.services.state(f"relayaxis-realm-{endpoint['endpoint_id']}.service")[
                    "active"
                ]
            )
        self.assertEqual(len(self.a.deployment.manifest("agent")), 1)
        self.c.network.missing_addresses.clear()
        self.assertEqual(self.sync.reconcile()[0]["state"], "ACTIVE")
        self.assertEqual(len(self.c.deployment.manifest("rule-" + rule["rule_id"])), 3)

    def test_periodic_probe_detects_offline_ingress_without_new_edits(self):
        rule = self.c.rule(31000, ["a", "b"])
        self.sync.apply_rule(rule["rule_id"])
        self.transport.offline.add("b")
        self.sync.reconcile()
        self.assertEqual(self.c.store.runtime("rule:" + rule["rule_id"])["state"], "OUT_OF_SYNC")
        self.assertTrue(
            all(
                state["active"]
                for unit, state in self.c.services.states.items()
                if rule["rule_id"] in unit
            )
        )
        self.transport.offline.clear()
        self.assertEqual(self.sync.reconcile()[0]["state"], "ACTIVE")

    def test_stale_wrong_checksum_and_arbitrary_target_are_rejected(self):
        rule = self.c.rule(31000, ["a"])
        self.sync.apply_rule(rule["rule_id"])
        snapshot = self.transport.events[-1][1]
        agent = self.transport.agents["a"]
        tampered = copy.deepcopy(snapshot)
        tampered["sha256"] = "0" * 64
        with self.assertRaises(ValidationError):
            agent.receive(tampered)
        endpoints = copy.deepcopy(snapshot["payload"]["endpoints"])
        endpoints[0]["remote_host"] = "192.0.2.99"
        with self.assertRaises(ValidationError):
            agent.receive(envelope("a", 2, endpoints))
        agent.receive(envelope("a", 2, snapshot["payload"]["endpoints"]))
        with self.assertRaises(ValidationError):
            agent.receive(snapshot)

    def test_no_route_causes_failure_before_remote_open(self):
        rule = self.c.rule(31000, ["a"])
        self.c.network.invalid = True
        result = self.sync.apply_rule(rule["rule_id"])
        self.assertEqual(result["state"], "FAILED")
        self.assertEqual(self.transport.events, [])

    def test_sync_diff(self):
        self.assertEqual(
            diff(
                [{"endpoint_id": "a", "v": 1}, {"endpoint_id": "b"}],
                [{"endpoint_id": "a", "v": 2}, {"endpoint_id": "c"}],
            ),
            {"added": ["c"], "removed": ["b"], "changed": ["a"]},
        )
