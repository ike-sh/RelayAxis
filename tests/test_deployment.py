import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from relayaxis.core.realm import Endpoint, render
from relayaxis.errors import ApplyError, ConflictError

from .helpers import Lab


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name))
        self.endpoint = Endpoint(
            "r-one", "r", "::1", 12345, "192.0.2.80", 443, "both", "192.0.2.10", "eth0"
        )

    def test_toml_protocol_and_source_binding(self):
        for proto in ("tcp", "udp", "both"):
            self.endpoint.protocol = proto
            parsed = tomllib.loads(render(self.endpoint))
            self.assertEqual(parsed["network"]["no_tcp"], proto == "udp")
            self.assertEqual(parsed["network"]["use_udp"], proto != "tcp")
            self.assertTrue(parsed["network"]["ipv6_only"])
            self.assertEqual(parsed["endpoints"][0]["through"], "192.0.2.10")
            self.assertEqual(parsed["endpoints"][0]["interface"], "eth0")

    def test_apply_idempotence_and_single_rule_isolation(self):
        d = self.lab.deployment
        d.apply("one", [self.endpoint])
        other = Endpoint("other", "q", "::1", 12346, "192.0.2.90", 80, "tcp")
        d.apply("two", [other])
        self.lab.services.calls.clear()
        d.apply("one", [self.endpoint])
        self.assertEqual(self.lab.services.calls, [])
        self.endpoint.remote_port = 444
        d.apply("one", [self.endpoint])
        self.assertFalse(any(unit == other.unit for action, unit in self.lab.services.calls))

    def test_failed_start_restores_files_service_state_and_manifest(self):
        d = self.lab.deployment
        d.apply("one", [self.endpoint])
        config = self.lab.paths.config / "realm/r-one.toml"
        old = config.read_bytes()
        self.lab.services.fail_next = True
        self.endpoint.remote_port = 444
        with self.assertRaises(ApplyError):
            d.apply("one", [self.endpoint])
        self.assertEqual(config.read_bytes(), old)
        self.assertEqual(d.manifest("one")["r-one"]["remote_port"], 443)
        self.assertTrue(self.lab.services.state(self.endpoint.unit)["active"])

    def test_crash_journal_recovers_on_next_process(self):
        d = self.lab.deployment
        d.apply("one", [self.endpoint])
        backups = list(self.lab.paths.backups.glob("deployment-*.json"))
        journal = json.loads(backups[0].read_text())
        self.lab.store.set_runtime("deployment-commit:" + journal["id"], False)
        path = self.lab.paths.state / "journals/crashed.json"
        path.write_text(json.dumps(journal))
        result = d.recover()
        self.assertEqual(result[0]["result"], "rolled_back")
        self.assertFalse((self.lab.paths.config / "realm/r-one.toml").exists())

    def test_unregistered_external_file_is_never_overwritten(self):
        path = self.lab.paths.config / "realm/r-one.toml"
        path.parent.mkdir()
        path.write_text("external")
        with self.assertRaises(ConflictError):
            self.lab.deployment.apply("one", [self.endpoint])
        self.assertEqual(path.read_text(), "external")

    def test_disabled_unit_removed_without_touching_other_scope(self):
        self.lab.deployment.apply("one", [self.endpoint])
        self.lab.deployment.apply("one", [])
        self.assertEqual(self.lab.deployment.manifest("one"), {})
        self.assertFalse(self.lab.services.state(self.endpoint.unit)["active"])
