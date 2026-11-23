import json
import os
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from relayaxis.config import Paths
from relayaxis.core.network import Network
from relayaxis.core.persistence import NetworkdBackend, PersistenceManager
from relayaxis.core.routing import Routing
from relayaxis.core.system import Result
from relayaxis.errors import ApplyError, ConflictError, SystemError, ValidationError
from relayaxis.models import Egress
from relayaxis.storage import Store

from .helpers import FakeRunner, FakeServices


class PersistenceRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.installed = False
        self.netplan_applies = 0
        self.fail_candidate = False
        self.extra_rules = []

    @property
    def addresses(self):
        return [
            {
                "ifname": "eth0",
                "operstate": "UP",
                "addr_info": [
                    {
                        "family": "inet",
                        "scope": "global",
                        "local": "10.7.0.212",
                        "prefixlen": 24,
                    }
                ],
            },
            {
                "ifname": "eth1",
                "operstate": "UP",
                "addr_info": [
                    {
                        "family": "inet",
                        "scope": "global",
                        "local": "10.8.0.212",
                        "prefixlen": 24,
                    }
                ],
            },
        ]

    @property
    def routes(self):
        result = [
            {
                "dst": "default",
                "dev": "eth0",
                "gateway": "10.7.0.1",
                "prefsrc": "10.7.0.212",
                "protocol": "static",
            }
        ]
        if self.installed:
            result.append(
                {
                    "dst": "default",
                    "dev": "eth1",
                    "gateway": "10.8.0.1",
                    "prefsrc": "10.8.0.212",
                    "table": 108,
                    "protocol": "static",
                }
            )
        return result

    @property
    def rules(self):
        return (
            [{"priority": 18080, "src": "10.8.0.212/32", "table": 108, "protocol": 4}]
            if self.installed
            else []
        ) + self.extra_rules

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv == ["ip", "-j", "address", "show"]:
            return Result(stdout=json.dumps(self.addresses))
        if argv == ["ip", "-j", "-4", "route", "show", "table", "all"]:
            return Result(stdout=json.dumps(self.routes))
        if argv == ["ip", "-j", "-4", "rule", "show"]:
            return Result(stdout=json.dumps(self.rules))
        if argv[:6] == ["ip", "-j", "-4", "route", "get", "198.51.100.1"]:
            if self.installed:
                return Result(
                    stdout=json.dumps(
                        [
                            {
                                "dev": "eth1",
                                "gateway": "10.8.0.1",
                                "src": "10.8.0.212",
                                "table": 108,
                            }
                        ]
                    )
                )
            return Result(
                stdout=json.dumps(
                    [
                        {
                            "dev": "eth0",
                            "gateway": "10.7.0.1",
                            "src": "10.8.0.212",
                        }
                    ]
                )
            )
        if argv == ["netplan", "apply"]:
            self.netplan_applies += 1
            if self.fail_candidate and self.netplan_applies == 1:
                raise SystemError("injected netplan failure")
            self.installed = True
            return Result()
        if argv == ["networkctl", "reconfigure", "eth1"]:
            self.installed = True
            return Result()
        if argv[:3] == ["systemctl", "is-active", "NetworkManager.service"]:
            return Result(3)
        if argv[:3] == ["networkctl", "--json=short", "status"]:
            return Result(
                stdout=json.dumps({"NetworkFile": "/etc/systemd/network/10-eth1.network"})
            )
        return Result()


BASE_NETPLAN = """network:
  version: 2
  renderer: networkd
  ethernets:
    uplink:
      match:
        macaddress: 02:00:00:00:00:02
      set-name: eth1
      addresses:
        - 10.8.0.212/24
        - 2001:db8:8::212/64
      nameservers:
        addresses: [192.0.2.53, 2001:db8::53]
      routes:
        - to: 2001:db8:ffff::/48
          via: 2001:db8:8::1
"""


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = Paths(Path(self.temp.name))
        self.paths.initialize()
        self.paths.netplan.mkdir(parents=True)
        self.base = self.paths.netplan / "50-cloud-init.yaml"
        self.base.write_text(BASE_NETPLAN, encoding="utf-8")
        self.store = Store(self.paths.database)
        self.runner = PersistenceRunner()
        self.network = Network(self.runner)
        self.manager = PersistenceManager(
            self.paths, self.store, self.network, self.runner, FakeServices()
        )
        self.egress = Egress(
            "line-cn2",
            "电信 CN2",
            "eth1",
            "10.8.0.212",
            "10.8.0.1",
            "108",
            18080,
            managed=True,
        ).validate()
        self.store.put("egress", self.egress.egress_id, asdict(self.egress), 0)

    def test_netplan_candidate_is_separate_and_preserves_all_base_properties(self):
        before = self.base.read_bytes()
        plan = self.manager.plan(self.egress)
        self.assertEqual(plan["backend"], "netplan")
        self.assertEqual(plan["change"], "create")
        self.assertIn("90-relayaxis-egress-line-cn2.yaml", plan["path"])
        self.assertEqual(self.base.read_bytes(), before)
        self.assertIn("table: 108", plan["diff"])
        self.assertIn("priority: 18080", plan["diff"])
        self.assertIn("from: 10.8.0.212", plan["diff"])
        self.assertIn("    'uplink':", plan["diff"])
        # The independent fragment does not duplicate or overwrite base identity,
        # addresses, v6, DNS, MAC matching, or unrelated routes.
        self.assertNotIn("macaddress", plan["diff"])
        self.assertNotIn("nameservers", plan["diff"])

    def test_conflicting_external_table_is_rejected_without_writes(self):
        external = self.paths.netplan / "80-external.yaml"
        external.write_text(
            "network:\n  version: 2\n  ethernets:\n    eth1:\n      routes:\n"
            "        - to: default\n          via: 10.8.0.1\n          table: 108\n"
        )
        with self.assertRaises(ConflictError):
            self.manager.plan(self.egress)
        self.assertFalse(self.manager.netplan.path(self.egress).exists())

    def test_matching_kernel_entries_are_still_external_without_ownership(self):
        self.runner.installed = True
        with self.assertRaises(ConflictError):
            self.manager.plan(self.egress)
        self.assertFalse(self.manager.netplan.path(self.egress).exists())

    def test_another_rule_using_the_candidate_table_is_a_conflict(self):
        self.runner.extra_rules.append(
            {"priority": 19000, "src": "10.8.0.213/32", "table": 108, "protocol": 4}
        )
        with self.assertRaises(ConflictError):
            self.manager.plan(self.egress)

    def test_missing_source_and_offlink_gateway_are_rejected_before_candidate_write(self):
        missing = Egress(**{**asdict(self.egress), "source": "10.8.0.213"}).validate()
        with self.assertRaises(ValidationError):
            self.manager.plan(missing)
        offlink = Egress(**{**asdict(self.egress), "gateway": "10.9.0.1"}).validate()
        with self.assertRaises(ValidationError):
            self.manager.plan(offlink)
        self.assertFalse(self.manager.netplan.path(self.egress).exists())

    def test_mac_only_match_does_not_treat_definition_id_as_kernel_name(self):
        self.base.write_text(
            """network:
  version: 2
  renderer: networkd
  ethernets:
    eth1:
      match:
        macaddress: 02:00:00:00:00:02
      addresses: [10.8.0.212/24]
"""
        )
        with self.assertRaises(ConflictError):
            self.manager.plan(self.egress)

    def test_unregistered_destination_is_never_overwritten(self):
        destination = self.manager.netplan.path(self.egress)
        destination.write_text("# user file\n", encoding="utf-8")
        with self.assertRaises(ConflictError):
            self.manager.plan(self.egress)
        self.assertEqual(destination.read_text(), "# user file\n")

    def test_apply_is_confirmed_idempotent_and_verifies_real_kernel_lookup(self):
        plan = self.manager.plan(self.egress)
        result = self.manager.apply(self.egress, plan["plan_id"])
        self.assertEqual(result["state"], "ACTIVE")
        self.assertEqual(result["health"]["status"], "HEALTHY")
        destination = self.manager.netplan.path(self.egress)
        first = destination.read_bytes()
        repeated = self.manager.plan(self.egress)
        self.assertEqual(repeated["change"], "unchanged")
        self.manager.apply(self.egress, repeated["plan_id"])
        self.assertEqual(destination.read_bytes(), first)
        self.assertEqual(self.base.read_text(encoding="utf-8"), BASE_NETPLAN)

    def test_failed_apply_restores_original_file(self):
        plan = self.manager.plan(self.egress)
        self.runner.fail_candidate = True
        with self.assertRaises(ApplyError):
            self.manager.apply(self.egress, plan["plan_id"])
        self.assertFalse(self.manager.netplan.path(self.egress).exists())
        self.assertFalse(list((self.paths.state / "network-journals").glob("*.json")))

    def test_networkd_uses_drop_in_for_effective_file_not_competing_network(self):
        egress = Egress(**{**asdict(self.egress), "backend": "networkd"}).validate()
        backend = NetworkdBackend(self.paths, self.runner, self.network)
        destination = backend.path(egress)
        backend.prepare_destination(destination)
        self.assertEqual(destination.parent.name, "10-eth1.network.d")
        if os.name == "posix":
            self.assertEqual(destination.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(backend.file_mode, 0o644)
        self.assertEqual(destination.suffix, ".conf")
        rendered = backend.render(egress)
        self.assertIn("[Route]", rendered)
        self.assertIn("[RoutingPolicyRule]", rendered)
        self.assertNotIn("[Match]", rendered)

    def test_networkd_conflicts_include_runtime_and_vendor_search_paths(self):
        egress = Egress(**{**asdict(self.egress), "backend": "networkd"}).validate()
        vendor = self.paths.root / "usr/lib/systemd/network/20-vendor.network.d/policy.conf"
        vendor.parent.mkdir(parents=True)
        vendor.write_text("[RoutingPolicyRule]\nFrom=192.0.2.1/32\nTable=109\nPriority=18080\n")
        backend = NetworkdBackend(self.paths, self.runner, self.network)
        destination = backend.path(egress)
        self.assertTrue(
            any(item["file"] == str(vendor) for item in backend.conflicts(egress, destination))
        )

    def test_system_and_external_detection_stays_read_only(self):
        system = Egress(
            "main", "默认", "eth0", "10.7.0.212", "10.7.0.1", management="system"
        ).validate()
        external = Egress(
            "outside",
            "外部 Netplan",
            "eth1",
            "10.8.0.212",
            "10.8.0.1",
            "108",
            18080,
            management="external",
            backend="netplan",
        ).validate()
        self.assertEqual(self.manager.detect(system)["selected"], "system")
        report = self.manager.detect(external)
        self.assertEqual(report["selected"], "read-only")
        self.assertFalse(report["writable"])

    def test_rollback_transaction_id_cannot_escape_journal_directory(self):
        outside = self.paths.state / "outside.json"
        outside.write_text("{}")
        with self.assertRaises(ValidationError):
            self.manager.rollback("../outside")
        self.assertTrue(outside.exists())

    def test_owned_route_is_target_repaired_but_external_route_is_report_only(self):
        plan = self.manager.plan(self.egress)
        self.manager.apply(self.egress, plan["plan_id"])
        self.runner.installed = False
        self.runner.calls.clear()
        repaired = self.manager.repair(self.egress)
        self.assertEqual(repaired["state"], "HEALTHY")
        self.assertIn(["networkctl", "reconfigure", "eth1"], self.runner.calls)

        external = Egress(
            "external",
            "外部管理",
            "eth1",
            "10.8.0.212",
            "10.8.0.1",
            "108",
            18080,
            management="external",
            backend="netplan",
        ).validate()
        self.runner.installed = False
        self.runner.calls.clear()
        report = self.manager.repair(external)
        self.assertFalse(report["changed"])
        self.assertFalse(
            any(call[:1] in (["netplan"], ["networkctl"]) for call in self.runner.calls)
        )


class LegacyRunner(PersistenceRunner):
    def __init__(self):
        super().__init__()
        self.realm_dependency = True
        self.external_dependency = False

    def run(self, argv, **kwargs):
        if argv[:2] == ["systemctl", "cat"]:
            return Result(
                stdout="""[Service]
ExecStart=/usr/sbin/ip -4 rule add priority 18080 from 10.8.0.212/32 table 108
ExecStart=/usr/sbin/ip -4 route replace default via 10.8.0.1 dev eth1 src 10.8.0.212 table 108
ExecStop=/usr/sbin/ip -4 rule del priority 18080 from 10.8.0.212/32 table 108
ExecStop=/usr/sbin/ip -4 route flush table 108
"""
            )
        if argv[:3] == ["systemctl", "list-dependencies", "--reverse"]:
            dependencies = ["relayaxis-pbr-old.service"]
            if self.realm_dependency:
                dependencies.append("relayaxis-realm-example.service")
            if self.external_dependency:
                dependencies.append("custom-consumer.service")
            return Result(stdout="\n".join(dependencies) + "\n")
        return super().run(argv, **kwargs)


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = Paths(Path(self.temp.name))
        self.paths.initialize()
        self.paths.netplan.mkdir(parents=True)
        (self.paths.netplan / "50-cloud-init.yaml").write_text(BASE_NETPLAN)
        self.store = Store(self.paths.database)
        self.runner = LegacyRunner()
        self.runner.installed = True
        self.services = FakeServices()
        self.services.states["relayaxis-pbr-old.service"] = {
            "active": True,
            "enabled": True,
        }
        self.network = Network(self.runner)
        self.routing = Routing(self.paths, self.store, self.network, self.runner, self.services)
        old = Egress(
            "old",
            "旧出口",
            "eth1",
            "10.8.0.212",
            "10.8.0.1",
            "108",
            18080,
            managed=True,
            dependency_service="relayaxis-pbr-old.service",
        )
        self.store.put("egress", "old", asdict(old), 0)
        self.store.set_runtime("pbr-unit:old", {"unit": "relayaxis-pbr-old.service"})

    def test_migration_audits_execstop_and_requires_reviewed_plan(self):
        result = self.routing.migrate("old")
        self.assertEqual(result["state"], "PLANNED")
        self.assertTrue(result["audit"]["exec_stop_destructive"])
        self.assertTrue(result["audit"]["safe_migration"])
        self.assertIn("relayaxis-realm-example.service", result["audit"]["reverse_dependencies"])
        self.assertEqual(result["plan"]["backend"], "netplan")
        self.assertEqual(self.services.calls, [])

    def test_confirmed_migration_reconciles_dependencies_before_disable(self):
        planned = self.routing.migrate("old")
        result = self.routing.migrate("old", confirm=True, plan_id=planned["plan"]["plan_id"])
        self.assertEqual(result["state"], "NATIVE_STAGED")
        self.assertNotIn(("disable", "relayaxis-pbr-old.service"), self.services.calls)
        self.runner.realm_dependency = False
        finalized = self.routing.finalize_migration("old", result["migration_id"])
        self.assertEqual(finalized["state"], "ACTIVE")
        self.assertIn(("disable", "relayaxis-pbr-old.service"), self.services.calls)
        self.assertNotIn(("stop", "relayaxis-pbr-old.service"), self.services.calls)
        saved = Egress(**self.store.get("egress", "old")).validate()
        self.assertEqual(saved.backend, "netplan")
        self.assertEqual(saved.dependency_service, "")
        self.assertTrue(self.store.runtime("legacy-pbr:old")["disabled_without_stop"])

    def test_crash_after_native_apply_is_finalized_without_stopping_legacy_unit(self):
        planned = self.routing.migrate("old")
        egress = Egress(**self.store.get("egress", "old")).validate()
        self.routing.persistence.apply(egress, planned["plan"]["plan_id"], migration=True)
        migration_id = "0123456789abcdef"
        journal = self.paths.state / f"pbr-migrations/{migration_id}.json"
        journal.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "id": migration_id,
                    "egress_id": "old",
                    "unit": "relayaxis-pbr-old.service",
                    "phase": "NATIVE_APPLIED",
                }
            )
        )
        self.runner.realm_dependency = False
        result = self.routing._recover_pbr_migrations()
        self.assertEqual(result[0]["state"], "NATIVE_FINALIZED")
        self.assertIn(("disable", "relayaxis-pbr-old.service"), self.services.calls)
        self.assertNotIn(("stop", "relayaxis-pbr-old.service"), self.services.calls)
        self.assertEqual(Egress(**self.store.get("egress", "old")).validate().backend, "netplan")

    def test_unsafe_legacy_apply_returns_audit_without_native_plan(self):
        self.store.set_runtime("pbr-unit:old", {})
        result = self.routing.apply("old")
        self.assertEqual(result["state"], "MIGRATION_REQUIRED")
        self.assertFalse(result["audit"]["safe_migration"])
        self.assertNotIn("plan", result)

    def test_v010_indirect_unit_matches_reviewed_config_not_execstop_text(self):
        self.routing.config_path("old").parent.mkdir(parents=True, exist_ok=True)
        self.routing.config_path("old").write_text(json.dumps(self.store.get("egress", "old")))
        original_run = self.runner.run

        def indirect(argv, **kwargs):
            if argv[:2] == ["systemctl", "cat"]:
                return Result(
                    stdout="""[Service]
ExecStart=/usr/local/bin/ra --json egress activate old --from-config
ExecStop=/usr/local/bin/ra --json egress deactivate old
ExecStopPost=-/usr/local/bin/ra --json egress deactivate old
"""
                )
            return original_run(argv, **kwargs)

        self.runner.run = indirect
        audit = self.routing.audit_legacy("old")
        self.assertTrue(audit["matches_egress"])
        self.assertTrue(audit["config_matches_egress"])
        self.assertTrue(audit["exec_stop_destructive"])
        self.assertEqual(audit["exec_start_mode"], "relayaxis-v0.1.0")

    def test_external_reverse_dependency_keeps_migration_in_audit_mode(self):
        self.runner.external_dependency = True
        result = self.routing.migrate("old")
        self.assertEqual(result["state"], "AUDIT_ONLY")
        self.assertEqual(result["audit"]["external_dependencies"], ["custom-consumer.service"])
