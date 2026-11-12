import copy
import json
import tempfile
import unittest
from pathlib import Path

from relayaxis.core.network import Network
from relayaxis.core.routing import Routing
from relayaxis.core.system import Result
from relayaxis.errors import ApplyError, ConflictError, SystemError

from .helpers import FakeRunner, Lab


class RoutingRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.routes, self.rules = [], []
        self.has_source = True
        self.fail_on = ""

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:4] == ["ip", "-j", "address", "show"]:
            return Result(
                stdout=json.dumps(
                    [
                        {
                            "ifname": "eth1",
                            "addr_info": [
                                {"family": "inet", "local": "10.8.0.212", "prefixlen": 24}
                            ],
                        }
                    ]
                    if self.has_source
                    else []
                )
            )
        if argv[:6] == ["ip", "-j", "-4", "route", "show", "table"]:
            return Result(stdout=json.dumps(self.routes))
        if argv == ["ip", "-j", "-4", "rule", "show"]:
            return Result(stdout=json.dumps(self.rules))
        if argv[:3] == ["ip", "-4", "route"]:
            record = {
                "dst": argv[4],
                "dev": argv[argv.index("dev") + 1],
                "prefsrc": argv[argv.index("src") + 1],
                "table": int(argv[argv.index("table") + 1]),
                "protocol": 186,
            }
            if "via" in argv:
                record["gateway"] = argv[argv.index("via") + 1]
            collection = self.routes
        elif argv[:3] == ["ip", "-4", "rule"]:
            record = {
                "priority": int(argv[argv.index("priority") + 1]),
                "src": argv[argv.index("from") + 1],
                "table": int(argv[argv.index("table") + 1]),
                "protocol": 186,
            }
            collection = self.rules
        else:
            return Result()
        if argv[3] == "add":
            if self.fail_on and self.fail_on in argv:
                self.fail_on = ""
                raise SystemError("injected routing error")
            collection.append(record)
        elif record in collection:
            collection.remove(record)
        else:
            return Result(2)
        return Result()


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name))
        self.runner = RoutingRunner()
        self.routing = Routing(
            self.lab.paths, self.lab.store, Network(self.runner), self.runner, self.lab.services
        )
        self.data = {
            "egress_id": "owned",
            "name": "CN2",
            "interface": "eth1",
            "source": "10.8.0.212",
            "gateway": "10.8.0.1",
            "table": "108",
            "priority": 18080,
            "managed": True,
        }
        self.routing.save(self.data)

    def test_owned_pbr_is_idempotent_and_repairs_only_missing_entry(self):
        self.routing.activate("owned")
        self.assertEqual(len(self.runner.routes), 2)
        self.assertEqual(len(self.runner.rules), 1)
        self.assertFalse(self.routing.activate("owned")["changed"])
        self.runner.routes = [r for r in self.runner.routes if r["dst"] != "default"]
        self.runner.calls.clear()
        self.routing.activate("owned")
        writes = [c for c in self.runner.calls if len(c) > 3 and c[3] in ("add", "del")]
        self.assertEqual(len(writes), 1)
        self.assertIn("default", writes[0])

    def test_partial_failure_retracts_own_entries(self):
        self.runner.fail_on = "default"
        with self.assertRaises(ApplyError):
            self.routing.activate("owned")
        self.assertEqual(self.runner.routes, [])
        self.assertEqual(self.runner.rules, [])

    def test_external_existing_table_and_rule_are_not_changed(self):
        external = {"priority": 18080, "src": "10.8.0.212", "table": 108, "protocol": 4}
        self.runner.rules.append(external)
        with self.assertRaises(ConflictError):
            self.routing.activate("owned")
        self.assertEqual(self.runner.rules, [external])
        self.assertEqual(self.runner.routes, [])

    def test_remove_exact_owned_routes_even_after_source_address_disappears(self):
        self.routing.activate("owned")
        self.runner.has_source = False
        self.routing.deactivate("owned")
        self.assertEqual(self.runner.routes, [])
        self.assertEqual(self.runner.rules, [])
        self.assertFalse(any("flush" in c or "main" in c for c in self.runner.calls))

    def test_modified_external_entry_is_not_silently_replaced(self):
        self.routing.activate("owned")
        self.runner.routes[1]["gateway"] = "10.8.0.2"
        before = copy.deepcopy(self.runner.routes)
        with self.assertRaises(ConflictError):
            self.routing.activate("owned")
        self.assertEqual(self.runner.routes, before)

    def test_external_egress_apply_does_not_touch_routes(self):
        self.runner.calls.clear()
        self.assertEqual(self.routing.apply("line-a")["state"], "EXTERNAL")
        self.assertEqual(self.runner.calls, [])
