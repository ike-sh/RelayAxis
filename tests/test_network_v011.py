import json
import unittest

from relayaxis.core.network import Network
from relayaxis.core.system import Result
from relayaxis.models import Egress, EgressHealth

from .helpers import FakeRunner


def address(device, source, *, state="UP"):
    return {
        "ifname": device,
        "operstate": state,
        "flags": ["UP", "LOWER_UP"] if state == "UP" else [],
        "addr_info": [
            {
                "family": "inet",
                "local": source,
                "prefixlen": 24,
                "scope": "global",
            }
        ],
    }


def network(addresses, routes, rules):
    return Network(
        FakeRunner(
            {
                ("ip", "-j", "address", "show"): Result(stdout=json.dumps(addresses)),
                ("ip", "-j", "-4", "route", "show", "table", "all"): Result(
                    stdout=json.dumps(routes)
                ),
                ("ip", "-j", "-4", "rule", "show"): Result(stdout=json.dumps(rules)),
            }
        )
    )


class EgressDiscoveryV011Tests(unittest.TestCase):
    def test_default_is_a_kernel_fact_not_an_interface_or_carrier_name(self):
        scenarios = (
            (
                "9929-default",
                [address("eth0", "10.7.0.212"), address("eth1", "10.8.0.212")],
                [
                    {
                        "dst": "default",
                        "dev": "eth0",
                        "gateway": "10.7.0.1",
                        "prefsrc": "10.7.0.212",
                    },
                    {
                        "dst": "default",
                        "dev": "eth1",
                        "gateway": "10.8.0.1",
                        "prefsrc": "10.8.0.212",
                        "table": 108,
                    },
                ],
                [{"priority": 18080, "src": "10.8.0.212/32", "table": 108}],
                ("eth0", "10.7.0.212", "main"),
            ),
            (
                "cn2-default",
                [address("eth0", "10.8.0.212"), address("eth1", "10.7.0.212")],
                [
                    {
                        "dst": "default",
                        "dev": "eth0",
                        "gateway": "10.8.0.1",
                        "prefsrc": "10.8.0.212",
                    },
                    {
                        "dst": "default",
                        "dev": "eth1",
                        "gateway": "10.7.0.1",
                        "prefsrc": "10.7.0.212",
                        "table": 109,
                    },
                ],
                [{"priority": 18081, "src": "10.7.0.212/32", "table": 109}],
                ("eth0", "10.8.0.212", "main"),
            ),
            (
                "bgp-three-lines",
                [
                    address("eth0", "192.0.2.10"),
                    address("eth1", "10.7.0.212"),
                    address("eth2", "10.8.0.212"),
                ],
                [
                    {
                        "dst": "default",
                        "dev": "eth0",
                        "gateway": "192.0.2.1",
                        "prefsrc": "192.0.2.10",
                    },
                    {
                        "dst": "default",
                        "dev": "eth1",
                        "gateway": "10.7.0.1",
                        "prefsrc": "10.7.0.212",
                        "table": 108,
                    },
                    {
                        "dst": "default",
                        "dev": "eth2",
                        "gateway": "10.8.0.1",
                        "prefsrc": "10.8.0.212",
                        "table": 109,
                    },
                ],
                [
                    {"priority": 18080, "src": "10.7.0.212/32", "table": 108},
                    {"priority": 18081, "src": "10.8.0.212/32", "table": 109},
                ],
                ("eth0", "192.0.2.10", "main"),
            ),
            (
                "irregular-name",
                [address("ens18", "192.0.2.10"), address("enp1s0", "198.51.100.10")],
                [
                    {
                        "dst": "default",
                        "dev": "ens18",
                        "gateway": "192.0.2.1",
                        "prefsrc": "192.0.2.10",
                    },
                    {
                        "dst": "default",
                        "dev": "enp1s0",
                        "gateway": "198.51.100.1",
                        "prefsrc": "198.51.100.10",
                        "table": 201,
                    },
                ],
                [{"priority": 18201, "src": "198.51.100.10/32", "table": 201}],
                ("ens18", "192.0.2.10", "main"),
            ),
        )
        for label, addresses, routes, rules, expected in scenarios:
            with self.subTest(label=label):
                discovered = network(addresses, routes, rules).discover_egresses()
                defaults = [item for item in discovered if item["is_default"]]
                self.assertEqual(len(defaults), 1)
                self.assertEqual(
                    (defaults[0]["interface"], defaults[0]["source"], defaults[0]["table"]),
                    expected,
                )
                self.assertEqual(defaults[0]["management"], "system")

    def test_single_egress_and_dynamic_source_are_derived_from_current_snapshot(self):
        routes = [{"dst": "default", "dev": "ens18", "gateway": "192.0.2.1"}]
        first = network([address("ens18", "192.0.2.10")], routes, []).discover_egresses()
        second = network([address("ens18", "192.0.2.11")], routes, []).discover_egresses()
        self.assertEqual(first[0]["source"], "192.0.2.10")
        self.assertEqual(second[0]["source"], "192.0.2.11")
        self.assertTrue(first[0]["source_inferred"])

    def test_metric_selects_unique_default_but_equal_best_routes_require_confirmation(self):
        addresses = [address("eth0", "192.0.2.10"), address("eth1", "198.51.100.10")]
        preferred = [
            {
                "dst": "default",
                "dev": "eth0",
                "gateway": "192.0.2.1",
                "prefsrc": "192.0.2.10",
                "metric": 10,
            },
            {
                "dst": "default",
                "dev": "eth1",
                "gateway": "198.51.100.1",
                "prefsrc": "198.51.100.10",
                "metric": 20,
            },
        ]
        found = network(addresses, preferred, []).discover_egresses()
        self.assertEqual([item["interface"] for item in found if item["is_default"]], ["eth0"])
        ambiguous = network(
            addresses,
            [{**route, "metric": 10} for route in preferred],
            [],
        ).discover_egresses()
        self.assertFalse(any(item["is_default"] for item in ambiguous))
        self.assertTrue(all(item["default_ambiguous"] for item in ambiguous))

    def test_missing_default_does_not_invent_one_and_multiple_policy_priorities_are_visible(self):
        found = network(
            [address("eth1", "10.8.0.212")],
            [],
            [
                {"priority": 18080, "src": "10.8.0.212/32", "table": 108},
                {"priority": 18090, "src": "10.8.0.212/32", "table": 109},
            ],
        ).discover_egresses()
        self.assertFalse(any(item["is_default"] for item in found))
        self.assertEqual({item["priority"] for item in found}, {18080, 18090})
        self.assertTrue(all(not item["has_default"] for item in found))

    def test_missing_policy_source_is_still_visible_and_dst_all_is_simple(self):
        found = network(
            [address("eth1", "10.8.0.213")],
            [
                {
                    "dst": "default",
                    "dev": "eth1",
                    "gateway": "10.8.0.1",
                    "table": 108,
                }
            ],
            [
                {
                    "priority": 18080,
                    "src": "10.8.0.212/32",
                    "dst": "all",
                    "table": 108,
                }
            ],
        ).discover_egresses()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["source"], "10.8.0.212")
        self.assertEqual(found[0]["source_selector"], "10.8.0.212/32")

    def test_default_with_multiple_possible_sources_requires_confirmation(self):
        link = address("eth0", "192.0.2.10")
        link["addr_info"].append(
            {
                "family": "inet",
                "local": "192.0.2.11",
                "prefixlen": 24,
                "scope": "global",
            }
        )
        found = network(
            [link],
            [{"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"}],
            [],
        ).discover_egresses()
        self.assertFalse(found[0]["is_default"])
        self.assertTrue(found[0]["source_uncertain"])
        self.assertTrue(found[0]["default_requires_confirmation"])


class EgressHealthV011Tests(unittest.TestCase):
    def setUp(self):
        self.egress = Egress(
            "line-cn2",
            "自定义线路",
            "eth1",
            "10.8.0.212",
            "10.8.0.1",
            "108",
            18080,
            management="external",
        ).validate()
        self.addresses = [address("eth1", "10.8.0.212")]

    def test_active_exited_incident_is_rule_missing_not_healthy(self):
        # Service state is intentionally absent from the decision: only kernel
        # rule/table/lookup facts can make this healthy.
        net = network(self.addresses, [], [])
        report = net.egress_health(self.egress)
        self.assertEqual(report["status"], EgressHealth.RULE_MISSING)
        self.assertFalse(report["ok"])

    def test_empty_table_is_route_missing(self):
        net = network(
            self.addresses,
            [],
            [{"priority": 18080, "src": "10.8.0.212/32", "table": 108}],
        )
        self.assertEqual(net.egress_health(self.egress)["status"], EgressHealth.ROUTE_MISSING)

    def test_wrong_interface_is_not_accepted_as_default_fallback(self):
        net = network(
            self.addresses,
            [
                {
                    "dst": "default",
                    "dev": "eth0",
                    "gateway": "10.7.0.1",
                    "prefsrc": "10.8.0.212",
                    "table": 108,
                }
            ],
            [{"priority": 18080, "src": "10.8.0.212/32", "table": 108}],
        )
        self.assertEqual(net.egress_health(self.egress)["status"], EgressHealth.WRONG_INTERFACE)

    def test_health_classifies_source_link_table_gateway_and_lookup_failures(self):
        cases = (
            (
                "source",
                network([address("eth1", "10.8.0.213")], [], []),
                EgressHealth.SOURCE_MISSING,
            ),
            (
                "link",
                network([address("eth1", "10.8.0.212", state="DOWN")], [], []),
                EgressHealth.DEGRADED,
            ),
            (
                "table",
                network(
                    self.addresses,
                    [],
                    [{"priority": 18080, "src": "10.8.0.212/32", "table": 109}],
                ),
                EgressHealth.WRONG_TABLE,
            ),
            (
                "gateway",
                network(
                    self.addresses,
                    [
                        {
                            "dst": "default",
                            "dev": "eth1",
                            "gateway": "10.8.0.254",
                            "prefsrc": "10.8.0.212",
                            "table": 108,
                        }
                    ],
                    [{"priority": 18080, "src": "10.8.0.212/32", "table": 108}],
                ),
                EgressHealth.WRONG_GATEWAY,
            ),
        )
        for label, net, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(net.egress_health(self.egress)["status"], expected)

        unreachable = network(
            self.addresses,
            [
                {
                    "dst": "default",
                    "dev": "eth1",
                    "gateway": "10.8.0.1",
                    "prefsrc": "10.8.0.212",
                    "table": 108,
                }
            ],
            [{"priority": 18080, "src": "10.8.0.212/32", "table": 108}],
        )
        self.assertEqual(unreachable.egress_health(self.egress)["status"], EgressHealth.UNREACHABLE)

    def test_healthy_requires_both_ordinary_and_bound_effective_lookup(self):
        net = network(
            self.addresses,
            [
                {
                    "dst": "default",
                    "dev": "eth1",
                    "gateway": "10.8.0.1",
                    "prefsrc": "10.8.0.212",
                    "table": 108,
                }
            ],
            [{"priority": 18080, "src": "10.8.0.212/32", "table": 108}],
        )
        base = (
            "ip",
            "-j",
            "-4",
            "route",
            "get",
            "198.51.100.1",
            "from",
            "10.8.0.212",
            "ipproto",
            "tcp",
            "dport",
            "443",
        )
        route = {
            "dev": "eth1",
            "gateway": "10.8.0.1",
            "src": "10.8.0.212",
            "table": 108,
        }
        net.runner.answers[base] = Result(stdout=json.dumps([route]))
        net.runner.answers[(*base, "oif", "eth1")] = Result(stdout=json.dumps([route]))
        report = net.egress_health(self.egress)
        self.assertEqual(report["status"], EgressHealth.HEALTHY)
        self.assertTrue(report["ok"])
