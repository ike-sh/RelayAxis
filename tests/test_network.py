import json
import unittest

from relayaxis.core.network import Network
from relayaxis.core.system import Result
from relayaxis.errors import ValidationError
from relayaxis.models import Egress

from .helpers import FakeRunner


class NetworkTests(unittest.TestCase):
    def setUp(self):
        addresses = [
            {
                "ifname": "eth1",
                "addr_info": [
                    {"family": "inet", "local": "10.8.0.212", "prefixlen": 24, "scope": "global"}
                ],
            }
        ]
        self.route = {"dev": "eth1", "gateway": "10.8.0.1", "table": 108, "src": "10.8.0.212"}
        self.runner = FakeRunner(
            {("ip", "-j", "address", "show"): Result(stdout=json.dumps(addresses))}
        )
        self.net = Network(self.runner)
        self.egress = Egress(
            "cn2",
            "CN2",
            "eth1",
            "10.8.0.212",
            "10.8.0.1",
            "108",
            18080,
            dependency_service="ipv4-eth1-pbr.service",
        )

    def route_response(self, value):
        for proto in ("tcp", "udp"):
            self.runner.answers[
                (
                    "ip",
                    "-j",
                    "-4",
                    "route",
                    "get",
                    "198.51.100.8",
                    "from",
                    "10.8.0.212",
                    "ipproto",
                    proto,
                    "dport",
                    "443",
                )
            ] = Result(stdout=json.dumps([value]))
            base = next(reversed(self.runner.answers))
            self.runner.answers[(*base, "oif", "eth1")] = Result(stdout=json.dumps([value]))

    def test_source_routing_uses_effective_kernel_lookup_without_oif(self):
        self.route_response(self.route)
        result = self.net.validate_egress(self.egress, "198.51.100.8", 443)
        self.assertEqual(len(result), 4)
        lookups = [c for c in self.runner.calls if "get" in c]
        self.assertNotIn("oif", lookups[0])
        self.assertIn("oif", lookups[1])

    def test_interface_gateway_table_and_source_mismatch_rejected(self):
        for key, value in (
            ("dev", "eth0"),
            ("gateway", "10.7.0.1"),
            ("table", "main"),
            ("src", "10.7.0.212"),
        ):
            with self.subTest(key=key):
                self.route_response({**self.route, key: value})
                with self.assertRaises(ValidationError):
                    self.net.validate_egress(self.egress, "198.51.100.8", 443)

    def test_missing_source_rejected(self):
        self.egress.source = "10.8.0.213"
        with self.assertRaises(ValidationError):
            self.net.validate_egress(self.egress, "198.51.100.8", 443)

    def test_existing_source_pbr_discovery_is_read_only(self):
        self.runner.answers[("ip", "-j", "-4", "route", "show", "table", "all")] = Result(
            stdout=json.dumps([{**self.route, "dst": "default"}])
        )
        self.runner.answers[("ip", "-j", "-4", "rule", "show")] = Result(
            stdout=json.dumps([{"priority": 18080, "src": "10.8.0.212", "table": 108}])
        )
        result = self.net.discover_egresses()
        self.assertEqual(result[0]["priority"], 18080)
        self.assertEqual(result[0]["table"], "108")
        self.assertTrue(result[0]["external"])
        self.assertFalse(
            any(any(a in c for a in ("add", "del", "replace")) for c in self.runner.calls)
        )
