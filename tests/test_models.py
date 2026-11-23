import unittest

from relayaxis.errors import ValidationError
from relayaxis.models import (
    Binding,
    Egress,
    Rule,
    address_conflict,
    hostname,
    ip,
    networks_overlap,
    port,
)


class ModelsTests(unittest.TestCase):
    def test_ip_and_port_validation(self):
        self.assertEqual(ip("2001:db8::1", 6), "2001:db8::1")
        for value in ("1.2.3.999", "$(id)", "fe80::1%eth0", "224.0.0.1"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ip(value)
        for value in (0, 65536, True, "22"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                port(value)

    def test_hostname_does_not_allow_commands_or_ipv6_egress(self):
        self.assertEqual(hostname("example.com"), "example.com")
        for value in (
            "example.com\n",
            "-oProxyCommand=id",
            "2001:db8::1",
            "300.1.1.1",
            "a..b",
            "a.-b",
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                hostname(value)

    def test_overlap(self):
        self.assertTrue(networks_overlap("10.1.0.1/30", "10.1.0.0/24"))
        self.assertFalse(networks_overlap("10.1.0.0/30", "10.2.0.0/30"))

    def test_socket_conflicts(self):
        self.assertTrue(address_conflict("::", "2001:db8::1"))
        self.assertTrue(address_conflict("0.0.0.0", "192.0.2.1"))
        self.assertFalse(address_conflict("::", "0.0.0.0"))
        self.assertFalse(address_conflict("192.0.2.1", "192.0.2.2"))

    def test_no_managed_main_route(self):
        with self.assertRaises(ValidationError):
            Egress("x", "X", "eth0", "192.0.2.3", "192.0.2.1", managed=True).validate()

    def test_v010_managed_flag_migrates_without_changing_resource_ownership(self):
        system = Egress("main", "默认", "eth0", "192.0.2.3", "192.0.2.1").validate()
        external = Egress(
            "external", "外部", "eth1", "198.51.100.3", "198.51.100.1", "108", 18080
        ).validate()
        legacy = Egress(
            "legacy",
            "旧受管",
            "eth1",
            "198.51.100.3",
            "198.51.100.1",
            "108",
            18080,
            managed=True,
            dependency_service="relayaxis-pbr-legacy.service",
        ).validate()
        self.assertEqual((system.management, system.backend), ("system", "system"))
        self.assertEqual((external.management, external.backend), ("external", "external"))
        self.assertEqual((legacy.management, legacy.backend), ("relayaxis", "legacy-oneshot"))
        with self.assertRaises(ValidationError):
            Egress(
                "bad-native",
                "冲突",
                "eth1",
                "198.51.100.3",
                "198.51.100.1",
                "108",
                18080,
                management="external",
                backend="netplan",
                dependency_service="legacy-pbr.service",
            ).validate()

    def test_rule_round_trip(self):
        rule = Rule("日本", "192.0.2.88", 5203, "line", [Binding("::", 5203)])
        self.assertEqual(Rule.from_dict(rule.to_dict()), rule.validate())
