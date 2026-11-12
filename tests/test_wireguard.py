import tempfile
import unittest
from pathlib import Path

from relayaxis.core.wireguard import (
    WireGuard,
    accept_pairing,
    allocate_subnet,
    pairing_bundle,
    render,
)
from relayaxis.errors import ConflictError, ValidationError
from relayaxis.models import Tunnel

from .helpers import KEY, PEER_KEY, FakeRunner, Lab


class WireGuardTests(unittest.TestCase):
    def tunnel(self, role="controller"):
        return Tunnel(
            "a",
            "ra-a",
            role,
            "10.203.0.1/30",
            "10.203.0.2/30",
            endpoint="198.51.100.10:51820" if role == "controller" else "",
            public_key=KEY,
            peer_public_key=PEER_KEY,
        )

    def test_nat_direction_keepalive_and_only_peer_host_route(self):
        text = render(self.tunnel(), KEY)
        self.assertIn("Endpoint = 198.51.100.10:51820", text)
        self.assertIn("PersistentKeepalive = 25", text)
        self.assertIn("Table = off", text)
        self.assertIn("AllowedIPs = 10.203.0.2/32", text)
        self.assertNotIn("0.0.0.0/0", text)
        listener = render(self.tunnel("ingress"), KEY)
        self.assertNotIn("Endpoint", listener)
        self.assertNotIn("PersistentKeepalive", listener)

    def test_pairing_never_contains_private_key_and_checks_roles_addresses(self):
        c = self.tunnel()
        i = self.tunnel("ingress")
        i.local_address, i.peer_address = c.peer_address, c.local_address
        bundle = pairing_bundle(c)
        self.assertNotIn("private", str(bundle).lower())
        self.assertEqual(accept_pairing(i, bundle).peer_public_key, KEY)
        with self.assertRaises(ValidationError):
            accept_pairing(c, bundle)
        bundle["payload"]["private_key"] = "sensitive"
        with self.assertRaises(ValidationError):
            accept_pairing(i, bundle)

    def test_allocator_avoids_existing_networks(self):
        allocated = allocate_subnet(["10.203.0.0/30", "10.203.0.4/30"])
        self.assertEqual(allocated["subnet"], "10.203.0.8/30")
        with self.assertRaises(ConflictError):
            allocate_subnet(["10.203.0.0/30"], "10.203.0.0/30")

    def test_repeated_create_does_not_rotate_private_key(self):
        with tempfile.TemporaryDirectory() as temp:
            lab = Lab(Path(temp))
            runner = FakeRunner()
            manager = WireGuard(lab.paths, lab.store, runner, lab.services, lab.network)
            data = self.tunnel().__dict__.copy()
            manager.create(data)
            before = manager.key_path("a").read_bytes()
            with self.assertRaises(ConflictError):
                manager.create(data)
            self.assertEqual(manager.key_path("a").read_bytes(), before)
            self.assertEqual(sum(c == ["wg", "genkey"] for c in runner.calls), 1)

    def test_independent_tunnels_reject_duplicate_listen_port_and_auto_allocate(self):
        with tempfile.TemporaryDirectory() as temp:
            lab = Lab(Path(temp))
            manager = WireGuard(lab.paths, lab.store, FakeRunner(), lab.services, lab.network)
            first = self.tunnel().__dict__.copy()
            manager.create(first)
            second = {
                **first,
                "tunnel_id": "b",
                "interface": "ra-b",
                "local_address": "10.203.1.1/30",
                "peer_address": "10.203.1.2/30",
            }
            with self.assertRaises(ConflictError):
                manager.create(second)
            second.pop("listen_port")
            created = manager.create(second)
            self.assertNotEqual(created["listen_port"], first["listen_port"])
