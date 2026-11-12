import json
import tempfile
import unittest
from pathlib import Path

from relayaxis.core.wg_link import WireGuardLink, load_config
from relayaxis.core.wireguard import render
from relayaxis.errors import ApplyError, ConflictError, SystemError, ValidationError
from relayaxis.models import Tunnel

from .helpers import KEY, PEER_KEY, FakeRunner, Lab


class KernelRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.links = []
        self.fail_setconf = False
        self.key_input = ""

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        from relayaxis.core.system import Result

        if argv == ["ip", "-j", "-d", "link", "show"]:
            return Result(stdout=json.dumps(self.links))
        if argv[:3] == ["ip", "link", "add"]:
            self.links.append(
                {
                    "ifname": argv[argv.index("dev") + 1],
                    "ifalias": argv[argv.index("alias") + 1],
                    "flags": [],
                }
            )
        if argv[:3] == ["ip", "link", "set"]:
            self.links[0]["flags"] = ["UP"]
        if argv[:3] == ["ip", "link", "delete"]:
            self.links = []
        if argv[:2] == ["wg", "setconf"]:
            if self.fail_setconf:
                raise SystemError("injected setconf failure")
            self.key_input = kwargs["input"]
        return Result()


class NativeWireGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name))
        self.runner = KernelRunner()
        self.link = WireGuardLink(self.runner, self.lab.store)
        self.tunnel = Tunnel(
            "a",
            "ra-a",
            "controller",
            "10.203.0.1/30",
            "10.203.0.2/30",
            endpoint="198.51.100.8:51820",
            public_key=KEY,
            peer_public_key=PEER_KEY,
        )

    def test_native_up_uses_stdin_host_route_and_unique_ownership_alias(self):
        self.link.up(self.tunnel, KEY)
        self.assertIn("PrivateKey = " + KEY, self.runner.key_input)
        self.assertNotIn(KEY, " ".join(" ".join(c) for c in self.runner.calls))
        self.assertFalse(any("0.0.0.0/0" in c or "wg-quick" in c for c in self.runner.calls))
        self.assertTrue(self.runner.links[0]["ifalias"].startswith("relayaxis:a:"))
        self.link.down("a", "ra-a")
        self.assertEqual(self.runner.links, [])

    def test_failed_setconf_cleans_only_just_created_interface(self):
        self.runner.fail_setconf = True
        with self.assertRaises(ApplyError):
            self.link.up(self.tunnel, KEY)
        self.assertEqual(self.runner.links, [])
        self.assertEqual(self.lab.store.runtime("wg-owner:a"), {})

    def test_external_interface_is_never_deleted_or_overwritten(self):
        self.runner.links = [{"ifname": "ra-a", "ifalias": "external", "flags": ["UP"]}]
        with self.assertRaises(ConflictError):
            self.link.up(self.tunnel, KEY)
        self.assertFalse(any("delete" in c or "setconf" in c for c in self.runner.calls))

    def test_wg_quick_data_roundtrip_rejects_hooks_and_default_allowed_routes(self):
        config = render(self.tunnel, KEY)
        tunnel, private = load_config(config, self.tunnel.__dict__)
        self.assertEqual(tunnel.local_address, "10.203.0.1/32")
        self.assertEqual(private, KEY)
        for invalid in (
            config.replace("Table = off", "Table = off\nPostUp = arbitrary"),
            config.replace("10.203.0.2/32", "0.0.0.0/0"),
        ):
            with self.assertRaises(ValidationError):
                load_config(invalid, self.tunnel.__dict__)
