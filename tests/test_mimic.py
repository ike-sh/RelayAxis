import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from relayaxis.core.mimic import Mimic
from relayaxis.core.system import Result
from relayaxis.errors import ApplyError, ValidationError

from .helpers import FakeRunner, Lab


class MimicTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Lab(Path(self.temp.name))
        self.lab.add_server("a", 1)
        self.runner = FakeRunner({("mimic", "--version"): Result(stdout="mimic-test-1\n")})
        self.mimic = Mimic(self.lab.paths, self.lab.store, self.runner, self.lab.services)
        self.mimic.configure("a", "eth0", "198.51.100.1", 51820)

    def test_failed_prerequisites_keep_native_wg(self):
        with patch.object(self.mimic, "check", return_value={"prerequisites_ok": False}):
            with self.assertRaises(ValidationError):
                self.mimic.toggle("a", True)
        self.assertFalse(self.lab.services.state("relayaxis-mimic-a.service")["active"])

    def test_generated_filter_is_specific_and_no_offload_or_kernel_upgrade(self):
        with patch.object(self.mimic, "check", return_value={"prerequisites_ok": True, "link": []}):
            result = self.mimic.toggle("a", True)
        self.assertTrue(result["enabled"])
        self.assertFalse(result["verified_pair"])
        text = (self.lab.paths.config / "mimic/a.conf").read_text()
        self.assertIn("filter = remote=198.51.100.1:51820", text)
        self.assertFalse(
            any("ethtool" in c or "sysctl" in c or "upgrade" in c for c in self.runner.calls)
        )

    def test_dual_end_mismatch_is_error(self):
        class Remote:
            def request(self, *args):
                return {"enabled": True, "version": "other", "xdp_mode": "native"}

        with self.assertRaises(ApplyError):
            self.mimic.verify_pair("a", Remote())
