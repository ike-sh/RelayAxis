import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from relayaxis.cli import main, parser, unsuccessful
from relayaxis.menu import menu


class CLITests(unittest.TestCase):
    def test_core_parser_paths(self):
        for argv in (
            ["status"],
            ["doctor"],
            ["ingress", "list"],
            ["egress", "list"],
            ["wg", "list"],
            ["rules", "list"],
            ["sync", "status"],
            ["backup", "create"],
            ["version"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(parser().parse_args(argv).command, argv[0])

    def test_cli_json_and_role_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = ["--root", temp]
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(
                    main(prefix + ["init", "--role", "ingress", "--node-id", "a", "--json"]), 0
                )
                value = json.loads(out.getvalue())
                self.assertEqual(value["role"], "ingress")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(prefix + ["rules", "list", "--json"]), 2)
                self.assertEqual(json.loads(out.getvalue())["state"], "FAILED")

    def test_malformed_input_is_json_error_not_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            main_args = ["--root", temp, "--json"]
            with contextlib.redirect_stdout(io.StringIO()):
                main(main_args + ["init", "--role", "controller", "--node-id", "c"])
            path = Path(temp) / "bad.json"
            path.write_text('{"name":')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(main_args + ["rules", "add", "--file", str(path)]), 2)
                self.assertEqual(json.loads(output.getvalue())["state"], "FAILED")

    def test_json_exit_status_detects_partial_success(self):
        self.assertTrue(unsuccessful({"rule_id": "r", "state": "OUT_OF_SYNC", "ingresses": []}))
        self.assertTrue(unsuccessful({"application": {"state": "FAILED", "error": "no route"}}))
        self.assertFalse(unsuccessful({"state": "PENDING_SYNC", "note": "intent saved"}))

    def test_menu_invalid_selection_returns_and_exits(self):
        with tempfile.TemporaryDirectory() as temp:
            from relayaxis.app import App
            from relayaxis.config import Paths

            app = App(Paths(Path(temp)))
            app.initialize("controller", "test")
            with (
                patch("builtins.input", side_effect=["invalid", "1", "0", "0"]),
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                self.assertEqual(menu(app), 0)
                self.assertIn("无效选项", out.getvalue())
