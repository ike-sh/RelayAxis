import base64
import json
from dataclasses import asdict

from relayaxis.config import Paths
from relayaxis.core.deployment import Deployment
from relayaxis.core.realm import Compiler
from relayaxis.core.rules import RuleManager
from relayaxis.core.sync import Agent, Coordinator
from relayaxis.core.system import Result
from relayaxis.errors import ApplyError, SystemError
from relayaxis.models import Binding, Egress, Rule, Server, Tunnel
from relayaxis.storage import Store

KEY = base64.b64encode(b"a" * 32).decode()
PEER_KEY = base64.b64encode(b"b" * 32).decode()


class FakeServices:
    def __init__(self):
        self.states = {}
        self.calls = []
        self.fail_start = set()
        self.fail_next = False

    def state(self, unit):
        return dict(self.states.get(unit, {"active": False, "enabled": False}))

    def daemon_reload(self):
        self.calls.append(("daemon-reload", ""))

    def action(self, action, unit):
        self.calls.append((action, unit))
        if action == "start" and (unit in self.fail_start or self.fail_next):
            self.fail_next = False
            raise SystemError("injected start failure")
        state = self.states.setdefault(unit, {"active": False, "enabled": False})
        if action in ("start", "restart", "stop"):
            state["active"] = action != "stop"
        if action in ("enable", "disable"):
            state["enabled"] = action == "enable"

    def healthy(self, unit):
        return self.state(unit)["active"]


class FakeNetwork:
    def __init__(self):
        self.invalid = False
        self.missing_addresses = set()

    def resolve4(self, host):
        return ["192.0.2.80" if host == "target.example" else host]

    def validate_egress(self, *args):
        if self.invalid:
            from relayaxis.errors import ValidationError

            raise ValidationError("injected wrong egress")
        return [{"dev": "eth0", "gateway": "192.0.2.1"}]

    def ensure_local_listen(self, address):
        if address in self.missing_addresses:
            from relayaxis.errors import ValidationError

            raise ValidationError("injected unavailable interface")

    def addresses(self):
        return []


class FakeRunner:
    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def require_root(self):
        pass

    def require_linux(self):
        pass

    def run(self, argv, *, input=None, timeout=15, check=True):
        self.calls.append(list(argv))
        if argv[:2] == ["wg", "genkey"]:
            return Result(stdout=KEY + "\n")
        if argv[:2] == ["wg", "pubkey"]:
            return Result(stdout=PEER_KEY + "\n")
        value = self.answers.get(tuple(argv), Result())
        if isinstance(value, Exception):
            raise value
        return value

    def json(self, argv):
        result = self.run(argv)
        return json.loads(result.stdout or "[]")


class Lab:
    def __init__(self, root):
        self.paths = Paths(root)
        self.paths.initialize()
        self.store = Store(self.paths.database)
        self.services = FakeServices()
        self.network = FakeNetwork()
        self.deployment = Deployment(
            self.paths, self.store, self.services, bind_check=lambda e: None
        )
        self.rules = RuleManager(self.store)
        self.compiler = Compiler(self.store, self.network)
        self.store.put(
            "egress", "line-a", asdict(Egress("line-a", "A", "eth0", "192.0.2.10", "192.0.2.1")), 0
        )

    def add_server(self, name, index):
        tunnel = Tunnel(
            name,
            f"ra-{name}",
            "controller",
            f"10.203.{index}.1/30",
            f"10.203.{index}.2/30",
            endpoint=f"198.51.100.{index}:51820",
            public_key=KEY,
            peer_public_key=PEER_KEY,
        )
        self.store.put("tunnel", name, asdict(tunnel), 0)
        server = Server(name, name, f"198.51.100.{index}", name)
        self.store.put("server", name, asdict(server), 0)

    def rule(self, number=12345, servers=(), protocol="both"):
        return self.rules.create(
            Rule(
                "test",
                "192.0.2.80",
                443,
                "line-a",
                [Binding("::", number)] + [Binding("0.0.0.0", number, name) for name in servers],
                protocol=protocol,
            ).to_dict()
        )


class LabTransport:
    def __init__(self, labs):
        self.agents = {}
        self.offline = set()
        self.events = []
        for name, lab, index in labs:
            policy = {
                "server_id": name,
                "tunnel_id": name,
                "listen_addresses": ["0.0.0.0"],
                "controller_wg_address": f"10.203.{index}.1",
                "ingress_wg_address": f"10.203.{index}.2",
                "wg_interface": f"ra-{name}",
            }
            self.agents[name] = Agent(lab.store, lab.deployment, policy)

    def send(self, server, snapshot):
        name = server["server_id"]
        self.events.append((name, snapshot))
        if name in self.offline:
            raise ApplyError("injected offline")
        return self.agents[name].receive(snapshot)


def coordinator(lab, transport):
    return Coordinator(lab.paths, lab.store, lab.compiler, lab.deployment, transport)
