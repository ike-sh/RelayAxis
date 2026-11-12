import json
import shutil
from pathlib import Path

from . import __version__
from .config import Paths
from .core.deployment import Deployment
from .core.mimic import Mimic
from .core.network import Network
from .core.realm import Compiler
from .core.recovery import Backups
from .core.resources import ResourceFiles
from .core.routing import Routing
from .core.rules import RuleManager
from .core.sync import Coordinator, SSHTransport
from .core.system import Runner, Services, atomic_write, environment
from .core.wireguard import WireGuard
from .errors import ConflictError, ValidationError
from .models import identifier
from .roles.controller import IngressManager
from .storage import Store, canonical


class App:
    def __init__(self, paths=None, runner=None):
        self.paths = paths or Paths()
        self.paths.initialize()
        self.runner = runner or Runner()
        self.store = Store(self.paths.database)
        self.services = Services(self.runner)
        self.network = Network(self.runner)
        self.rules = RuleManager(self.store)
        self.compiler = Compiler(self.store, self.network)
        realm_binary = self.store.runtime("realm-binary", "/usr/local/bin/realm")
        self.deployment = Deployment(self.paths, self.store, self.services, realm_binary)
        self.resources = ResourceFiles(self.paths, self.store, self.services)
        self.routing = Routing(self.paths, self.store, self.network, self.runner, self.services)
        self.wg = WireGuard(self.paths, self.store, self.runner, self.services, self.network)
        self.mimic = Mimic(self.paths, self.store, self.runner, self.services)
        self.backups = Backups(self.paths, self.store, self.runner)
        self.ingresses = IngressManager(self.paths, self.store)
        self.transport = SSHTransport(self.store, self.runner)
        self.coordinator = Coordinator(
            self.paths, self.store, self.compiler, self.deployment, self.transport
        )

    def settings(self):
        path = self.paths.config / "settings.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        if data and data.get("schema") != 1:
            raise ValidationError("配置 schema 不受此版本支持，拒绝覆盖或降级")
        return data

    def initialize(self, role, node_id, realm_binary=None):
        identifier(node_id)
        previous = self.settings()
        if previous and (previous["role"] != role or previous["node_id"] != node_id):
            raise ConflictError("安装角色或节点身份已固定，请保留现有身份或在独立目录部署")
        data = {"schema": 1, "role": role, "node_id": node_id, "version": __version__}
        atomic_write(self.paths.config / "settings.json", canonical(data))
        if realm_binary:
            path = Path(realm_binary)
            if not path.is_absolute():
                raise ValidationError("Realm 可执行文件需要绝对路径")
            self.store.set_runtime("realm-binary", str(path))
        return data

    def require_role(self, role):
        if self.settings().get("role") != role:
            raise ValidationError(
                f"此功能需要 {role} 角色；先运行 ra init --role {role} --node-id <ID>"
            )

    def require_live(self):
        if self.paths.root.resolve() != Path("/"):
            raise ValidationError("--root 隔离目录不能对宿主机应用网络或 systemd 配置")
        self.runner.require_root()
        if not environment()["systemd"]:
            raise ValidationError("应用服务需要运行中的 systemd")

    def status(self):
        rules = self.rules.list()
        return {
            "version": __version__,
            "settings": self.settings(),
            "environment": environment(),
            "rules": [
                {
                    "rule_id": r["rule_id"],
                    "name": r["name"],
                    "revision": r["revision"],
                    "enabled": r["enabled"],
                    "external_service": r["external_service"],
                    "runtime": self.store.runtime(
                        "rule:" + r["rule_id"], {"state": "PENDING_SYNC"}
                    ),
                }
                for r in rules
            ],
            "ingresses": [
                {
                    **s,
                    "sync": self.store.runtime("sync:" + s["server_id"], {"state": "PENDING_SYNC"}),
                }
                for s in self.store.list("server")
            ],
            "egresses": self.store.list("egress"),
            "tunnels": self.store.list("tunnel"),
        }

    def verify_install(self):
        env = environment()
        missing = [
            name for name in ("ip", "ss", "wg", "ssh", "systemctl") if not env["tools"][name]
        ]
        realm = self.store.runtime("realm-binary", "/usr/local/bin/realm")
        if not Path(realm).is_file() and not shutil.which(realm):
            missing.append("realm")
        return {
            "ok": not missing and env["systemd"] and bool(self.settings()),
            "missing": missing,
            "systemd": env["systemd"],
            "settings": self.settings(),
        }
