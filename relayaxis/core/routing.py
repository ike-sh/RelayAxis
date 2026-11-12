import ipaddress
import json
from dataclasses import asdict

from ..errors import ApplyError, ConflictError, ValidationError
from ..models import Egress, new_id, now
from ..storage import canonical
from .network import table_name
from .resources import ResourceFiles
from .system import atomic_write, file_lock


class Routing:
    def __init__(self, paths, store, network, runner, services):
        self.paths, self.store, self.network = paths, store, network
        self.runner, self.services = runner, services

    def save(self, data, updating=False):
        egress = Egress(**data).validate()
        if egress.managed:
            egress.dependency_service = f"relayaxis-pbr-{egress.egress_id}.service"
        with file_lock(self.paths.state / "control.lock"):
            existing = next(
                (e for e in self.store.list("egress") if e["egress_id"] == egress.egress_id), None
            )
            if existing and not updating:
                raise ConflictError("出口 ID 已存在")
            if updating and not existing:
                raise ValidationError("出口不存在")
            if existing and existing["managed"] != egress.managed:
                raise ValidationError("不能把外部出口切换为自建出口或反向切换")
            network_fields = (
                "interface",
                "source",
                "gateway",
                "table",
                "priority",
                "dependency_service",
            )
            if (
                existing
                and any(existing.get(k) != asdict(egress).get(k) for k in network_fields)
                and self._referenced_live(existing)
            ):
                raise ConflictError("出口仍在运行中使用；先禁用并完成关联规则同步，再修改出口参数")
            for other in self.store.list("egress"):
                if other["egress_id"] == egress.egress_id:
                    continue
                if egress.managed and (
                    str(other["table"]) == egress.table or other["priority"] == egress.priority
                ):
                    raise ConflictError("自建出口路由表或优先级已被使用")
            return self.store.put(
                "egress", egress.egress_id, asdict(egress), existing["revision"] if existing else 0
            )

    def _referenced_live(self, egress):
        with self.store.connect() as db:
            manifests = db.execute(
                "SELECT data FROM runtime WHERE key LIKE 'deployment:%'"
            ).fetchall()
        return any(
            endpoint.get("through") == egress["source"]
            and endpoint.get("interface") == egress["interface"]
            for row in manifests
            for endpoint in json.loads(row[0]).values()
        )

    def _commands(self, egress, action):
        # Route tables are exclusive to a managed egress; no replace/flush/main writes.
        source = next(
            a
            for link in self.network.addresses()
            if link["ifname"] == egress.interface
            for a in link.get("addr_info", [])
            if a.get("local") == egress.source
        )
        subnet = str(ipaddress.ip_network(f"{egress.source}/{source['prefixlen']}", strict=False))
        return [
            [
                "ip",
                "-4",
                "route",
                action,
                subnet,
                "dev",
                egress.interface,
                "src",
                egress.source,
                "table",
                egress.table,
                "proto",
                "186",
            ],
            [
                "ip",
                "-4",
                "route",
                action,
                "default",
                "via",
                egress.gateway,
                "dev",
                egress.interface,
                "src",
                egress.source,
                "table",
                egress.table,
                "proto",
                "186",
            ],
            [
                "ip",
                "-4",
                "rule",
                action,
                "priority",
                str(egress.priority),
                "from",
                egress.source + "/32",
                "table",
                egress.table,
                "protocol",
                "186",
            ],
        ]

    def config_path(self, egress_id):
        from ..models import identifier

        identifier(egress_id)
        return self.paths.config / "egress" / f"{egress_id}.json"

    @staticmethod
    def _undo(command):
        result = list(command)
        result[3] = "del"
        return result

    def _remaining(self, commands):
        routes, rules = self.network.routes(), self.network.policy_rules()
        remaining = []
        for command in commands:
            table = command[command.index("table") + 1]
            if command[2] == "route":
                source = command[command.index("src") + 1]
                device = command[command.index("dev") + 1]
                gateway = command[command.index("via") + 1] if "via" in command else ""
                exists = any(
                    table_name(r.get("table", "main")) == table
                    and r.get("dst") == command[4]
                    and str(r.get("protocol")) == "186"
                    and r.get("dev") == device
                    and r.get("gateway", "") == gateway
                    and r.get("prefsrc", r.get("src", source)) == source
                    for r in routes
                )
            else:
                source = command[command.index("from") + 1].removesuffix("/32")
                priority = int(command[command.index("priority") + 1])
                exists = any(
                    r.get("priority") == priority
                    and table_name(r.get("table")) == table
                    and r.get("src") in (source, source + "/32")
                    and str(r.get("protocol")) == "186"
                    for r in rules
                )
            if exists:
                remaining.append(command)
        return remaining

    def activate(self, egress_id, from_config=False):
        """Apply/repair only an exclusive, protocol-tagged source routing table."""
        self.runner.require_root()
        with file_lock(self.paths.state / "pbr-activate.lock"):
            directory = self.paths.state / "routing-journals"
            if any(directory.glob("*.json")):
                raise ApplyError("策略路由有未完成事务，请先 recovery repair")
            data = (
                json.loads(self.config_path(egress_id).read_text(encoding="utf-8"))
                if from_config
                else self.store.get("egress", egress_id)
            )
            egress = Egress(**data).validate()
            if not egress.managed:
                raise ValidationError("外部 PBR 只读复用，不能激活或重建")
            if not self.network.source_present(egress):
                raise ValidationError("出口源地址不存在，拒绝创建策略路由")
            commands = self._commands(egress, "add")
            routes = [
                r
                for r in self.network.routes()
                if table_name(r.get("table", "main")) == egress.table
            ]
            rules = [r for r in self.network.policy_rules() if r.get("priority") == egress.priority]
            previous = self.store.runtime("pbr:" + egress_id, {})
            if (routes or rules) and not previous:
                raise ConflictError("路由表或优先级已存在外部配置，拒绝覆盖")
            subnet = commands[0][4]
            found = set()
            for route in routes:
                index = 1 if route.get("dst") == "default" else 0
                if (
                    route.get("dst") not in (subnet, "default")
                    or str(route.get("protocol")) != "186"
                    or route.get("dev") != egress.interface
                    or route.get("prefsrc", route.get("src", egress.source)) != egress.source
                    or route.get("gateway", "") != (egress.gateway if index else "")
                    or index in found
                ):
                    raise ConflictError("受管表有外部或被更改的路由，拒绝清理或覆盖")
                found.add(index)
            for rule in rules:
                if (
                    rule.get("src") not in (egress.source, egress.source + "/32")
                    or table_name(rule.get("table")) != egress.table
                    or str(rule.get("protocol")) != "186"
                    or any(k in rule for k in ("fwmark", "ipproto", "dport", "sport", "iif", "oif"))
                    or 2 in found
                ):
                    raise ConflictError("受管优先级出现外部策略，拒绝删除或覆盖")
                found.add(2)
            missing = [command for index, command in enumerate(commands) if index not in found]
            identity = new_id()
            journal = {
                "id": identity,
                "operation": "add",
                "egress_id": egress_id,
                "commands": missing,
                "previous": previous,
            }
            path = directory / f"{identity}.json"
            atomic_write(path, canonical(journal))
            applied = []
            try:
                for command in missing:
                    self.runner.run(command)
                    applied.append(command)
                with self.store.transaction() as db:
                    self.store.set_runtime(
                        "pbr:" + egress_id,
                        {"egress": asdict(egress), "commands": commands, "at": now()},
                        db,
                    )
                    self.store.set_runtime("routing-commit:" + identity, True, db)
            except Exception as exc:
                errors = []
                for command in reversed(applied):
                    if self.runner.run(self._undo(command), check=False).returncode:
                        errors.append(command)
                if not errors:
                    path.unlink()
                raise ApplyError(
                    "策略路由创建失败，已撤回本次变更；未完成事务会保留恢复日志"
                ) from exc
            path.unlink()
            return {"state": "ACTIVE", "changed": bool(missing)}

    def deactivate(self, egress_id):
        self.runner.require_root()
        with file_lock(self.paths.state / "pbr-activate.lock"):
            old = self.store.runtime("pbr:" + egress_id, {})
            if not old:
                return {"state": "DISABLED", "changed": False}
            if not Egress(**old["egress"]).validate().managed:
                raise ValidationError("拒绝删除外部策略路由")
            commands = old.get("commands") or self._commands(Egress(**old["egress"]), "add")
            identity = new_id()
            journal = {
                "id": identity,
                "operation": "del",
                "egress_id": egress_id,
                "commands": commands,
                "previous": old,
            }
            path = self.paths.state / "routing-journals" / f"{identity}.json"
            atomic_write(path, canonical(journal))
            for command in reversed(commands):
                result = self.runner.run(self._undo(command), check=False)
                # ip returns 2 for an already absent exact entry; no broad flush occurs.
                if result.returncode not in (0, 2):
                    raise ApplyError("策略路由撤销失败，保留精确恢复日志")
            if self._remaining(commands):
                raise ApplyError("内核仍保留受管路由，撤销未完成；已保留恢复日志")
            with self.store.transaction() as db:
                self.store.set_runtime("pbr:" + egress_id, {}, db)
                self.store.set_runtime("routing-commit:" + identity, True, db)
            path.unlink()
            return {"state": "DISABLED"}

    def recover(self):
        reports = []
        with file_lock(self.paths.state / "pbr-activate.lock"):
            for path in sorted((self.paths.state / "routing-journals").glob("*.json")):
                journal = json.loads(path.read_text(encoding="utf-8"))
                if not self.store.runtime("routing-commit:" + journal["id"]):
                    # Both undo an incomplete add and finish an incomplete delete.
                    for command in reversed(journal["commands"]):
                        if (
                            command[:3] not in (["ip", "-4", "route"], ["ip", "-4", "rule"])
                            or "186" not in command
                            or "table" not in command
                            or command[command.index("table") + 1] in ("main", "253", "254", "255")
                        ):
                            raise ApplyError("路由恢复日志包含非受管命令")
                        result = self.runner.run(self._undo(command), check=False)
                        if result.returncode not in (0, 2):
                            raise ApplyError("路由事务恢复失败，已保留日志")
                    if self._remaining(journal["commands"]):
                        raise ApplyError("路由恢复后仍有受管条目，拒绝提交成功状态")
                    self.store.set_runtime(
                        "pbr:" + journal["egress_id"],
                        journal["previous"] if journal["operation"] == "add" else {},
                    )
                path.unlink()
                reports.append(path.name)
        return reports

    def apply(self, egress_id):
        self.runner.require_root()
        with file_lock(self.paths.state / "routing.lock"):
            egress = Egress(**self.store.get("egress", egress_id)).validate()
            if not egress.managed:
                return {"state": "EXTERNAL", "note": "保留已有服务和路由，请使用 egress check 验证"}
            if not self.network.source_present(egress):
                raise ValidationError("出口源地址不存在")
            unit = f"relayaxis-pbr-{egress_id}.service"
            unit_path, config = self.paths.units / unit, self.config_path(egress_id)
            owned = self.store.runtime("pbr-unit:" + egress_id)
            if (unit_path.exists() or config.exists()) and not owned:
                raise ConflictError("拒绝覆盖未登记的 PBR 配置或服务")
            original = json.loads(config.read_text(encoding="utf-8")) if config.exists() else {}
            fields = ("interface", "source", "gateway", "table", "priority")
            same_network = original and all(
                original.get(k) == asdict(egress).get(k) for k in fields
            )
            if original and not same_network and self._referenced_live(original):
                raise ConflictError("旧出口仍有活动监听，先禁用关联业务")
            resource = ResourceFiles(self.paths, self.store, self.services)
            state = self.services.state(unit)
            with resource.transaction(unit, [config, unit_path]) as identity:
                if state["active"] and not same_network:
                    self.services.action("stop", unit)
                atomic_write(config, canonical(asdict(egress)))
                atomic_write(
                    unit_path,
                    f"""# Managed by RelayAxis
[Unit]
Description=RelayAxis PBR {egress_id}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ra --json egress activate {egress_id} --from-config
ExecStop=/usr/local/bin/ra --json egress deactivate {egress_id}
ExecStopPost=-/usr/local/bin/ra --json egress deactivate {egress_id}

[Install]
WantedBy=multi-user.target
""",
                )
                self.services.daemon_reload()
                self.services.action("enable", unit)
                if same_network and state["active"]:
                    self.activate(egress_id, from_config=True)
                else:
                    self.services.action("start", unit)
                if not self.services.healthy(unit):
                    raise ApplyError("PBR 服务启动失败")
                self.activate(egress_id, from_config=True)
                resource.commit(
                    identity,
                    lambda db: self.store.set_runtime("pbr-unit:" + egress_id, {"unit": unit}, db),
                )
            return {"state": "ACTIVE", "dependency_service": unit}

    def delete(self, egress_id):
        if any(
            r["egress_id"] == egress_id
            and (
                not r.get("deleted")
                or self.store.runtime("rule:" + r["rule_id"], {}).get("state") != "DISABLED"
            )
            for r in self.store.list("rule")
        ):
            raise ConflictError("出口仍有关联规则")
        egress = Egress(**self.store.get("egress", egress_id)).validate()
        if self._referenced_live(asdict(egress)):
            raise ConflictError("仍有本机保留的旧监听使用该出口")
        if not egress.managed:
            self.store.remove("egress", egress_id)
            return {"deleted": egress_id, "external_preserved": True}
        self.runner.require_root()
        with file_lock(self.paths.state / "routing.lock"):
            unit = self.store.runtime("pbr-unit:" + egress_id, {}).get("unit")
            if unit:
                resource = ResourceFiles(self.paths, self.store, self.services)
                with resource.transaction(
                    unit, [self.config_path(egress_id), self.paths.units / unit]
                ) as identity:
                    self.services.action("stop", unit)
                    self.services.action("disable", unit)
                    self.deactivate(egress_id)
                    (self.paths.units / unit).unlink(missing_ok=True)
                    self.config_path(egress_id).unlink(missing_ok=True)
                    self.services.daemon_reload()

                    def commit(db):
                        self.store.remove("egress", egress_id, db)
                        self.store.set_runtime("pbr-unit:" + egress_id, {}, db)

                    resource.commit(identity, commit)
            else:
                self.deactivate(egress_id)
                self.store.remove("egress", egress_id)
        return {"deleted": egress_id, "external_preserved": False}
