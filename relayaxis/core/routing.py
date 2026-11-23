import hashlib
import ipaddress
import json
import re
from dataclasses import asdict

from ..errors import ApplyError, ConflictError, RelayAxisError, ValidationError
from ..models import Egress, EgressHealth, PersistenceBackend, identifier, new_id, now
from ..storage import canonical
from .network import table_name
from .persistence import PersistenceManager
from .resources import ResourceFiles
from .system import atomic_write, file_lock


class Routing:
    def __init__(self, paths, store, network, runner, services):
        self.paths, self.store, self.network = paths, store, network
        self.runner, self.services = runner, services
        self.persistence = PersistenceManager(paths, store, network, runner, services)

    def save(self, data, updating=False):
        egress = Egress(**data).validate()
        with file_lock(self.paths.state / "control.lock"):
            existing_raw = next(
                (e for e in self.store.list("egress") if e["egress_id"] == egress.egress_id), None
            )
            existing = Egress(**existing_raw).validate() if existing_raw else None
            if existing and not updating:
                raise ConflictError("出口 ID 已存在")
            if updating and not existing:
                raise ValidationError("出口不存在")
            if existing and existing.management != egress.management:
                raise ValidationError("不能通过普通更新改变出口资源所有权")
            if not existing and egress.backend == PersistenceBackend.LEGACY_ONESHOT:
                raise ValidationError("新出口必须使用原生网络持久化后端")
            network_fields = (
                "interface",
                "source",
                "gateway",
                "table",
                "priority",
                "dependency_service",
                "management",
                "backend",
            )
            network_changed = bool(
                existing
                and any(asdict(existing).get(k) != asdict(egress).get(k) for k in network_fields)
            )
            if network_changed and self.store.runtime("persistence:" + egress.egress_id, {}):
                raise ConflictError(
                    "原生 PBR 已应用；先用带 plan-id 的出口删除流程撤销，再重建参数"
                )
            if network_changed and self._referenced_live(asdict(existing)):
                raise ConflictError("出口仍在运行中使用；先禁用并完成关联规则同步，再修改出口参数")
            for other_raw in self.store.list("egress"):
                other = Egress(**other_raw).validate()
                if other.egress_id == egress.egress_id:
                    continue
                if egress.managed and (
                    str(other.table) == egress.table or other.priority == egress.priority
                ):
                    raise ConflictError("自建出口路由表或优先级已被使用")
            return self.store.put(
                "egress",
                egress.egress_id,
                asdict(egress),
                existing.revision if existing else 0,
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
            if egress.backend != PersistenceBackend.LEGACY_ONESHOT:
                raise ValidationError("activate 仅供 v0.1.0 旧 PBR 单元兼容调用")
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
            legacy = Egress(**old["egress"]).validate()
            if not legacy.managed:
                raise ValidationError("拒绝删除外部策略路由")
            if legacy.backend != PersistenceBackend.LEGACY_ONESHOT:
                raise ValidationError("deactivate 仅清理 v0.1.0 旧 PBR 条目")
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

    def _recover_legacy(self):
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

    def recover(self):
        with file_lock(self.paths.state / "routing.lock"):
            native = self.persistence.recover()
            return {
                "legacy_kernel": self._recover_legacy(),
                "native_persistence": native,
                "pbr_migrations": self._recover_pbr_migrations(),
            }

    def _recover_pbr_migrations(self):
        reports = []
        for path in sorted((self.paths.state / "pbr-migrations").glob("*.json")):
            if path.is_symlink():
                raise ApplyError("PBR 迁移日志不能是符号链接")
            journal = json.loads(path.read_text(encoding="utf-8"))
            if not re.fullmatch(r"[0-9a-f]{16}", path.stem) or journal.get("id") != path.stem:
                raise ApplyError("PBR 迁移日志身份异常")
            egress_id = journal.get("egress_id", "")
            unit = journal.get("unit", "")
            try:
                identifier(egress_id)
            except ValidationError as exc:
                raise ApplyError("PBR 迁移日志出口身份异常") from exc
            if unit != f"relayaxis-pbr-{egress_id}.service":
                raise ApplyError("PBR 迁移日志含非受管服务")
            runtime = self.store.runtime("persistence:" + egress_id, {})
            if not runtime:
                # Native apply either never began or was rolled back by its own
                # journal. The enabled legacy unit remains the owner.
                path.unlink()
                reports.append({"egress_id": egress_id, "state": "LEGACY_PRESERVED"})
                continue
            egress = Egress(**self.store.get("egress", egress_id)).validate()
            updated = Egress(
                **{
                    **asdict(egress),
                    "backend": runtime["backend"],
                    "dependency_service": "",
                }
            ).validate()
            with self.store.transaction() as db:
                if (
                    egress.backend != updated.backend
                    or egress.dependency_service != updated.dependency_service
                ):
                    self.store.put("egress", egress_id, asdict(updated), egress.revision, db)
                previous = self.store.runtime("legacy-pbr:" + egress_id, {}, db)
                self.store.set_runtime(
                    "legacy-pbr:" + egress_id,
                    {
                        **previous,
                        "unit": unit,
                        "native_staged": True,
                        "staged_at": now(),
                        "recovered": True,
                    },
                    db,
                )
            reverse, dependents = self._legacy_dependencies(unit)
            if reverse.returncode or dependents:
                atomic_write(
                    path,
                    canonical(
                        {
                            **journal,
                            "phase": "AWAITING_REALM_RECONCILE",
                            "remaining_dependencies": dependents,
                        }
                    ),
                )
                reports.append(
                    {
                        "egress_id": egress_id,
                        "state": "REALM_RECONCILE_REQUIRED",
                        "remaining_dependencies": dependents,
                    }
                )
                continue
            if self.services.state(unit)["enabled"]:
                self.services.action("disable", unit)
            with self.store.transaction() as db:
                previous = self.store.runtime("legacy-pbr:" + egress_id, {}, db)
                self.store.set_runtime(
                    "legacy-pbr:" + egress_id,
                    {
                        **previous,
                        "disabled_without_stop": True,
                        "migrated_at": now(),
                        "native_staged": False,
                    },
                    db,
                )
                self.store.set_runtime("pbr:" + egress_id, {}, db)
                self.store.set_runtime("pbr-unit:" + egress_id, {}, db)
                self.store.set_runtime("pbr-migration-plan:" + egress_id, {}, db)
            path.unlink()
            reports.append({"egress_id": egress_id, "state": "NATIVE_FINALIZED"})
        return reports

    def health(self, egress_id, target="198.51.100.1", port=443, protocol="tcp"):
        egress = Egress(**self.store.get("egress", egress_id)).validate()
        try:
            report = self.network.egress_health(egress, target, port, protocol)
        except (RelayAxisError, OSError, ValueError, TypeError, KeyError) as exc:
            report = {
                "egress_id": egress_id,
                "status": EgressHealth.UNKNOWN,
                "ok": False,
                "target": target,
                "checks": {},
                "error": type(exc).__name__,
            }
        previous = self.store.runtime("egress-health:" + egress_id, {})
        current = {
            **report,
            "management": egress.management,
            "backend": egress.backend,
            "checked_at": now(),
        }
        if report["status"] != EgressHealth.HEALTHY:
            current["last_error"] = {
                "status": report["status"],
                "at": current["checked_at"],
                "error": report.get("error", ""),
            }
        elif previous.get("last_error"):
            current["last_error"] = previous["last_error"]
        self.store.set_runtime("egress-health:" + egress_id, current)
        return current

    def list_status(self, target="198.51.100.1", port=443):
        result = []
        for data in self.store.list("egress"):
            egress = Egress(**data).validate()
            try:
                health = self.health(egress.egress_id, target, port)
            except Exception as exc:
                health = {
                    "status": EgressHealth.UNKNOWN,
                    "ok": False,
                    "error": type(exc).__name__,
                }
            result.append({**asdict(egress), "health": health})
        return result

    def backend_status(self, egress_id):
        egress = Egress(**self.store.get("egress", egress_id)).validate()
        return self.persistence.status(egress)

    def plan(self, egress_id, migration=False):
        egress = Egress(**self.store.get("egress", egress_id)).validate()
        return self.persistence.plan(egress, migration=migration, allow_existing=migration)

    def apply(self, egress_id, confirm=False, plan_id=""):
        egress = Egress(**self.store.get("egress", egress_id)).validate()
        if not egress.managed:
            return {
                "state": "SYSTEM" if egress.management == "system" else "EXTERNAL",
                "management": egress.management,
                "note": "复用并验证现有路由，不改变其配置",
            }
        if egress.backend == PersistenceBackend.LEGACY_ONESHOT:
            audit = self.audit_legacy(egress_id)
            result = {
                "state": "MIGRATION_REQUIRED",
                "audit": audit,
            }
            if audit["safe_migration"]:
                result["plan"] = self.plan(egress_id, migration=True)
            return result
        if not confirm:
            return self.plan(egress_id)
        with file_lock(self.paths.state / "routing.lock"):
            result = self.persistence.apply(egress, plan_id)
            selected = result["backend"]
            updated = Egress(
                **{
                    **asdict(egress),
                    "backend": selected,
                    "dependency_service": "",
                }
            ).validate()
            self.store.put("egress", egress_id, asdict(updated), egress.revision)
        return result

    def _legacy_dependencies(self, unit):
        reverse = self.runner.run(
            ["systemctl", "list-dependencies", "--reverse", unit, "--plain", "--no-pager"],
            check=False,
        )
        dependents = sorted(
            {
                value.strip().lstrip("●").strip()
                for value in reverse.stdout.splitlines()
                if value.strip().endswith(".service") and value.strip().lstrip("●").strip() != unit
            }
        )
        return reverse, dependents

    def audit_legacy(self, egress_id):
        egress = Egress(**self.store.get("egress", egress_id)).validate()
        unit = egress.dependency_service or self.store.runtime("pbr-unit:" + egress_id, {}).get(
            "unit", ""
        )
        if not unit:
            return {
                "egress_id": egress_id,
                "legacy": False,
                "safe_migration": False,
                "reason": "未登记旧 PBR 服务",
            }
        state = self.services.state(unit)
        cat = self.runner.run(["systemctl", "cat", unit, "--no-pager"], check=False)
        reverse, dependents = self._legacy_dependencies(unit)
        text = cat.stdout
        starts = re.findall(r"(?m)^ExecStart\s*=\s*(.+)$", text)
        stops = re.findall(r"(?m)^ExecStop(?:Post)?\s*=\s*(.+)$", text)
        start_text = "\n".join(starts)
        direct_commands = bool(starts) and all(
            re.search(r"(?:^|/)ip\s+-4\s+(?:rule|route)\s+(?:add|replace)\b", command)
            for command in starts
        )
        direct_match = direct_commands and all(
            item in start_text
            for item in (
                egress.interface,
                egress.source,
                egress.gateway,
                egress.table,
                str(egress.priority),
            )
        )
        internal_commands = bool(starts) and all(
            re.search(rf"(?:^|\s)egress\s+activate\s+{re.escape(egress_id)}(?:\s|$)", command)
            and "--from-config" in command
            for command in starts
        )
        config_matches = False
        config = self.config_path(egress_id)
        if internal_commands and config.is_file() and not config.is_symlink():
            try:
                configured = Egress(**json.loads(config.read_text(encoding="utf-8"))).validate()
                fields = ("egress_id", "interface", "source", "gateway", "table", "priority")
                config_matches = all(
                    getattr(configured, field) == getattr(egress, field) for field in fields
                )
            except (OSError, ValueError, TypeError, ValidationError):
                config_matches = False
        expected = direct_match or (internal_commands and config_matches)
        start_mode = "direct-ip" if direct_match else "relayaxis-v0.1.0" if expected else "unknown"
        owned = bool(
            unit == f"relayaxis-pbr-{egress_id}.service"
            and self.store.runtime("pbr-unit:" + egress_id)
        )
        external_dependents = [
            value
            for value in dependents
            if not re.fullmatch(r"relayaxis-realm-[a-zA-Z0-9_-]+\.service", value)
        ]
        native_backend = self.persistence.detect(
            Egress(**{**asdict(egress), "backend": "auto", "dependency_service": ""}).validate()
        )
        return {
            "egress_id": egress_id,
            "legacy": True,
            "unit": unit,
            "active": state["active"],
            "enabled": state["enabled"],
            "exec_start": starts,
            "exec_start_mode": start_mode,
            "exec_stop": stops,
            "exec_stop_destructive": any(
                " rule del " in f" {command} "
                or " route flush " in f" {command} "
                or bool(
                    re.search(
                        rf"(?:^|\s)egress\s+deactivate\s+{re.escape(egress_id)}(?:\s|$)",
                        command,
                    )
                )
                for command in stops
            ),
            "reverse_dependencies": dependents,
            "external_dependencies": external_dependents,
            "matches_egress": expected,
            "config_matches_egress": config_matches,
            "owned": owned,
            "safe_migration": bool(
                egress.managed
                and owned
                and expected
                and cat.returncode == 0
                and reverse.returncode == 0
                and not external_dependents
                and native_backend["selected"]
                in (PersistenceBackend.NETPLAN.value, PersistenceBackend.NETWORKD.value)
            ),
            "native_backend": native_backend,
            "note": "Realm 反向依赖清零后只禁用旧单元，不调用可能清理新路由的 ExecStop",
        }

    @staticmethod
    def _audit_fingerprint(audit):
        material = {
            key: audit.get(key)
            for key in (
                "unit",
                "enabled",
                "exec_start",
                "exec_stop",
                "reverse_dependencies",
                "matches_egress",
                "config_matches_egress",
                "owned",
                "safe_migration",
            )
        }
        return hashlib.sha256(canonical(material).encode()).hexdigest()

    def _pending_migration(self, egress_id):
        for path in sorted((self.paths.state / "pbr-migrations").glob("*.json")):
            if path.is_symlink():
                raise ApplyError("PBR 迁移日志不能是符号链接")
            journal = json.loads(path.read_text(encoding="utf-8"))
            if not re.fullmatch(r"[0-9a-f]{16}", path.stem) or journal.get("id") != path.stem:
                raise ApplyError("PBR 迁移日志身份异常")
            if journal.get("egress_id") == egress_id:
                return {**journal, "journal_id": path.stem}
        return None

    def migrate(self, egress_id, confirm=False, plan_id=""):
        identifier(egress_id)
        pending = self._pending_migration(egress_id)
        if pending:
            if self.store.runtime("persistence:" + egress_id, {}):
                return {
                    "state": "NATIVE_STAGED",
                    "migration_id": pending.get("id", pending["journal_id"]),
                    "legacy_unit": pending.get("unit", ""),
                    "legacy_disabled_without_stop": False,
                    "legacy_file_preserved": True,
                    "reconcile_realm_required": True,
                    "resumed": True,
                }
            return {
                "state": "RECOVERY_REQUIRED",
                "migration_id": pending.get("id", pending["journal_id"]),
                "ok": False,
                "error": "PBR 迁移事务尚未建立原生提交记录，请先运行 recovery repair",
            }
        audit = self.audit_legacy(egress_id)
        if not audit["safe_migration"]:
            return {"state": "AUDIT_ONLY", "audit": audit}
        if not confirm:
            plan = self.plan(egress_id, True)
            audit_sha256 = self._audit_fingerprint(audit)
            self.store.set_runtime(
                "pbr-migration-plan:" + egress_id,
                {
                    "plan_id": plan["plan_id"],
                    "audit_sha256": audit_sha256,
                    "at": now(),
                },
            )
            return {
                "state": "PLANNED",
                "audit": audit,
                "audit_sha256": audit_sha256,
                "plan": plan,
            }
        with (
            file_lock(self.paths.state / "routing.lock"),
            file_lock(self.paths.state / "pbr-migration.lock"),
        ):
            reviewed = self.store.runtime("pbr-migration-plan:" + egress_id, {})
            current_audit = self.audit_legacy(egress_id)
            if (
                not current_audit["safe_migration"]
                or reviewed.get("plan_id") != plan_id
                or reviewed.get("audit_sha256") != self._audit_fingerprint(current_audit)
            ):
                raise ConflictError("旧单元或迁移计划已变化，请重新审阅")
            audit = current_audit
            egress = Egress(**self.store.get("egress", egress_id)).validate()
            migration_id = new_id()
            journal_path = self.paths.state / "pbr-migrations" / f"{migration_id}.json"
            journal = {
                "schema": 1,
                "id": migration_id,
                "egress_id": egress_id,
                "unit": audit["unit"],
                "plan_id": plan_id,
                "phase": "APPLYING_NATIVE",
                "at": now(),
            }
            atomic_write(journal_path, canonical(journal))
            result = self.persistence.apply(egress, plan_id, migration=True)
            atomic_write(journal_path, canonical({**journal, "phase": "NATIVE_APPLIED"}))
            updated = Egress(
                **{
                    **asdict(egress),
                    "backend": result["backend"],
                    "dependency_service": "",
                }
            ).validate()
            with self.store.transaction() as db:
                saved = self.store.put("egress", egress_id, asdict(updated), egress.revision, db)
                self.store.set_runtime(
                    "legacy-pbr:" + egress_id,
                    {
                        **audit,
                        "native_staged": True,
                        "staged_at": now(),
                    },
                    db,
                )
        return {
            **result,
            "state": "NATIVE_STAGED",
            "egress": saved,
            "migration_id": migration_id,
            "legacy_unit": audit["unit"],
            "legacy_disabled_without_stop": False,
            "legacy_file_preserved": True,
            "reconcile_realm_required": True,
        }

    def finalize_migration(self, egress_id, migration_id):
        identifier(egress_id)
        if not re.fullmatch(r"[0-9a-f]{16}", migration_id):
            raise ValidationError("PBR 迁移事务 ID 格式异常")
        with (
            file_lock(self.paths.state / "routing.lock"),
            file_lock(self.paths.state / "pbr-migration.lock"),
        ):
            path = self.paths.state / "pbr-migrations" / f"{migration_id}.json"
            if not path.is_file() or path.is_symlink():
                raise ValidationError("未找到对应的 PBR 迁移事务")
            journal = json.loads(path.read_text(encoding="utf-8"))
            if journal.get("id") != migration_id or journal.get("egress_id") != egress_id:
                raise ConflictError("PBR 迁移事务身份不匹配")
            unit = journal.get("unit", "")
            if unit != f"relayaxis-pbr-{egress_id}.service":
                raise ConflictError("PBR 迁移事务服务身份异常")
            runtime = self.store.runtime("persistence:" + egress_id, {})
            if not runtime:
                raise ConflictError("原生持久化提交记录缺失，保留旧 PBR 单元")
            reverse, dependents = self._legacy_dependencies(unit)
            if reverse.returncode or dependents:
                atomic_write(
                    path,
                    canonical(
                        {
                            **journal,
                            "phase": "AWAITING_REALM_RECONCILE",
                            "remaining_dependencies": dependents,
                        }
                    ),
                )
                return {
                    "state": "PENDING_SYNC",
                    "error": "旧 PBR 单元仍有服务依赖，已保留为启用状态",
                    "remaining_dependencies": dependents,
                    "legacy_disabled_without_stop": False,
                }
            # RemainAfterExit may run destructive ExecStop commands.  Removing
            # enablement only affects future boot; the current unit stays active.
            if self.services.state(unit)["enabled"]:
                self.services.action("disable", unit)
            with self.store.transaction() as db:
                previous = self.store.runtime("legacy-pbr:" + egress_id, {}, db)
                self.store.set_runtime(
                    "legacy-pbr:" + egress_id,
                    {
                        **previous,
                        "native_staged": False,
                        "disabled_without_stop": True,
                        "migrated_at": now(),
                    },
                    db,
                )
                self.store.set_runtime("pbr:" + egress_id, {}, db)
                self.store.set_runtime("pbr-unit:" + egress_id, {}, db)
                self.store.set_runtime("pbr-migration-plan:" + egress_id, {}, db)
            path.unlink()
            return {
                "state": "ACTIVE",
                "legacy_unit": unit,
                "legacy_disabled_without_stop": True,
                "legacy_file_preserved": True,
            }

    def reconcile_persistence(self):
        reports = []
        with file_lock(self.paths.state / "routing.lock"):
            for data in self.store.list("egress"):
                egress = Egress(**data).validate()
                try:
                    reports.append(self.persistence.repair(egress))
                except Exception as exc:
                    reports.append(
                        {
                            "egress_id": egress.egress_id,
                            "state": "UNKNOWN",
                            "changed": False,
                            "error": type(exc).__name__,
                        }
                    )
        return reports

    def delete(self, egress_id, confirm=False, plan_id=""):
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
            persistence = self.store.runtime("persistence:" + egress_id, {})
            if persistence:
                if not confirm:
                    return self.persistence.remove_plan(egress)
                removed = self.persistence.remove(egress, plan_id)
                self.store.remove("egress", egress_id)
                return {
                    "deleted": egress_id,
                    "external_preserved": False,
                    "persistence": removed,
                }
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
