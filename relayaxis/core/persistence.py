"""Native, ownership-aware IPv4 policy-routing persistence.

The backends only add a RelayAxis-named fragment.  They never rewrite a base
Netplan document or create a competing catch-all ``.network`` file.
"""

import base64
import difflib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from ..errors import ApplyError, ConflictError, ValidationError
from ..models import Egress, EgressHealth, PersistenceBackend, new_id, now
from ..storage import canonical
from .network import table_name
from .system import atomic_write, file_lock

OWNER = "Managed by RelayAxis; egress="


def _sha256(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def _read_regular(path):
    path = Path(path)
    if path.is_symlink():
        raise ConflictError(f"配置文件是符号链接: {path.name}")
    return path.read_text(encoding="utf-8")


class NetplanBackend:
    name = PersistenceBackend.NETPLAN.value
    file_mode = 0o600

    def __init__(self, paths, runner):
        self.paths, self.runner = paths, runner

    def path(self, egress):
        return self.paths.netplan / f"90-relayaxis-egress-{egress.egress_id}.yaml"

    def prepare_destination(self, destination):
        if not destination.parent.is_dir() or destination.parent.is_symlink():
            raise ConflictError("Netplan 配置目录缺失或是符号链接")

    @staticmethod
    def render(egress, definition=None):
        egress.validate()
        definition = definition or egress.interface
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", definition):
            raise ValidationError("Netplan 接口定义 ID 含有不支持的字符")
        return f"""# {OWNER}{egress.egress_id}
network:
  version: 2
  ethernets:
    '{definition}':
      routes:
        - to: 0.0.0.0/0
          via: {egress.gateway}
          from: {egress.source}
          table: {egress.table}
      routing-policy:
        - from: {egress.source}/32
          table: {egress.table}
          priority: {egress.priority}
"""

    def interface_id(self, egress):
        """Map the kernel name to an existing Netplan definition.

        A direct ID, an exact ``set-name`` or an exact ``match.name`` is
        deterministic. Glob matches and MAC-only definitions without set-name
        need an administrator decision and are intentionally left read-only.
        """
        matches = set()
        destination = self.path(egress)
        for path in self.files():
            if path.resolve() == destination.resolve():
                continue
            lines = _read_regular(path).splitlines()
            in_ethernets = False
            index = 0
            while index < len(lines):
                line = lines[index]
                stripped = line.strip()
                indent = len(line) - len(line.lstrip(" "))
                if indent == 2 and re.fullmatch(r"ethernets\s*:\s*(?:#.*)?", stripped):
                    in_ethernets = True
                    index += 1
                    continue
                if in_ethernets and indent <= 2 and stripped and not stripped.startswith("#"):
                    in_ethernets = False
                match = (
                    re.fullmatch(r"['\"]?([A-Za-z0-9_.-]+)['\"]?\s*:\s*(?:#.*)?", stripped)
                    if in_ethernets and indent == 4
                    else None
                )
                if not match:
                    index += 1
                    continue
                definition = match.group(1)
                block = []
                index += 1
                while index < len(lines):
                    nested = lines[index]
                    nested_indent = len(nested) - len(nested.lstrip(" "))
                    if nested.strip() and nested_indent <= 4:
                        break
                    block.append(nested)
                    index += 1
                text = "\n".join(block)
                has_match_block = bool(re.search(r"(?m)^\s*match\s*:", text))
                if (
                    (definition == egress.interface and not has_match_block)
                    or re.search(
                        rf"(?m)^\s*set-name\s*:\s*['\"]?{re.escape(egress.interface)}['\"]?\s*(?:#.*)?$",
                        text,
                    )
                    or re.search(
                        rf"(?m)^\s*name\s*:\s*['\"]?{re.escape(egress.interface)}['\"]?\s*(?:#.*)?$",
                        text,
                    )
                ):
                    matches.add(definition)
        if len(matches) != 1:
            raise ConflictError(
                "Netplan 中没有唯一映射到实际接口的既有定义；保留只读并要求人工确认"
            )
        return next(iter(matches))

    def candidate(self, egress):
        return self.render(egress, self.interface_id(egress))

    def files(self):
        if not self.paths.netplan.exists():
            return []
        return sorted(
            path
            for pattern in ("*.yaml", "*.yml")
            for path in self.paths.netplan.glob(pattern)
            if path.is_file() or path.is_symlink()
        )

    def renderer(self):
        renderers = set()
        for path in self.files():
            match = re.search(
                r"(?m)^\s*renderer\s*:\s*([A-Za-z0-9_-]+)\s*(?:#.*)?$", _read_regular(path)
            )
            if match:
                renderers.add(match.group(1).lower())
        if len(renderers) > 1:
            return "mixed"
        return next(iter(renderers), "networkd")

    def conflicts(self, egress, destination):
        conflicts = []
        for path in self.files():
            if path.resolve() == destination.resolve():
                continue
            text = _read_regular(path)
            if re.search(rf"(?m)^\s*table\s*:\s*{re.escape(egress.table)}\s*(?:#.*)?$", text):
                conflicts.append({"file": str(path), "field": "table", "value": egress.table})
            if re.search(rf"(?m)^\s*priority\s*:\s*{egress.priority}\s*(?:#.*)?$", text):
                conflicts.append({"file": str(path), "field": "priority", "value": egress.priority})
        return conflicts

    def validate_candidate(self, destination, content):
        with tempfile.TemporaryDirectory(prefix="relayaxis-netplan-") as temporary:
            root = Path(temporary)
            directory = root / "etc/netplan"
            directory.mkdir(parents=True)
            for path in self.files():
                if path.resolve() == destination.resolve():
                    continue
                if path.is_symlink():
                    raise ConflictError("Netplan 基础配置含符号链接，停止自动写入")
                shutil.copy2(path, directory / path.name)
            atomic_write(directory / destination.name, content)
            self.runner.run(["netplan", "generate", "--root-dir", str(root)], timeout=45)

    def apply_live(self, egress):
        self.runner.run(["netplan", "generate"], timeout=45)
        self.runner.run(["netplan", "apply"], timeout=90)

    def repair_live(self, egress):
        # Netplan renders networkd files; reconfigure only the owned interface.
        self.runner.run(["netplan", "generate"], timeout=45)
        self.runner.run(["networkctl", "reload"], timeout=30)
        self.runner.run(["networkctl", "reconfigure", egress.interface], timeout=45)


class NetworkdBackend:
    name = PersistenceBackend.NETWORKD.value
    file_mode = 0o644

    def __init__(self, paths, runner, network):
        self.paths, self.runner, self.network = paths, runner, network

    @staticmethod
    def render(egress):
        egress.validate()
        return f"""# {OWNER}{egress.egress_id}
[Route]
Destination=0.0.0.0/0
Gateway={egress.gateway}
PreferredSource={egress.source}
Table={egress.table}

[RoutingPolicyRule]
From={egress.source}/32
Table={egress.table}
Priority={egress.priority}
"""

    candidate = render

    @staticmethod
    def _find_network_file(data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in ("networkfile", "network_file") and isinstance(value, str):
                    return value
                found = NetworkdBackend._find_network_file(value)
                if found:
                    return found
        elif isinstance(data, list):
            for value in data:
                found = NetworkdBackend._find_network_file(value)
                if found:
                    return found
        return ""

    def effective_file(self, interface):
        result = self.runner.run(["networkctl", "--json=short", "status", interface], check=False)
        if result.returncode == 0:
            try:
                found = self._find_network_file(json.loads(result.stdout))
            except ValueError:
                found = ""
            if found:
                return Path(found)
        result = self.runner.run(["networkctl", "--no-pager", "status", interface], check=False)
        match = re.search(r"(?m)^\s*Network File:\s*(\S+\.network)\s*$", result.stdout)
        return Path(match.group(1)) if match else None

    def path(self, egress):
        effective = self.effective_file(egress.interface)
        if not effective or effective.suffix != ".network":
            raise ValidationError("未识别到接口当前生效的 systemd-networkd .network 文件")
        # Drop-ins with the same base filename merge with /etc, /run and /usr
        # sources without creating another first-match .network definition.
        directory = self.paths.networkd / f"{effective.name}.d"
        return directory / f"90-relayaxis-egress-{egress.egress_id}.conf"

    def prepare_destination(self, destination):
        directory = destination.parent
        if directory.is_symlink():
            raise ConflictError("networkd drop-in 目录不能是符号链接")
        if not directory.exists():
            directory.mkdir(parents=True, mode=0o755)
            directory.chmod(0o755)
        if not directory.is_dir() or directory.stat().st_mode & 0o005 != 0o005:
            raise ConflictError("networkd drop-in 目录不允许服务账户读取")

    def files(self):
        # systemd-networkd merges same-name drop-ins across its complete search
        # path.  Conflicts in /run or vendor directories therefore matter even
        # though RelayAxis only ever writes its own fragment below /etc.
        roots = (
            self.paths.networkd,
            self.paths.root / "run/systemd/network",
            self.paths.root / "usr/local/lib/systemd/network",
            self.paths.root / "usr/lib/systemd/network",
        )
        files = {
            path
            for root in roots
            if root.exists()
            for path in root.rglob("*")
            if path.suffix in (".network", ".conf") and (path.is_file() or path.is_symlink())
        }
        return sorted(files, key=lambda path: str(path))

    def conflicts(self, egress, destination):
        conflicts = []
        for path in self.files():
            if path.resolve() == destination.resolve():
                continue
            text = _read_regular(path)
            if re.search(rf"(?mi)^\s*Table\s*=\s*{re.escape(egress.table)}\s*$", text):
                conflicts.append({"file": str(path), "field": "table", "value": egress.table})
            if re.search(rf"(?mi)^\s*Priority\s*=\s*{egress.priority}\s*$", text):
                conflicts.append({"file": str(path), "field": "priority", "value": egress.priority})
        return conflicts

    def validate_candidate(self, destination, content):
        # systemd-analyze verify accepts a .network path on current systemd.
        # Older releases return an unsupported-file error, so perform strict
        # section/key validation here and let networkctl parse it on apply.
        sections = re.findall(r"(?m)^\[([A-Za-z]+)]\s*$", content)
        if sections != ["Route", "RoutingPolicyRule"]:
            raise ValidationError("networkd 候选 drop-in 的节或顺序异常")
        required = (
            "Destination=0.0.0.0/0",
            "Gateway=",
            "PreferredSource=",
            "Table=",
            "From=",
            "Priority=",
        )
        if not all(item in content for item in required):
            raise ValidationError("networkd 候选 drop-in 缺少 PBR 字段")

    def apply_live(self, egress):
        self.runner.run(["networkctl", "reload"], timeout=30)
        self.runner.run(["networkctl", "reconfigure", egress.interface], timeout=45)

    repair_live = apply_live


class PersistenceManager:
    def __init__(self, paths, store, network, runner, services):
        self.paths, self.store, self.network = paths, store, network
        self.runner, self.services = runner, services
        self.netplan = NetplanBackend(paths, runner)
        self.networkd = NetworkdBackend(paths, runner, network)

    def _command(self, argv):
        return self.runner.run(argv, check=False).returncode == 0

    def detect(self, egress=None):
        netplan_available = self._command(["netplan", "--help"])
        networkd_active = self._command(["systemctl", "is-active", "systemd-networkd.service"])
        network_manager_active = self._command(["systemctl", "is-active", "NetworkManager.service"])
        files = [str(path) for path in self.netplan.files()]
        renderer = self.netplan.renderer() if files else ""
        requested = egress.backend if egress else PersistenceBackend.AUTO
        selected = PersistenceBackend.READ_ONLY.value
        reason = "当前网络管理器仅提供只读检测"
        if egress and egress.management == "system":
            selected, reason = PersistenceBackend.SYSTEM.value, "系统 main 默认路由只读复用"
        elif egress and not egress.managed:
            selected, reason = (
                PersistenceBackend.READ_ONLY.value,
                f"外部资源由 {egress.backend} 管理；RelayAxis 仅检测",
            )
        elif requested in (PersistenceBackend.NETPLAN, PersistenceBackend.NETPLAN.value):
            if netplan_available and files and renderer == "networkd" and networkd_active:
                selected, reason = PersistenceBackend.NETPLAN.value, "显式 Netplan 后端"
            else:
                reason = "Netplan 不可用、无基础配置、renderer 不是 networkd 或 networkd 未运行"
        elif requested in (PersistenceBackend.NETWORKD, PersistenceBackend.NETWORKD.value):
            if networkd_active:
                selected, reason = PersistenceBackend.NETWORKD.value, "显式 networkd 后端"
            else:
                reason = "systemd-networkd 未运行"
        elif requested in (
            PersistenceBackend.LEGACY_ONESHOT,
            PersistenceBackend.LEGACY_ONESHOT.value,
        ):
            selected, reason = PersistenceBackend.LEGACY_ONESHOT.value, "v0.1.0 旧 oneshot"
        elif netplan_available and files and renderer == "networkd" and networkd_active:
            selected, reason = PersistenceBackend.NETPLAN.value, "Netplan + systemd-networkd"
        elif networkd_active and not network_manager_active:
            selected, reason = PersistenceBackend.NETWORKD.value, "原生 systemd-networkd"
        elif network_manager_active:
            reason = "检测到 NetworkManager；v0.1.1 对该管理器只读"
        return {
            "selected": selected,
            "reason": reason,
            "writable": bool(
                egress
                and egress.managed
                and selected
                in (PersistenceBackend.NETPLAN.value, PersistenceBackend.NETWORKD.value)
            ),
            "netplan": {
                "available": netplan_available,
                "files": files,
                "renderer": renderer,
            },
            "networkd": {"active": networkd_active},
            "network_manager": {"active": network_manager_active},
        }

    def backend(self, egress, *, migration=False):
        report = self.detect(egress)
        selected = report["selected"]
        if selected == PersistenceBackend.NETPLAN:
            return self.netplan, report
        if selected == PersistenceBackend.NETWORKD:
            return self.networkd, report
        if selected == PersistenceBackend.LEGACY_ONESHOT and migration:
            probe = Egress(
                **{**asdict(egress), "backend": "auto", "dependency_service": ""}
            ).validate()
            report = self.detect(probe)
            if report["selected"] == PersistenceBackend.NETPLAN:
                return self.netplan, report
            if report["selected"] == PersistenceBackend.NETWORKD:
                return self.networkd, report
        raise ValidationError(report["reason"])

    def _kernel_conflicts(self, egress, allow_existing=False):
        routes = [
            route
            for route in self.network.routes()
            if table_name(route.get("table", "main")) == egress.table
        ]
        rules = [
            rule
            for rule in self.network.policy_rules()
            if int(rule.get("priority", -1)) == egress.priority
            or table_name(rule.get("table", "main")) == egress.table
        ]
        if not routes and not rules:
            return []
        source = ipaddress.ip_address(egress.source)

        def expected_route(route):
            destination = route.get("dst", "default")
            is_default = destination in ("default", "0.0.0.0/0")
            if is_default:
                destination_ok = route.get("gateway", "") == egress.gateway
            else:
                try:
                    destination_ok = not route.get("gateway") and source in ipaddress.ip_network(
                        destination, strict=False
                    )
                except ValueError:
                    destination_ok = False
            return (
                destination_ok
                and route.get("dev") == egress.interface
                and route.get("type", "unicast") == "unicast"
                and route.get("prefsrc", route.get("src", egress.source)) == egress.source
                and (is_default or not route.get("gateway"))
            )

        expected_routes = all(expected_route(route) for route in routes)
        expected_rules = all(
            rule.get("src") in (egress.source, egress.source + "/32")
            and int(rule.get("priority", -1)) == egress.priority
            and table_name(rule.get("table", "main")) == egress.table
            and self.network._simple_source_rule(rule)
            for rule in rules
        )
        owned = bool(
            self.store.runtime("persistence:" + egress.egress_id)
            or self.store.runtime("pbr:" + egress.egress_id)
        )
        if allow_existing and expected_routes and expected_rules:
            return []
        if owned and expected_routes and expected_rules:
            return []
        return [
            {
                "scope": "kernel",
                "routes": routes,
                "rules": rules,
                "reason": "路由表或优先级已有非本次候选拥有的条目",
            }
        ]

    def _existing(self, path, egress):
        if not path.exists():
            return "", False
        text = _read_regular(path)
        marker = f"{OWNER}{egress.egress_id}"
        if marker not in text:
            raise ConflictError("目标持久化文件已存在且不属于该出口")
        registered = self.store.runtime("persistence:" + egress.egress_id, {})
        legacy_journal = False
        for item in (self.paths.state / "network-journals").glob("*.json"):
            if item.is_symlink():
                raise ConflictError("网络恢复日志不能是符号链接")
            if json.loads(item.read_text(encoding="utf-8")).get("egress_id") == egress.egress_id:
                legacy_journal = True
                break
        if not registered and not legacy_journal:
            raise ConflictError("发现未登记的 RelayAxis 标记文件；请先运行 recovery status")
        return text, True

    def plan(self, egress, *, migration=False, allow_existing=False):
        egress.validate()
        if not egress.managed:
            return {
                "egress_id": egress.egress_id,
                "management": egress.management,
                "state": "READ_ONLY",
                "requires_confirmation": False,
            }
        link = next(
            (item for item in self.network.addresses() if item.get("ifname") == egress.interface),
            None,
        )
        address = next(
            (
                item
                for item in (link or {}).get("addr_info", [])
                if item.get("family") == "inet"
                and item.get("local") == egress.source
                and not set(item.get("flags", [])).intersection({"tentative", "dadfailed"})
                and not item.get("tentative", False)
            ),
            None,
        )
        if not address:
            raise ValidationError("自建出口的接口或源地址当前不存在")
        subnet = ipaddress.ip_network(
            f"{egress.source}/{address.get('prefixlen', 32)}", strict=False
        )
        if ipaddress.ip_address(egress.gateway) not in subnet:
            raise ValidationError("网关不在源地址的直连网段；候选未声明 on-link")
        backend, detection = self.backend(egress, migration=migration)
        destination = backend.path(egress)
        candidate = backend.candidate(egress)
        previous, exists = self._existing(destination, egress)
        conflicts = backend.conflicts(egress, destination)
        conflicts.extend(self._kernel_conflicts(egress, allow_existing or migration or exists))
        if conflicts:
            raise ConflictError("路由表、优先级或持久化配置与现有资源冲突")
        backend.validate_candidate(destination, candidate)
        default = self.network.default_route_state()
        if not default["resolved"]:
            raise ValidationError("系统 main 默认出口不唯一或缺失；先确认真实默认路由")
        diff = "".join(
            difflib.unified_diff(
                previous.splitlines(keepends=True),
                candidate.splitlines(keepends=True),
                fromfile=str(destination) if previous else "/dev/null",
                tofile=str(destination),
            )
        )
        material = {
            "egress": asdict(egress),
            "backend": backend.name,
            "path": str(destination),
            "candidate_sha256": _sha256(candidate),
            "previous_sha256": _sha256(previous),
            "default": default,
        }
        plan_id = _sha256(canonical(material))[:24]
        plan = {
            "plan_id": plan_id,
            "egress_id": egress.egress_id,
            "backend": backend.name,
            "detection": detection,
            "path": str(destination),
            "change": "unchanged" if previous == candidate else "update" if previous else "create",
            "diff": diff,
            "default_route_before": default,
            "requires_confirmation": True,
            "rollback_guard_seconds": 90,
            "candidate_sha256": material["candidate_sha256"],
            "created_at": now(),
        }
        self.store.set_runtime(
            "persistence-plan:" + egress.egress_id,
            {**plan, "material": material, "created_epoch": time.time()},
        )
        return plan

    def _peer_route(self, peer):
        try:
            version = ipaddress.ip_address(peer).version
        except ValueError:
            return {"peer": peer, "error": True}
        result = self.runner.run(["ip", "-j", f"-{version}", "route", "get", peer], check=False)
        if result.returncode:
            return {"peer": peer, "error": True}
        try:
            route = json.loads(result.stdout)[0]
        except (ValueError, IndexError):
            return {"peer": peer, "error": True}
        return {
            "peer": peer,
            "family": version,
            "dev": route.get("dev", ""),
            "gateway": route.get("gateway", ""),
            "src": route.get("src", route.get("prefsrc", "")),
            "table": table_name(route.get("table", "main")),
        }

    def _ssh_route(self):
        connection = os.environ.get("SSH_CONNECTION", "").split()
        return self._peer_route(connection[0]) if connection else None

    def _schedule_guard(self, journal):
        unit = journal["guard_unit"]
        result = self.runner.run(
            [
                "systemd-run",
                "--quiet",
                "--unit",
                unit,
                "--on-active=90s",
                "--timer-property=AccuracySec=1s",
                "/usr/local/bin/ra",
                "--json",
                "egress",
                "rollback",
                journal["id"],
            ],
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise ApplyError("独立回滚计时器创建失败，候选配置尚未应用")

    def _cancel_guard(self, journal):
        unit = journal["guard_unit"]
        self.runner.run(["systemctl", "stop", f"{unit}.timer", f"{unit}.service"], check=False)
        self.runner.run(
            ["systemctl", "reset-failed", f"{unit}.timer", f"{unit}.service"], check=False
        )

    def _cancel_guard_timer(self, journal):
        unit = journal["guard_unit"]
        self.runner.run(["systemctl", "stop", f"{unit}.timer"], check=False)
        self.runner.run(["systemctl", "reset-failed", f"{unit}.timer"], check=False)

    def _wait_health(self, egress, seconds=15):
        deadline = time.monotonic() + seconds
        latest = None
        while True:
            latest = self.network.egress_health(egress)
            if latest["status"] == EgressHealth.HEALTHY:
                return latest
            if time.monotonic() >= deadline:
                return latest
            time.sleep(0.25)

    def apply(self, egress, plan_id, *, migration=False):
        self.runner.require_root()
        if not plan_id:
            raise ValidationError("应用持久化配置需要先执行 egress plan 并提交 plan-id")
        with file_lock(self.paths.state / "network-persistence.lock"):
            plan = self.plan(egress, migration=migration, allow_existing=migration)
            saved = self.store.runtime("persistence-plan:" + egress.egress_id, {})
            if plan["plan_id"] != plan_id or saved.get("plan_id") != plan_id:
                raise ConflictError("网络事实或候选配置已变化，请重新审阅计划")
            backend, _ = self.backend(egress, migration=migration)
            destination = Path(plan["path"])
            previous = destination.read_bytes() if destination.exists() else None
            mode = destination.stat().st_mode & 0o777 if destination.exists() else 0o600
            identity = new_id()
            default_before = self.network.default_route_state()
            ssh_before = self._ssh_route()
            if ssh_before and ssh_before.get("error"):
                raise ValidationError("未取得当前 SSH 管理对端的实际路由，停止网络应用")
            candidate = backend.candidate(egress)
            if _sha256(candidate) != plan["candidate_sha256"]:
                raise ConflictError("候选配置在确认后发生变化，请重新审阅计划")
            journal = {
                "schema": 1,
                "id": identity,
                "egress_id": egress.egress_id,
                "backend": backend.name,
                "path": str(destination),
                "previous": base64.b64encode(previous).decode() if previous is not None else None,
                "mode": mode,
                "candidate_sha256": plan["candidate_sha256"],
                "default_before": default_before,
                "ssh_before": ssh_before,
                "guard_unit": f"relayaxis-network-rollback-{identity}",
                "at": now(),
            }
            journal_path = self.paths.state / "network-journals" / f"{identity}.json"
            atomic_write(journal_path, canonical(journal))
            atomic_write(self.paths.backups / f"network-{identity}.json", canonical(journal))
            guard_scheduled = False
            candidate_written = False
            try:
                backend.prepare_destination(destination)
                backend.validate_candidate(destination, candidate)
                self._schedule_guard(journal)
                guard_scheduled = True
                atomic_write(destination, candidate, backend.file_mode)
                candidate_written = True
                backend.apply_live(egress)
                health = self._wait_health(egress)
                default_after = self.network.default_route_state()
                ssh_after = self._ssh_route()
                if default_after != default_before:
                    raise ApplyError("应用后 main 默认路由发生变化")
                if ssh_before and ssh_after != ssh_before:
                    raise ApplyError("应用后远程管理对端的实际选路发生变化")
                if health["status"] != EgressHealth.HEALTHY:
                    raise ApplyError("应用后内核策略路由验证未通过")
                runtime = {
                    "backend": backend.name,
                    "path": str(destination),
                    "sha256": _sha256(candidate),
                    "egress": asdict(egress),
                    "health": health,
                    "at": now(),
                }
                with self.store.transaction() as db:
                    self.store.set_runtime("persistence:" + egress.egress_id, runtime, db)
                    self.store.set_runtime("network-commit:" + identity, True, db)
                self._cancel_guard(journal)
                journal_path.unlink()
                return {
                    "state": "ACTIVE",
                    "backend": backend.name,
                    "path": str(destination),
                    "health": health,
                    "rollback_backup": str(self.paths.backups / f"network-{identity}.json"),
                }
            except Exception as exc:
                try:
                    if candidate_written:
                        self._restore(journal, backend, egress)
                    if guard_scheduled:
                        self._cancel_guard(journal)
                    journal_path.unlink(missing_ok=True)
                except Exception as restore_error:
                    raise ApplyError("网络应用失败且回滚未完成，已保留恢复日志") from restore_error
                raise ApplyError("网络应用失败，已恢复原配置并重新加载") from exc

    def _restore(self, journal, backend=None, egress=None):
        backend_name = journal.get("backend")
        if backend_name not in (
            PersistenceBackend.NETPLAN.value,
            PersistenceBackend.NETWORKD.value,
        ):
            raise ApplyError("网络恢复日志后端异常")
        destination = Path(journal["path"])
        expected_root = (
            self.paths.netplan
            if backend_name == PersistenceBackend.NETPLAN.value
            else self.paths.networkd
        )
        try:
            destination.resolve().relative_to(expected_root.resolve())
        except ValueError as exc:
            raise ApplyError("网络恢复日志路径越界") from exc
        if destination.is_symlink():
            raise ApplyError("网络恢复目标已变为符号链接")
        previous = journal["previous"]
        if previous is None:
            destination.unlink(missing_ok=True)
        else:
            try:
                restored = base64.b64decode(previous, validate=True)
            except (ValueError, TypeError) as exc:
                raise ApplyError("网络恢复日志快照编码异常") from exc
            atomic_write(destination, restored, journal["mode"])
        if backend is None:
            backend = (
                self.netplan if backend_name == PersistenceBackend.NETPLAN.value else self.networkd
            )
        if egress is None:
            egress = Egress(**self.store.get("egress", journal["egress_id"])).validate()
        backend.apply_live(egress)
        if self.network.default_route_state() != journal["default_before"]:
            raise ApplyError("回滚后 main 默认路由尚未恢复")
        if journal.get("ssh_before"):
            peer = journal["ssh_before"].get("peer", "")
            if self._peer_route(peer) != journal["ssh_before"]:
                raise ApplyError("回滚后 SSH 管理对端选路尚未恢复")

    def rollback(self, identity):
        if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{16}", identity):
            raise ValidationError("网络回滚事务 ID 格式异常")
        path = self.paths.state / "network-journals" / f"{identity}.json"
        if not path.is_file() or path.is_symlink():
            raise ValidationError("未找到对应的网络回滚事务")
        with file_lock(self.paths.state / "network-persistence.lock"):
            journal = json.loads(path.read_text(encoding="utf-8"))
            if journal.get("id") != identity:
                raise ApplyError("网络回滚事务身份不匹配")
            if self.store.runtime("network-commit:" + identity):
                self._cancel_guard_timer(journal)
                path.unlink(missing_ok=True)
                return {"state": "ALREADY_COMMITTED"}
            self._restore(journal)
            self._cancel_guard_timer(journal)
            path.unlink()
            return {"state": "ROLLED_BACK", "egress_id": journal["egress_id"]}

    def recover(self):
        result = []
        for path in sorted((self.paths.state / "network-journals").glob("*.json")):
            if path.is_symlink():
                raise ApplyError("网络恢复日志不能是符号链接")
            identity = path.stem
            if not re.fullmatch(r"[0-9a-f]{16}", identity):
                raise ApplyError("网络恢复日志文件名异常")
            journal = json.loads(path.read_text(encoding="utf-8"))
            if journal.get("id") != identity:
                raise ApplyError("网络恢复日志身份不匹配")
            if self.store.runtime("network-commit:" + journal["id"]):
                self._cancel_guard(journal)
                path.unlink()
                result.append({"journal": path.name, "state": "COMMITTED"})
            else:
                result.append(self.rollback(identity))
        return result

    def remove_plan(self, egress):
        egress.validate()
        runtime = self.store.runtime("persistence:" + egress.egress_id, {})
        if not runtime:
            raise ConflictError("没有该出口的原生持久化资源所有权记录")
        if runtime.get("backend") not in (
            PersistenceBackend.NETPLAN.value,
            PersistenceBackend.NETWORKD.value,
        ):
            raise ConflictError("原生持久化所有权记录的后端异常")
        path = Path(runtime.get("path", ""))
        root = (
            self.paths.netplan
            if runtime["backend"] == PersistenceBackend.NETPLAN.value
            else self.paths.networkd
        )
        try:
            path.resolve().relative_to(root.resolve())
        except (OSError, ValueError) as exc:
            raise ConflictError("原生持久化所有权路径越界") from exc
        if not path.is_file() or path.is_symlink():
            raise ConflictError("受管持久化文件缺失或类型异常")
        content = path.read_bytes()
        if _sha256(content) != runtime.get("sha256"):
            raise ConflictError("受管持久化文件已经漂移，保留现场并停止删除")
        default = self.network.default_route_state()
        if not default["resolved"]:
            raise ValidationError("系统 main 默认出口不唯一或缺失；停止网络删除")
        material = {
            "operation": "delete",
            "egress_id": egress.egress_id,
            "backend": runtime["backend"],
            "path": str(path),
            "sha256": runtime["sha256"],
            "default": default,
        }
        plan_id = _sha256(canonical(material))[:24]
        plan = {
            "plan_id": plan_id,
            "operation": "delete",
            "egress_id": egress.egress_id,
            "backend": runtime["backend"],
            "path": str(path),
            "diff": "".join(
                difflib.unified_diff(
                    content.decode().splitlines(keepends=True),
                    [],
                    fromfile=str(path),
                    tofile="/dev/null",
                )
            ),
            "default_route_before": default,
            "requires_confirmation": True,
            "rollback_guard_seconds": 90,
        }
        self.store.set_runtime("persistence-remove-plan:" + egress.egress_id, plan)
        return plan

    def remove(self, egress, plan_id):
        self.runner.require_root()
        with file_lock(self.paths.state / "network-persistence.lock"):
            plan = self.remove_plan(egress)
            if not plan_id or plan["plan_id"] != plan_id:
                raise ConflictError("删除计划或网络事实已变化，请重新审阅")
            runtime = self.store.runtime("persistence:" + egress.egress_id, {})
            backend = self.netplan if runtime["backend"] == "netplan" else self.networkd
            destination = Path(runtime["path"])
            previous = destination.read_bytes()
            identity = new_id()
            ssh_before = self._ssh_route()
            if ssh_before and ssh_before.get("error"):
                raise ValidationError("未取得当前 SSH 管理对端的实际路由，停止网络删除")
            journal = {
                "schema": 1,
                "id": identity,
                "egress_id": egress.egress_id,
                "backend": runtime["backend"],
                "path": str(destination),
                "previous": base64.b64encode(previous).decode(),
                "mode": destination.stat().st_mode & 0o777,
                "candidate_sha256": _sha256(b""),
                "default_before": self.network.default_route_state(),
                "ssh_before": ssh_before,
                "guard_unit": f"relayaxis-network-rollback-{identity}",
                "operation": "delete",
                "at": now(),
            }
            journal_path = self.paths.state / "network-journals" / f"{identity}.json"
            atomic_write(journal_path, canonical(journal))
            atomic_write(self.paths.backups / f"network-{identity}.json", canonical(journal))
            try:
                self._schedule_guard(journal)
                destination.unlink()
                backend.apply_live(egress)
                default_after = self.network.default_route_state()
                ssh_after = self._ssh_route()
                health = self._wait_health(egress, 5)
                if default_after != journal["default_before"]:
                    raise ApplyError("删除后 main 默认路由发生变化")
                if journal["ssh_before"] and ssh_after != journal["ssh_before"]:
                    raise ApplyError("删除后远程管理对端的实际选路发生变化")
                if health["status"] == EgressHealth.HEALTHY:
                    raise ApplyError("持久化文件删除后该策略仍由其他配置管理")
                with self.store.transaction() as db:
                    self.store.set_runtime("persistence:" + egress.egress_id, {}, db)
                    self.store.set_runtime("network-commit:" + identity, True, db)
                self._cancel_guard(journal)
                journal_path.unlink()
                return {
                    "state": "REMOVED",
                    "backend": runtime["backend"],
                    "health_after": health,
                    "rollback_backup": str(self.paths.backups / f"network-{identity}.json"),
                }
            except Exception as exc:
                try:
                    self._restore(journal, backend, egress)
                    self._cancel_guard(journal)
                    journal_path.unlink(missing_ok=True)
                except Exception as restore_error:
                    raise ApplyError("网络删除失败且回滚未完成，已保留恢复日志") from restore_error
                raise ApplyError("网络删除失败，已恢复持久化文件") from exc

    def status(self, egress):
        egress.validate()
        runtime = self.store.runtime("persistence:" + egress.egress_id, {})
        ownership_state = "UNMANAGED"
        if runtime:
            path = Path(runtime.get("path", ""))
            if not path.is_file() or path.is_symlink():
                ownership_state = "MISSING"
            elif _sha256(path.read_bytes()) != runtime.get("sha256"):
                ownership_state = "DRIFTED"
            else:
                ownership_state = "ACTIVE"
        detected = []
        patterns = {
            "netplan": (
                self.netplan.files(),
                rf"(?m)^\s*table\s*:\s*{re.escape(egress.table)}\s*(?:#.*)?$",
            ),
            "networkd": (
                self.networkd.files(),
                rf"(?mi)^\s*Table\s*=\s*{re.escape(egress.table)}\s*$",
            ),
        }
        for name, (files, pattern) in patterns.items():
            for path in files:
                if re.search(pattern, _read_regular(path)):
                    detected.append({"backend": name, "file": str(path)})
        return {
            "egress_id": egress.egress_id,
            "management": egress.management,
            "configured_backend": egress.backend,
            "relayaxis_applied": ownership_state == "ACTIVE",
            "ownership_state": ownership_state,
            "runtime_ownership": runtime,
            "detected": detected,
            "selection": self.detect(egress),
        }

    def repair(self, egress):
        egress.validate()
        health = self.network.egress_health(egress)
        if health["status"] == EgressHealth.HEALTHY:
            return {"egress_id": egress.egress_id, "state": "HEALTHY", "changed": False}
        if not egress.managed:
            return {
                "egress_id": egress.egress_id,
                "state": health["status"],
                "changed": False,
                "management": egress.management,
            }
        runtime = self.store.runtime("persistence:" + egress.egress_id, {})
        if not runtime:
            return {
                "egress_id": egress.egress_id,
                "state": health["status"],
                "changed": False,
                "reason": "没有原生后端资源所有权记录",
            }
        path = Path(runtime["path"])
        root = (
            self.paths.netplan
            if runtime.get("backend") == PersistenceBackend.NETPLAN.value
            else self.paths.networkd
            if runtime.get("backend") == PersistenceBackend.NETWORKD.value
            else None
        )
        try:
            in_root = bool(root and path.resolve().is_relative_to(root.resolve()))
        except OSError:
            in_root = False
        if (
            not in_root
            or not path.is_file()
            or path.is_symlink()
            or _sha256(path.read_bytes()) != runtime["sha256"]
        ):
            return {
                "egress_id": egress.egress_id,
                "state": health["status"],
                "changed": False,
                "reason": "受管配置缺失或内容漂移",
            }
        default_before = self.network.default_route_state()
        ssh_before = self._ssh_route()
        protected_devices = {route[0] for route in default_before.get("routes", []) if route[0]}
        if not default_before["resolved"]:
            return {
                "egress_id": egress.egress_id,
                "state": health["status"],
                "changed": False,
                "reason": "main 默认出口不唯一或缺失，停止自动重配",
            }
        if egress.interface in protected_devices or (
            ssh_before and (ssh_before.get("error") or ssh_before.get("dev") == egress.interface)
        ):
            return {
                "egress_id": egress.egress_id,
                "state": health["status"],
                "changed": False,
                "reason": "该接口承载 main 默认出口或当前 SSH 管理路径，停止自动重配",
            }
        backend = self.netplan if runtime["backend"] == "netplan" else self.networkd
        backend.repair_live(egress)
        verified = self._wait_health(egress, 10)
        if self.network.default_route_state() != default_before or (
            ssh_before and self._ssh_route() != ssh_before
        ):
            raise ApplyError("定向恢复后 main 默认路由或 SSH 管理选路发生变化")
        return {
            "egress_id": egress.egress_id,
            "state": verified["status"],
            "changed": True,
            "backend": runtime["backend"],
        }
