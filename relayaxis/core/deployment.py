import base64
import json
from dataclasses import asdict
from pathlib import Path

from ..errors import ApplyError, ConflictError
from ..models import address_conflict, new_id, now, protocols
from .realm import Endpoint, check_bind, render, unit_text
from .system import atomic_write, file_lock


class Deployment:
    """Crash journal + per-endpoint compensation. Only manifest-owned files are touched."""

    def __init__(
        self, paths, store, services, realm_binary="/usr/local/bin/realm", bind_check=check_bind
    ):
        self.paths, self.store, self.services = paths, store, services
        self.realm_binary, self.bind_check = realm_binary, bind_check

    def manifest(self, scope):
        return self.store.runtime("deployment:" + scope, {})

    def _healthy(self, endpoint):
        checker = getattr(self.services, "endpoint_healthy", None)
        return checker(endpoint) if checker else self.services.healthy(endpoint.unit)

    def drift(self, endpoints):
        changed = set()
        for endpoint in endpoints:
            config = self.paths.config / "realm" / f"{endpoint.endpoint_id}.toml"
            unit = self.paths.units / endpoint.unit
            expected = {
                config: render(endpoint),
                unit: unit_text(endpoint, config, self.realm_binary),
            }
            for path, content in expected.items():
                if path.is_symlink():
                    raise ConflictError("受管配置被替换为符号链接")
                if not path.exists() or path.read_text() != content:
                    changed.add(endpoint.endpoint_id)
        return changed

    def pause(self, scope):
        """Fail closed on a bad source route while retaining the last valid files."""
        with file_lock(self.paths.state / "deploy.lock"):
            for data in self.manifest(scope).values():
                self.services.action("stop", Endpoint(**data).unit)

    def _allowed_path(self, value):
        path = Path(value)
        return (path.parent == self.paths.config / "realm" and path.suffix == ".toml") or (
            path.parent == self.paths.units
            and path.name.startswith("relayaxis-realm-")
            and path.suffix == ".service"
        )

    def _restore(self, journal):
        # Stop candidate listeners before restoring old listeners.
        errors = []
        for unit in journal["units"]:
            try:
                self.services.action("stop", unit)
                if self.services.state(unit)["enabled"]:
                    self.services.action("disable", unit)
            except Exception as exc:
                errors.append(type(exc).__name__)
        for file in journal["files"]:
            if not self._allowed_path(file["path"]):
                raise ApplyError("恢复日志包含非受管路径，拒绝执行")
            path = Path(file["path"])
            if file["content"] is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, base64.b64decode(file["content"]), file["mode"])
        self.services.daemon_reload()
        for unit, state in journal["units"].items():
            try:
                if state["enabled"]:
                    self.services.action("enable", unit)
                if state["active"]:
                    self.services.action("start", unit)
                    if not self.services.healthy(unit):
                        raise ApplyError("旧服务恢复后健康检查失败")
            except Exception as exc:
                errors.append(type(exc).__name__)
        if errors:
            raise ApplyError("补偿操作未全部成功，需要 ra recovery repair 检查")

    def recover(self):
        reports = []
        with file_lock(self.paths.state / "deploy.lock"):
            for path in sorted((self.paths.state / "journals").glob("*.json")):
                journal = json.loads(path.read_text())
                marker = self.store.runtime("deployment-commit:" + journal["id"], False)
                if not marker:
                    self._restore(journal)
                path.unlink()
                reports.append(
                    {"journal": path.name, "result": "committed" if marker else "rolled_back"}
                )
        return reports

    def apply(self, scope, endpoints, force=False, commit_extra=None):
        with file_lock(self.paths.state / "deploy.lock"):
            if any((self.paths.state / "journals").glob("*.json")) or any(
                (self.paths.state / "resource-journals").glob("*.json")
            ):
                raise ApplyError("发现未完成的应用日志；先运行 ra recovery repair")
            desired = {e.endpoint_id: asdict(e.validate()) for e in endpoints}
            if len(desired) != len(endpoints):
                raise ConflictError("候选配置包含重复端点")
            current = self.manifest(scope)
            changed = {
                key
                for key in current.keys() | desired.keys()
                if current.get(key) != desired.get(key)
                or (key in desired and (force is True or isinstance(force, set) and key in force))
            }
            changed.update(self.drift(endpoints))
            if not changed:
                # Idempotent snapshot replay still has to validate actual running services.
                for data in desired.values():
                    if not self._healthy(Endpoint(**data)):
                        raise ApplyError("配置版本一致但服务未运行，请重启规则后重试")
                if commit_extra:
                    with self.store.transaction() as db:
                        commit_extra(db)
                return {"changed": [], "scope": scope}
            # Validate all candidate TOML and listening combinations before touching files.
            for e in endpoints:
                render(e)
            values = list(desired.values())
            for i, a in enumerate(values):
                for b in values[i + 1 :]:
                    if (
                        a["listen_port"] == b["listen_port"]
                        and protocols(a["protocol"]) & protocols(b["protocol"])
                        and address_conflict(a["listen_address"], b["listen_address"])
                    ):
                        raise ConflictError("候选端点存在监听冲突")
            for key in changed & desired.keys():
                candidate = Endpoint(**desired[key])
                owned_active = any(
                    v["listen_port"] == candidate.listen_port
                    and address_conflict(v["listen_address"], candidate.listen_address)
                    and self.services.state(Endpoint(**v).unit)["active"]
                    for v in current.values()
                )
                if not owned_active:
                    self.bind_check(candidate)
            files, units, writes = {}, {}, {}
            for key in sorted(changed):
                data = desired.get(key) or current[key]
                endpoint = Endpoint(**data)
                config = self.paths.config / "realm" / f"{key}.toml"
                unit_path = self.paths.units / endpoint.unit
                for path in (config, unit_path):
                    if path.is_symlink():
                        raise ConflictError("受管路径被替换为符号链接，拒绝覆盖")
                    if key not in current and path.exists():
                        raise ConflictError(f"拒绝覆盖未登记的已有文件: {path.name}")
                    files[str(path)] = {
                        "path": str(path),
                        "content": base64.b64encode(path.read_bytes()).decode()
                        if path.exists()
                        else None,
                        "mode": path.stat().st_mode & 0o777 if path.exists() else 0o600,
                    }
                units[endpoint.unit] = self.services.state(endpoint.unit)
                if key in desired:
                    writes[str(config)] = render(Endpoint(**desired[key]))
                    writes[str(unit_path)] = unit_text(
                        Endpoint(**desired[key]), config, self.realm_binary
                    )
            journal_id = new_id()
            journal = {
                "id": journal_id,
                "scope": scope,
                "at": now(),
                "files": list(files.values()),
                "units": units,
            }
            journal_path = self.paths.state / "journals" / f"{journal_id}.json"
            atomic_write(journal_path, json.dumps(journal))
            atomic_write(self.paths.backups / f"deployment-{journal_id}.json", json.dumps(journal))
            try:
                for unit, state in units.items():
                    if state["active"]:
                        self.services.action("stop", unit)
                    if state["enabled"] and not any(
                        Endpoint(**v).unit == unit for v in desired.values()
                    ):
                        self.services.action("disable", unit)
                for path in files:
                    if path in writes:
                        atomic_write(path, writes[path])
                    else:
                        Path(path).unlink(missing_ok=True)
                self.services.daemon_reload()
                for key in sorted(changed):
                    endpoint = Endpoint(**(desired.get(key) or current[key]))
                    if key in desired:
                        self.services.action("enable", endpoint.unit)
                        self.services.action("start", endpoint.unit)
                        if not self._healthy(endpoint):
                            raise ApplyError(f"Realm 启动健康检查失败: {endpoint.unit}")
                with self.store.transaction() as db:
                    self.store.set_runtime("deployment:" + scope, desired, db)
                    self.store.set_runtime("deployment-commit:" + journal_id, True, db)
                    if commit_extra:
                        commit_extra(db)
            except Exception as exc:
                try:
                    self._restore(journal)
                    journal_path.unlink()
                except Exception as rollback_exc:
                    raise ApplyError("应用失败且恢复不完整，已保留恢复日志") from rollback_exc
                raise ApplyError(f"应用失败，已恢复上一有效配置（{type(exc).__name__}）") from exc
            journal_path.unlink()
            return {"changed": sorted(changed), "scope": scope}
