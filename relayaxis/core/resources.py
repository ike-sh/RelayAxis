"""Durable file/service transactions for separately managed WG and Mimic resources."""

import base64
import json
from contextlib import contextmanager
from pathlib import Path

from ..errors import ApplyError, ConflictError
from ..models import new_id, now
from .system import atomic_write, file_lock


class ResourceFiles:
    def __init__(self, paths, store, services):
        self.paths, self.store, self.services = paths, store, services

    def _allowed(self, path):
        path = Path(path)
        return (
            (
                path.parent in (self.paths.config / "wireguard", self.paths.config / "mimic")
                and path.suffix == ".conf"
            )
            or (path.parent == self.paths.config / "egress" and path.suffix == ".json")
            or (
                path.parent == self.paths.units
                and path.name.startswith(("relayaxis-wg-", "relayaxis-mimic-", "relayaxis-pbr-"))
                and path.suffix == ".service"
            )
        )

    def _restore(self, journal):
        unit = journal["unit"]
        if (
            not unit.startswith(("relayaxis-wg-", "relayaxis-mimic-", "relayaxis-pbr-"))
            or Path(unit).name != unit
        ):
            raise ApplyError("资源日志含非受管服务")
        if any(not self._allowed(file["path"]) for file in journal["files"]):
            raise ApplyError("资源日志含非受管路径")
        if (self.paths.units / unit).exists():
            self.services.action("stop", unit)
        if self.services.state(unit)["enabled"]:
            self.services.action("disable", unit)
        for file in journal["files"]:
            if file["content"] is None:
                Path(file["path"]).unlink(missing_ok=True)
            else:
                atomic_write(file["path"], base64.b64decode(file["content"]), file["mode"])
        self.services.daemon_reload()
        if journal["state"]["enabled"]:
            self.services.action("enable", unit)
        if journal["state"]["active"]:
            self.services.action("start", unit)
            if not self.services.healthy(unit):
                raise ApplyError("资源恢复后健康检查失败")

    @contextmanager
    def transaction(self, unit, paths):
        # Callers hold their resource-specific lock; this serializes recovery across resources.
        with file_lock(self.paths.state / "resource-files.lock"):
            directory = self.paths.state / "resource-journals"
            if any(directory.glob("*.json")):
                raise ApplyError("有未完成的资源事务，请先运行 recovery repair")
            files = []
            for path in paths:
                path = Path(path)
                if not self._allowed(path) or path.is_symlink():
                    raise ConflictError("非受管或符号链接的资源文件")
                files.append(
                    {
                        "path": str(path),
                        "content": base64.b64encode(path.read_bytes()).decode()
                        if path.exists()
                        else None,
                        "mode": path.stat().st_mode & 0o777 if path.exists() else 0o600,
                    }
                )
            identity = new_id()
            journal = {
                "id": identity,
                "at": now(),
                "unit": unit,
                "state": self.services.state(unit),
                "files": files,
            }
            path = directory / f"{identity}.json"
            atomic_write(path, json.dumps(journal))
            atomic_write(self.paths.backups / f"resource-{identity}.json", json.dumps(journal))
            try:
                yield identity
                if not self.store.runtime("resource-commit:" + identity):
                    raise ApplyError("资源事务没有提交确认标记")
            except Exception as exc:
                try:
                    self._restore(journal)
                    path.unlink()
                except Exception as restore_error:
                    raise ApplyError("资源应用失败且补偿未完成，已保留恢复日志") from restore_error
                raise ApplyError("资源应用失败，已恢复旧文件和服务状态") from exc
            path.unlink()

    def commit(self, identity, callback=None):
        with self.store.transaction() as db:
            if callback:
                callback(db)
            self.store.set_runtime("resource-commit:" + identity, True, db)

    def recover(self):
        results = []
        with file_lock(self.paths.state / "resource-files.lock"):
            for path in sorted((self.paths.state / "resource-journals").glob("*.json")):
                journal = json.loads(path.read_text())
                committed = self.store.runtime("resource-commit:" + journal["id"], False)
                if not committed:
                    self._restore(journal)
                path.unlink()
                results.append(
                    {"journal": path.name, "result": "committed" if committed else "rolled_back"}
                )
        return results
