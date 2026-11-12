"""Manifest-only uninstall, shared by shell entry point and packaging tests."""

import argparse
import json
import shutil
from pathlib import Path

from .config import Paths
from .core.system import Runner, Services, file_lock
from .errors import ConflictError, ValidationError
from .storage import Store


def uninstall(paths, purge=False):
    with file_lock(paths.root / "run/relayaxis-install.lock"):
        return _uninstall(paths, purge)


def _uninstall(paths, purge=False):
    manifest_path = paths.state / "installation.json"
    if not manifest_path.is_file():
        raise ValidationError("未找到安装清单，拒绝猜测或通配删除文件")
    manifest = json.loads(manifest_path.read_text())
    prefix = paths.root / "opt/relayaxis"
    if manifest["prefix"] != str(prefix) or not (prefix / ".relayaxis-owned").is_file():
        raise ConflictError("安装清单的程序目录不匹配")
    store = Store(paths.database)
    live = paths.root.resolve() == Path("/")
    services = Services(Runner())
    if live:
        services.runner.require_root()
        for unit in ("relayaxis-reconcile.timer", "relayaxis-reconcile.service"):
            if (paths.units / unit).exists():
                services.action("stop", unit)
        from .app import App
        from .core.migration import Migration

        app = App(paths)
        app.routing.recover()
        app.resources.recover()
        app.deployment.recover()
        Migration(app).recover()
    units = set(manifest["units"])
    with store.connect() as db:
        entries = db.execute("SELECT key,data FROM runtime").fetchall()
    for entry in entries:
        key, data = entry[0], json.loads(entry[1])
        if key.startswith("deployment:"):
            units.update(f"relayaxis-realm-{endpoint_id}.service" for endpoint_id in data)
        if key.startswith(("wg:", "pbr-unit:", "mimic-owned:")) and data.get("unit"):
            units.add(data["unit"])
    if live:
        services.runner.require_root()
        # Stop retries first, then listeners, then transports, then owned PBR.
        ordered = sorted(
            units,
            key=lambda u: (
                0
                if u.endswith(".timer")
                else 1
                if "realm-" in u
                else 2
                if "wg-" in u or "mimic-" in u
                else 3
            ),
        )
        for unit in ordered:
            if not unit.startswith("relayaxis-") or Path(unit).name != unit:
                raise ConflictError("卸载清单含有非受管服务")
            if (paths.units / unit).is_file():
                services.action("stop", unit)
                services.action("disable", unit)
    removed = []
    for unit in units:
        if not unit.startswith("relayaxis-") or Path(unit).name != unit:
            raise ConflictError("拒绝移除非受管服务")
        path = paths.units / unit
        if path.is_symlink():
            raise ConflictError("受管服务路径已变为符号链接，拒绝删除")
        if path.exists():
            path.unlink()
            removed.append(str(path))
    if live:
        services.daemon_reload()
    command = paths.root / "usr/local/bin/ra"
    if command.is_symlink():
        raise ConflictError("ra 路径已被替换为符号链接")
    command.unlink(missing_ok=True)
    shutil.rmtree(prefix)
    if purge:
        shutil.rmtree(paths.config)
        shutil.rmtree(paths.state)
    else:
        # Allow a subsequent clean reinstall to register a fresh program directory.
        manifest_path.unlink()
    return {
        "uninstalled": True,
        "purged": purge,
        "removed_units": removed,
        "config_preserved": not purge,
        "external_services_preserved": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--purge", action="store_true")
    args = parser.parse_args()
    print(json.dumps(uninstall(Paths(args.root.resolve()), args.purge), ensure_ascii=False))
