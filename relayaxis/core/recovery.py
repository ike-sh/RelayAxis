import hashlib
import io
import json
import sqlite3
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from .. import __version__
from ..errors import ConflictError, ValidationError
from ..models import Egress, Rule, Server, Tunnel, new_id, now
from ..storage import Store, canonical
from .system import atomic_write, file_lock

MAX_BACKUP_BYTES = 256 * 1024 * 1024


class Backups:
    def __init__(self, paths, store, runner):
        self.paths, self.store, self.runner = paths, store, runner

    def create(self, destination=None):
        destination = (
            Path(destination)
            if destination
            else self.paths.backups / f"relayaxis-{new_id()}.tar.gz"
        )
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists():
            raise ConflictError("备份文件已存在，拒绝覆盖")
        with (
            file_lock(self.paths.state / "backup.lock"),
            file_lock(self.paths.state / "deploy.lock"),
            file_lock(self.paths.state / "wg.lock"),
            file_lock(self.paths.state / "routing.lock"),
            file_lock(self.paths.state / "mimic.lock"),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "state.sqlite3"
                self.store.backup(database)
                files = {"state.sqlite3": database.read_bytes()}
                for path in self.paths.config.rglob("*"):
                    if path.is_symlink():
                        raise ValidationError("配置目录含符号链接，拒绝跟随备份")
                    if path.is_file():
                        files["config/" + path.relative_to(self.paths.config).as_posix()] = (
                            path.read_bytes()
                        )
                manifest = {
                    "schema": 1,
                    "version": __version__,
                    "created_at": now(),
                    "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
                }
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                    for name, raw in {
                        **files,
                        "manifest.json": canonical(manifest).encode(),
                    }.items():
                        info = tarfile.TarInfo(name)
                        info.size, info.mode = len(raw), 0o600
                        archive.addfile(info, io.BytesIO(raw))
                atomic_write(destination, buffer.getvalue())
        return {
            "backup": str(destination),
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "files": len(files),
            "contains_local_keys": True,
        }

    def inspect(self, source):
        files, size = {}, 0
        with tarfile.open(source, "r:gz") as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                if (
                    not member.isfile()
                    or path.is_absolute()
                    or ".." in path.parts
                    or "\\" in member.name
                    or member.name in files
                ):
                    raise ValidationError("备份含有路径穿越、重复成员或非普通文件")
                if member.name not in (
                    "manifest.json",
                    "state.sqlite3",
                ) and not member.name.startswith("config/"):
                    raise ValidationError("备份含有非受管成员")
                size += member.size
                if size > MAX_BACKUP_BYTES:
                    raise ValidationError("备份展开超过 256 MiB")
                files[member.name] = archive.extractfile(member).read()
        manifest = json.loads(files.pop("manifest.json"))
        if manifest.get("schema") != 1 or set(manifest["files"]) != set(files):
            raise ValidationError("备份清单不匹配")
        for name, raw in files.items():
            if hashlib.sha256(raw).hexdigest() != manifest["files"][name]:
                raise ValidationError("备份校验失败")
        if "state.sqlite3" not in files:
            raise ValidationError("备份缺少数据库")
        return manifest, files

    def restore(self, source, with_keys=False):
        """Restore intent as NEW revisions; do not revive stale sync acknowledgements.

        Current deployment manifests remain intact, so reconciliation knows exactly
        which live listeners need withdrawal. No tar member is extracted to a path.
        """
        manifest, files = self.inspect(source)
        models = {
            "rule": Rule.from_dict,
            "egress": lambda d: Egress(**d).validate(),
            "server": lambda d: Server(**d).validate(),
            "tunnel": lambda d: Tunnel(**d).validate(),
        }
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "restore.sqlite3"
            db_path.write_bytes(files["state.sqlite3"])
            with sqlite3.connect(db_path) as db:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValidationError("备份数据库损坏")
            restored = Store(db_path)
            objects = {kind: restored.list(kind) for kind in models}
            for kind, values in objects.items():
                for value in values:
                    models[kind](value)
            egress_ids = {e["egress_id"] for e in objects["egress"]}
            server_ids = {s["server_id"] for s in objects["server"]}
            tunnel_ids = {t["tunnel_id"] for t in objects["tunnel"]}
            if any(
                r["egress_id"] not in egress_ids
                or any(
                    b["server_id"] != "local" and b["server_id"] not in server_ids
                    for b in r["bindings"]
                )
                for r in objects["rule"]
            ) or any(s["tunnel_id"] not in tunnel_ids for s in objects["server"]):
                raise ValidationError("备份对象引用不完整")
            from .rules import RuleManager

            graph = RuleManager(restored)
            with restored.transaction() as db:
                for candidate in objects["rule"]:
                    graph._validate_graph(Rule.from_dict(candidate), db)
            keys = {}
            if with_keys:
                for tunnel in objects["tunnel"]:
                    name = f"config/keys/{tunnel['tunnel_id']}.key"
                    if name not in files:
                        raise ValidationError("备份缺少隧道密钥")
                    public = self.runner.run(
                        ["wg", "pubkey"], input=files[name].decode()
                    ).stdout.strip()
                    if public != tunnel["public_key"]:
                        raise ValidationError("备份私钥与数据库公钥不匹配")
                    path = self.paths.config / "keys" / f"{tunnel['tunnel_id']}.key"
                    if path.exists() and path.read_bytes() != files[name]:
                        raise ConflictError("现有私钥与备份不同，拒绝覆盖；请显式重新配对")
                    keys[path] = files[name]
            with file_lock(self.paths.state / "control.lock"):
                safety = self.create()
                for path, raw in keys.items():
                    atomic_write(path, raw)
                with self.store.transaction() as db:
                    for kind in ("egress", "tunnel", "server", "rule"):
                        id_key = {
                            "egress": "egress_id",
                            "server": "server_id",
                            "tunnel": "tunnel_id",
                            "rule": "rule_id",
                        }[kind]
                        for value in objects[kind]:
                            result = self.store.put(kind, value[id_key], value, db=db)
                            if kind == "rule":
                                old = self.store.runtime("rule:" + value[id_key], {}, db)
                                self.store.set_runtime(
                                    "rule:" + value[id_key],
                                    {
                                        **old,
                                        "state": "PENDING_SYNC",
                                        "desired_revision": result["revision"],
                                    },
                                    db,
                                )
                    restored_ids = {r["rule_id"] for r in objects["rule"]}
                    for current in self.store.list("rule", db):
                        if current["rule_id"] not in restored_ids:
                            result = self.store.put(
                                "rule",
                                current["rule_id"],
                                {**current, "deleted": True, "enabled": False},
                                db=db,
                            )
                            self.store.set_runtime(
                                "rule:" + current["rule_id"],
                                {"state": "PENDING_SYNC", "desired_revision": result["revision"]},
                                db,
                            )
        return {
            "restored_desired_state": True,
            "backup_version": manifest["version"],
            "safety_backup": safety["backup"],
            "next": "核验 egress / wg 后运行 ra sync reconcile；尚未改变运行中服务",
        }

    def export_rules(self, destination):
        rules = self.store.list("rule")
        payload = {"schema": 1, "rules": rules}
        atomic_write(
            destination,
            canonical(
                {
                    "payload": payload,
                    "sha256": hashlib.sha256(canonical(payload).encode()).hexdigest(),
                }
            ),
        )
        return {"exported": len(rules), "file": str(destination)}

    def import_rules(self, source, manager):
        data = json.loads(Path(source).read_text())
        payload = data["payload"]
        if (
            payload.get("schema") != 1
            or hashlib.sha256(canonical(payload).encode()).hexdigest() != data["sha256"]
        ):
            raise ValidationError("规则备份校验失败")
        candidates = [Rule.from_dict(r) for r in payload["rules"]]
        self.create()
        with file_lock(self.paths.state / "control.lock"), self.store.transaction() as db:
            results = []
            for candidate in candidates:
                candidate.enabled = False
                manager._validate_graph(candidate, db)
                result = self.store.put("rule", candidate.rule_id, candidate.to_dict(), db=db)
                self.store.set_runtime(
                    "rule:" + candidate.rule_id,
                    {"state": "PENDING_SYNC", "desired_revision": result["revision"]},
                    db,
                )
                results.append(result)
        return {"imported_disabled_rules": results}
