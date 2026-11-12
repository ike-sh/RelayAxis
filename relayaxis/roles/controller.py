from dataclasses import asdict

from ..core.system import file_lock
from ..errors import ConflictError, ValidationError
from ..models import Server


class IngressManager:
    def __init__(self, paths, store):
        self.paths, self.store = paths, store

    def save(self, data, updating=False):
        server = Server(**data).validate()
        with file_lock(self.paths.state / "control.lock"):
            existing = next(
                (s for s in self.store.list("server") if s["server_id"] == server.server_id), None
            )
            if bool(existing) != updating:
                raise ConflictError("前置机已存在" if existing else "前置机不存在")
            tunnel = self.store.get("tunnel", server.tunnel_id)
            if tunnel["role"] != "controller":
                raise ValidationError("前置机需要 Controller 侧隧道")
            if any(
                s["tunnel_id"] == server.tunnel_id and s["server_id"] != server.server_id
                for s in self.store.list("server")
            ):
                raise ConflictError("每台前置机需要独立隧道")
            related = [
                r
                for r in self.store.list("rule")
                if any(b["server_id"] == server.server_id for b in r["bindings"])
                and not r.get("deleted")
            ]
            active_related = [
                r
                for r in related
                if r["enabled"]
                or self.store.runtime("rule:" + r["rule_id"], {}).get("state") != "DISABLED"
            ]
            if (
                existing
                and related
                and (
                    existing["tunnel_id"] != server.tunnel_id
                    or active_related
                    and existing["enabled"] != server.enabled
                )
            ):
                raise ConflictError("先撤销并同步关联规则，再更改隧道或禁用前置机")
            return self.store.put(
                "server", server.server_id, asdict(server), existing["revision"] if existing else 0
            )

    def delete(self, server_id):
        with file_lock(self.paths.state / "control.lock"):
            if any(
                server_id
                in self.store.runtime("rule:" + r["rule_id"], {}).get("affected_servers", [])
                for r in self.store.list("rule")
            ):
                raise ConflictError("前置机仍有未确认的旧入口撤销任务")
            if any(
                any(b["server_id"] == server_id for b in r["bindings"])
                and (
                    not r.get("deleted")
                    or self.store.runtime("rule:" + r["rule_id"], {}).get("state") != "DISABLED"
                )
                for r in self.store.list("rule")
            ):
                raise ConflictError("前置机仍有关联业务或未完成入口撤销")
            self.store.get("server", server_id)
            self.store.remove("server", server_id)
            return {"deleted": server_id, "note": "仅删除管理记录；WG 隧道和远端服务需独立清理"}
