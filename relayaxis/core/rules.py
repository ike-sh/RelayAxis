from dataclasses import asdict

from ..errors import ConflictError, ValidationError
from ..models import Rule, address_conflict, new_id, protocols
from .system import file_lock


class RuleManager:
    """Desired state CRUD is transactional; runtime state is tracked separately."""

    def __init__(self, store):
        self.store = store

    def list(self, search="", include_deleted=False):
        return [
            r
            for r in self.store.list("rule")
            if (include_deleted or not r.get("deleted"))
            and search.lower()
            in (r["name"] + " " + r.get("remark", "") + " " + r["rule_id"]).lower()
        ]

    def get(self, rule_id):
        return self.store.get("rule", rule_id)

    def _validate_graph(self, rule, db):
        self.store.get("egress", rule.egress_id, db)
        existing = [
            Rule.from_dict(r)
            for r in self.store.list("rule", db)
            if r["rule_id"] != rule.rule_id and not r.get("deleted")
        ]
        for b in rule.bindings:
            if b.server_id != "local":
                server = self.store.get("server", b.server_id, db)
                if not server["enabled"] and rule.enabled and not rule.deleted:
                    raise ValidationError("不能在已禁用的前置机上启用规则")
                tunnel = self.store.get("tunnel", server["tunnel_id"], db)
                if tunnel["role"] != "controller" or not tunnel.get("peer_public_key"):
                    raise ValidationError("前置机需要已配对的 Controller WG 隧道")
                address = tunnel["local_address"].split("/")[0]
                if b.wg_target_address and b.wg_target_address != address:
                    raise ValidationError("内部目标地址必须是该前置机对应的 Controller WG 地址")
                b.wg_target_address = address
                used = {
                    x.wg_internal_port
                    for r in existing
                    for x in r.bindings
                    if x.wg_target_address == address
                }
                used.update(
                    x.wg_internal_port
                    for x in rule.bindings
                    if x is not b and x.wg_target_address == address
                )
                if not b.wg_internal_port:
                    b.wg_internal_port = next((p for p in range(20000, 60000) if p not in used), 0)
                    if not b.wg_internal_port:
                        raise ConflictError("没有可分配的内部端口")
        # Disabled rules reserve ports too, so enabling later cannot steal another rule's port.
        endpoints = []
        for other in [*existing, rule]:
            if other.deleted:
                continue
            for b in other.bindings:
                endpoints.append(
                    (b.server_id, b.listen_address, b.listen_port, other.protocol, other.rule_id)
                )
                if b.server_id != "local":
                    endpoints.append(
                        (
                            "local",
                            b.wg_target_address,
                            b.wg_internal_port,
                            other.protocol,
                            other.rule_id,
                        )
                    )
        for index, a in enumerate(endpoints):
            for b in endpoints[index + 1 :]:
                if (
                    a[0] == b[0]
                    and a[2] == b[2]
                    and protocols(a[3]) & protocols(b[3])
                    and address_conflict(a[1], b[1])
                ):
                    raise ConflictError(f"监听冲突: {a[0]} {a[1]}:{a[2]}（{a[4]} / {b[4]}）")

    def save(self, data, expected=None, creating=False):
        rule = Rule.from_dict(data)
        with file_lock(self.store.path.parent / "control.lock"), self.store.transaction() as db:
            found = db.execute(
                "SELECT revision FROM objects WHERE kind='rule' AND id=?", (rule.rule_id,)
            ).fetchone()
            if creating and found:
                raise ConflictError("规则 ID 已存在")
            if not creating and not found:
                raise ValidationError("修改的规则不存在")
            self._validate_graph(rule, db)
            result = self.store.put(
                "rule",
                rule.rule_id,
                asdict(rule),
                expected if expected is not None else (found[0] if found else 0),
                db,
            )
            old = self.store.runtime("rule:" + rule.rule_id, {}, db)
            self.store.set_runtime(
                "rule:" + rule.rule_id,
                {
                    **old,
                    "state": "PENDING_SYNC",
                    "desired_revision": result["revision"],
                    "error": "",
                },
                db,
            )
        return result

    def create(self, data):
        return self.save(data, expected=0, creating=True)

    def update(self, rule_id, patch, expected=None):
        data = self.get(rule_id)
        if "rule_id" in patch and patch["rule_id"] != rule_id:
            raise ValidationError("不能修改规则 ID")
        revision = data["revision"]
        data.update(patch)
        return self.save(data, expected=revision if expected is None else expected)

    def delete(self, rule_id):
        return self.update(rule_id, {"deleted": True, "enabled": False})

    def enable(self, rule_id, enabled=True):
        return self.update(rule_id, {"enabled": enabled})

    def copy(self, rule_id, name, bindings):
        data = self.get(rule_id)
        data.update(
            rule_id=new_id(),
            name=name,
            bindings=bindings,
            revision=0,
            created_at="",
            updated_at="",
            deleted=False,
            external_service="",
        )
        return self.create(data)

    def rollback(self, rule_id, revision):
        candidate = next(
            (r for r in self.store.history("rule", rule_id) if r["revision"] == revision), None
        )
        if not candidate:
            raise ValidationError("历史版本不存在")
        current = self.get(rule_id)
        candidate.update(created_at=current["created_at"])
        return self.save(candidate, current["revision"])
