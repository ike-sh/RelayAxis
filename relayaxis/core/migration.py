import hashlib
import json
from pathlib import Path

from ..errors import ApplyError, ConflictError, ValidationError
from ..models import new_id
from ..storage import canonical
from .system import atomic_write, file_lock


class Migration:
    def __init__(self, app):
        self.app = app

    def _restore(self, journal):
        app = self.app
        for rule in journal["rules"]:
            app.deployment.apply("rule-" + rule["rule_id"], [])
        with app.store.transaction() as db:
            for rule in journal["rules"]:
                app.store.put("rule", rule["rule_id"], rule, db=db)
                app.store.set_runtime(
                    "rule:" + rule["rule_id"],
                    {"state": "DISABLED", "error": "迁移失败，已保留外部原服务"},
                    db,
                )
        ready = app.store.runtime("ready-rules", {})
        for rule in journal["rules"]:
            ready.pop(rule["rule_id"], None)
        app.store.set_runtime("ready-rules", ready)
        if journal["original_state"]["enabled"]:
            app.services.action("enable", journal["service"])
        if journal["original_state"]["active"]:
            app.services.action("start", journal["service"])
            if not app.services.healthy(journal["service"]):
                raise ApplyError("原服务恢复后健康检查失败")

    def migrate(self, service):
        app = self.app
        with file_lock(app.paths.state / "migration.lock"):
            record = app.store.runtime("import:" + service)
            if not record:
                raise ValidationError("必须先扫描并导入该服务，导入会创建备份")
            if hashlib.sha256(Path(record["config"]).read_bytes()).hexdigest() != record["sha256"]:
                raise ConflictError("导入后原配置已变更，请重新检查；不会自动覆盖")
            current_unit = app.runner.run(
                ["systemctl", "cat", service], check=False
            ).stdout or Path(record["unit_path"]).read_text(encoding="utf-8")
            if current_unit != record["unit_text"]:
                raise ConflictError("导入后原服务或 drop-in 已变更，拒绝迁移")
            rules = [r for r in app.store.list("rule") if r.get("external_service") == service]
            if not rules:
                raise ValidationError("该服务没有待迁移规则")
            for rule in rules:
                app.compiler.local({**rule, "external_service": "", "enabled": True})
            journal_id = new_id()
            journal = {
                "service": service,
                "rules": rules,
                "original_state": app.services.state(service),
            }
            journal_path = app.paths.state / "migrations" / f"{journal_id}.json"
            atomic_write(journal_path, canonical(journal))
            app.backups.create()
            try:
                app.services.action("stop", service)
                for rule in rules:
                    updated = app.rules.update(
                        rule["rule_id"], {"external_service": "", "enabled": True}
                    )
                    result = app.coordinator.apply_rule(updated["rule_id"])
                    if result["state"] != "ACTIVE":
                        raise ApplyError("受管规则未全部通过应用验证")
                app.services.action("disable", service)
                app.store.set_runtime("migration-commit:" + journal_id, True)
            except Exception as exc:
                self._restore(journal)
                journal_path.unlink()
                raise ApplyError("迁移失败，已尝试恢复全部原规则和原服务") from exc
            journal_path.unlink()
            return {
                "state": "ACTIVE",
                "migrated_service": service,
                "rule_ids": [r["rule_id"] for r in rules],
                "original_files_preserved": True,
            }

    def recover(self):
        results = []
        with file_lock(self.app.paths.state / "migration.lock"):
            for path in sorted((self.app.paths.state / "migrations").glob("*.json")):
                if not self.app.store.runtime("migration-commit:" + path.stem):
                    self._restore(json.loads(path.read_text(encoding="utf-8")))
                path.unlink()
                results.append(path.name)
        return results
