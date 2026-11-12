import json
import os

from ..core.sync import MAX_SNAPSHOT_BYTES, Agent
from ..errors import ValidationError


def receive(context, stream):
    original = os.environ.get("SSH_ORIGINAL_COMMAND")
    if original is not None and original != "ra-agent-v1":
        raise ValidationError("此 SSH 密钥只允许固定的 RelayAxis Agent 协议")
    policy_path = context.paths.config / "agent-policy.json"
    if not policy_path.is_file():
        raise ValidationError("请先在前置机配置 agent-policy")
    raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw.encode()) > MAX_SNAPSHOT_BYTES:
        raise ValidationError("快照超过 4 MiB 限制")
    incoming = json.loads(raw)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if isinstance(incoming, dict) and incoming.get("operation", "").startswith("mimic-"):
        if set(incoming) != {"operation"} or not policy.get("allow_mimic", False):
            raise ValidationError("未授权远程 Mimic 管理")
        operation = incoming["operation"]
        if operation == "mimic-status":
            return context.mimic.status(policy["tunnel_id"])
        if operation in ("mimic-enable", "mimic-disable"):
            return context.mimic.toggle(policy["tunnel_id"], operation == "mimic-enable")
        raise ValidationError("无效 Mimic Agent 操作")
    return Agent(context.store, context.deployment, policy).receive(incoming)
