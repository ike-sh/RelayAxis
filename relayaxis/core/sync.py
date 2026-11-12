import hashlib
import json
import os
import time
from dataclasses import asdict
from pathlib import Path

from ..errors import ApplyError, RelayAxisError, ValidationError
from ..models import Rule, State, now
from ..storage import canonical
from .realm import Endpoint
from .system import atomic_write, file_lock

MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024


def checksum(payload):
    return hashlib.sha256(canonical(payload).encode()).hexdigest()


def envelope(server_id, revision, endpoints):
    payload = {
        "schema": 1,
        "server_id": server_id,
        "revision": revision,
        "endpoints": sorted(
            [asdict(e) if isinstance(e, Endpoint) else e for e in endpoints],
            key=lambda x: x["endpoint_id"],
        ),
    }
    return {"payload": payload, "sha256": checksum(payload)}


def diff(old, new):
    a = {e["endpoint_id"]: e for e in old}
    b = {e["endpoint_id"]: e for e in new}
    return {
        "added": sorted(b.keys() - a.keys()),
        "removed": sorted(a.keys() - b.keys()),
        "changed": sorted(key for key in a.keys() & b.keys() if a[key] != b[key]),
    }


class Agent:
    def __init__(self, store, deployment, policy):
        self.store, self.deployment, self.policy = store, deployment, policy

    def validate(self, incoming):
        if not isinstance(incoming, dict) or set(incoming) != {"payload", "sha256"}:
            raise ValidationError("无效快照封装")
        payload = incoming["payload"]
        if not isinstance(payload, dict) or set(payload) != {
            "schema",
            "server_id",
            "revision",
            "endpoints",
        }:
            raise ValidationError("无效快照字段")
        if checksum(payload) != incoming["sha256"]:
            raise ValidationError("快照校验值不匹配")
        if payload["schema"] != 1 or payload["server_id"] != self.policy["server_id"]:
            raise ValidationError("快照版本或前置机身份错误")
        if type(payload["revision"]) is not int or payload["revision"] < 1:
            raise ValidationError("无效同步版本")
        if not isinstance(payload["endpoints"], list) or len(payload["endpoints"]) > 2048:
            raise ValidationError("快照端点数量无效")
        endpoints = []
        for item in payload["endpoints"]:
            endpoint = Endpoint(**item).validate()
            if endpoint.listen_address not in self.policy["listen_addresses"]:
                raise ValidationError("监听地址不在本机授权范围内")
            if (
                endpoint.remote_host != self.policy["controller_wg_address"]
                or endpoint.through != self.policy["ingress_wg_address"]
                or endpoint.interface != self.policy["wg_interface"]
            ):
                raise ValidationError("快照试图更改受限 WG 目标或传输接口")
            if endpoint.dependency != f"relayaxis-wg-{self.policy['tunnel_id']}.service":
                raise ValidationError("快照含有未授权启动依赖")
            if (
                not self.policy.get("port_min", 1)
                <= endpoint.listen_port
                <= self.policy.get("port_max", 65535)
            ):
                raise ValidationError("公网端口超出授权范围")
            endpoints.append(endpoint)
        return payload, endpoints

    def receive(self, incoming):
        payload, endpoints = self.validate(incoming)
        with file_lock(self.deployment.paths.state / "agent.lock"):
            previous = self.store.runtime("agent-applied", {"revision": 0})
            if payload["revision"] < previous["revision"]:
                raise ValidationError("拒绝过期同步快照")
            if payload["revision"] == previous["revision"] and incoming["sha256"] != previous.get(
                "sha256"
            ):
                raise ValidationError("相同版本携带不同配置，拒绝应用")
            result = {
                "revision": payload["revision"],
                "sha256": incoming["sha256"],
                "state": "ACTIVE",
                "server_id": payload["server_id"],
                "applied_at": now(),
            }
            unhealthy = {e.endpoint_id for e in endpoints if not self.deployment._healthy(e)}
            self.deployment.apply(
                "agent",
                endpoints,
                force=unhealthy,
                commit_extra=lambda db: self.store.set_runtime("agent-applied", result, db),
            )
            return result


class SSHTransport:
    def __init__(self, store, runner, retries=2):
        self.store, self.runner, self.retries = store, runner, retries

    def send(self, server, snapshot):
        response = self.request(server, snapshot)
        if (
            response.get("server_id") != server["server_id"]
            or response.get("revision") != snapshot["payload"]["revision"]
            or response.get("sha256") != snapshot["sha256"]
            or response.get("state") != "ACTIVE"
        ):
            raise ApplyError("前置机返回的实际版本或校验值与期望不一致")
        return response

    def request(self, server, request):
        tunnel = self.store.get("tunnel", server["tunnel_id"])
        address = tunnel["peer_address"].split("/")[0]
        identity, known_hosts = server["identity_file"], server["known_hosts_file"]
        if (
            not identity
            or not known_hosts
            or not Path(identity).is_file()
            or not Path(known_hosts).is_file()
        ):
            raise ApplyError("需要专用 SSH 私钥和已核验的 WG known_hosts 文件")
        if os.name == "posix" and Path(identity).stat().st_mode & 0o077:
            raise ApplyError("SSH 私钥权限必须为 0600 或更严格")
        if os.name == "posix" and Path(known_hosts).stat().st_mode & 0o022:
            raise ApplyError("known_hosts 不能允许组用户或其他用户写入")
        argv = [
            "ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=3",
            "-o",
            "ServerAliveCountMax=2",
            "-i",
            identity,
            "-p",
            str(server["ssh_port"]),
            f"{server['ssh_user']}@{address}",
            "ra-agent-v1",
        ]
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                result = self.runner.run(argv, input=canonical(request) + "\n", timeout=30)
                response = json.loads(result.stdout)
                if not isinstance(response, dict) or response.get("state") == "FAILED":
                    raise ApplyError("受限 Agent 拒绝请求或返回了无效应答")
                return response
            except (RelayAxisError, ValueError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(0.2 * (attempt + 1))
        raise ApplyError(
            f"SSH 同步失败（已重试 {self.retries} 次；{type(last_error).__name__}）"
        ) from last_error


class Coordinator:
    """Prepare controller -> publish ingresses -> retire old controller listeners.

    Partial remote failure retains BOTH old and new internal listeners. A later full
    snapshot converges to the newest intent. Each ingress rolls back locally.
    """

    def __init__(self, paths, store, compiler, deployment, transport):
        self.paths, self.store, self.compiler = paths, store, compiler
        self.deployment, self.transport = deployment, transport

    def _ready(self):
        return self.store.runtime("ready-rules", {})

    def _snapshot(self, server_id):
        endpoints = self.compiler.ingress(server_id, list(self._ready().values()))
        old = self.store.runtime("sync:" + server_id, {})
        semantic = checksum([asdict(e) for e in sorted(endpoints, key=lambda e: e.endpoint_id)])
        revision = old.get("desired_revision", 0)
        if old.get("semantic") != semantic:
            revision += 1
        snapshot = envelope(server_id, revision or 1, endpoints)
        state = {
            **old,
            "desired_revision": revision or 1,
            "semantic": semantic,
            "desired_sha256": snapshot["sha256"],
            "state": "PENDING_SYNC",
            "error": "",
        }
        self.store.set_runtime("sync:" + server_id, state)
        return snapshot

    def _send(self, server_id):
        snapshot = self._snapshot(server_id)
        key = "sync:" + server_id
        state = self.store.runtime(key)
        try:
            self.store.set_runtime(key, {**state, "state": "APPLYING"})
            ack = self.transport.send(self.store.get("server", server_id), snapshot)
            self.store.set_runtime(
                key,
                {
                    **state,
                    "state": "ACTIVE",
                    "applied_revision": ack["revision"],
                    "applied_sha256": ack["sha256"],
                    "last_seen": now(),
                    "error": "",
                },
            )
            return {"server_id": server_id, "state": "ACTIVE", "revision": ack["revision"]}
        except RelayAxisError as exc:
            self.store.set_runtime(key, {**state, "state": "PENDING_SYNC", "error": str(exc)})
            return {"server_id": server_id, "state": "PENDING_SYNC", "error": str(exc)}

    def apply_rule(self, rule_id, force=False):
        with file_lock(self.paths.state / "control.lock"):
            data = self.store.get("rule", rule_id)
            rule = Rule.from_dict(data)
            state_key = "rule:" + rule_id
            prior_state = self.store.runtime(state_key, {})
            self.store.set_runtime(state_key, {**prior_state, "state": "APPLYING", "error": ""})
            ready = self._ready()
            previous = ready.get(rule_id)
            previous_servers = Rule.from_dict(previous).ingress_server_ids if previous else []
            servers = sorted(
                set(rule.ingress_server_ids)
                | set(previous_servers)
                | set(prior_state.get("affected_servers", []))
            )
            withdrawing = not rule.enabled or rule.deleted
            scope = "rule-" + rule_id
            locally_validated = withdrawing
            try:
                unavailable = []
                desired = (
                    self.compiler.local(data, unavailable=unavailable) if not withdrawing else []
                )
                locally_validated = True
                current = self.deployment.manifest(scope)
                if not withdrawing:
                    transitional = {**current, **{e.endpoint_id: asdict(e) for e in desired}}
                    for item in unavailable:
                        transitional.pop(item["endpoint_id"], None)
                    for key, endpoint in list(transitional.items()):
                        try:
                            self.compiler.network.ensure_local_listen(endpoint["listen_address"])
                        except ValidationError:
                            transitional.pop(key)
                    # Keep a removed protocol alive until its ingress is withdrawn.
                    for key in current.keys() & transitional.keys():
                        if (
                            key in {e.endpoint_id for e in desired}
                            and current[key]["protocol"] != transitional[key]["protocol"]
                        ):
                            transitional[key] = {**transitional[key], "protocol": "both"}
                    self.deployment.apply(
                        scope, [Endpoint(**v) for v in transitional.values()], force=force
                    )
                # Publish only locally prepared rules; unrelated un-applied edits never leak.
                missing_indices = {u["index"] for u in unavailable}
                ready[rule_id] = {
                    **data,
                    "bindings": [
                        b
                        for index, b in enumerate(data["bindings"])
                        if index not in missing_indices
                    ],
                }
                if not ready[rule_id]["bindings"]:
                    # A disabled empty intent must not be parsed as an invalid logical rule.
                    ready.pop(rule_id, None)
                self.store.set_runtime("ready-rules", ready)
                blocked_servers = {u["server_id"] for u in unavailable if u["server_id"] != "local"}
                results = []
                for server_id in servers:
                    if server_id in blocked_servers:
                        self._snapshot(server_id)
                        pending = {
                            "server_id": server_id,
                            "state": "PENDING_SYNC",
                            "error": "Controller 侧该 WG 入口未就绪，其他入口继续运行",
                        }
                        state = self.store.runtime("sync:" + server_id, {})
                        self.store.set_runtime("sync:" + server_id, {**state, **pending})
                        results.append(pending)
                    else:
                        results.append(self._send(server_id))
                failed = [r for r in results if r["state"] != "ACTIVE"]
                if failed or unavailable:
                    state = (
                        State.OUT_OF_SYNC
                        if any(r["state"] == "ACTIVE" for r in results) or unavailable and desired
                        else State.PENDING_SYNC
                    )
                    self.store.set_runtime(
                        state_key,
                        {
                            **prior_state,
                            "state": state.value,
                            "desired_revision": rule.revision,
                            "affected_servers": servers,
                            "unavailable_bindings": unavailable,
                            "error": "部分前置机未确认；保留旧内部监听，等待重试",
                        },
                    )
                    return {
                        "rule_id": rule_id,
                        "state": state.value,
                        "ingresses": results,
                        "local_prepared": bool(desired),
                        "unavailable_bindings": unavailable,
                    }
                # All entrances have acknowledged removal/update; old internal ports are safe to retire.
                self.deployment.apply(scope, desired)
                state = State.DISABLED if withdrawing else State.ACTIVE
                self.store.set_runtime(
                    state_key,
                    {
                        "state": state.value,
                        "desired_revision": rule.revision,
                        "affected_servers": [],
                        "applied_revision": rule.revision,
                        "error": "",
                        "at": now(),
                    },
                )
                return {"rule_id": rule_id, "state": state.value, "ingresses": results}
            except RelayAxisError as exc:
                if not locally_validated and not rule.external_service:
                    self.deployment.pause(scope)
                    ready.pop(rule_id, None)
                    self.store.set_runtime("ready-rules", ready)
                self.store.set_runtime(
                    state_key,
                    {
                        **prior_state,
                        "state": "FAILED",
                        "desired_revision": rule.revision,
                        "affected_servers": servers,
                        "error": str(exc),
                    },
                )
                return {"rule_id": rule_id, "state": "FAILED", "error": str(exc)}

    def reconcile(self):
        result = []
        touched = set()
        for rule in self.store.list("rule"):
            if rule.get("external_service"):
                continue
            runtime = self.store.runtime("rule:" + rule["rule_id"], {})
            changed = runtime.get("applied_revision") != rule["revision"] or runtime.get(
                "state"
            ) not in ("ACTIVE", "DISABLED")
            unhealthy = False
            if not changed and rule["enabled"] and not rule["deleted"]:
                try:
                    desired = {e.endpoint_id: asdict(e) for e in self.compiler.local(rule)}
                    changed = desired != self.deployment.manifest("rule-" + rule["rule_id"])
                    changed = changed or bool(
                        self.deployment.drift([Endpoint(**e) for e in desired.values()])
                    )
                    unhealthy = any(
                        not self.deployment._healthy(Endpoint(**e)) for e in desired.values()
                    )
                except RelayAxisError:
                    changed = True
            if changed or unhealthy:
                applied = self.apply_rule(
                    rule["rule_id"], force=unhealthy or runtime.get("state") == "FAILED"
                )
                result.append(applied)
                touched.update(s["server_id"] for s in applied.get("ingresses", []))
        # Poll each remaining ingress once, even when intent is unchanged. A saved
        # ACTIVE acknowledgement is not evidence that its Realm process still runs.
        for server in self.store.list("server"):
            if not server["enabled"] or server["server_id"] in touched:
                continue
            with file_lock(self.paths.state / "control.lock"):
                ack = self._send(server["server_id"])
                if ack["state"] != "ACTIVE":
                    for rule in self.store.list("rule"):
                        runtime = self.store.runtime("rule:" + rule["rule_id"], {})
                        if (
                            runtime.get("state") == "ACTIVE"
                            and server["server_id"] in Rule.from_dict(rule).ingress_server_ids
                        ):
                            self.store.set_runtime(
                                "rule:" + rule["rule_id"],
                                {
                                    **runtime,
                                    "state": "OUT_OF_SYNC",
                                    "affected_servers": sorted(
                                        set(runtime.get("affected_servers", []))
                                        | {server["server_id"]}
                                    ),
                                    "error": "周期核验未收到前置机实际应用确认；其他入口继续运行",
                                },
                            )
                result.append(ack)
        return result

    def sync_server(self, server_id):
        # Reconcile outstanding local preparations before publishing any full snapshot.
        self.store.get("server", server_id)
        results = self.reconcile()
        with file_lock(self.paths.state / "control.lock"):
            ack = self._send(server_id)
        return {"rules": results, "server": ack}


def write_policy(paths, store, server_id, tunnel_id, listen_addresses, port_min=1, port_max=65535):
    from ..models import Tunnel, identifier, ip, port

    identifier(server_id)
    port(port_min)
    port(port_max)
    if port_min > port_max:
        raise ValidationError("端口授权范围倒置")
    tunnel = Tunnel(**store.get("tunnel", tunnel_id)).validate()
    if tunnel.role != "ingress" or not tunnel.peer_public_key:
        raise ValidationError("Agent 需要已配对的 Ingress WG 隧道")
    policy = {
        "server_id": server_id,
        "tunnel_id": tunnel_id,
        "wg_interface": tunnel.interface,
        "ingress_wg_address": tunnel.local_address.split("/")[0],
        "controller_wg_address": tunnel.peer_address.split("/")[0],
        "listen_addresses": [ip(a, 4) for a in listen_addresses],
        "port_min": port_min,
        "port_max": port_max,
    }
    if not policy["listen_addresses"]:
        raise ValidationError("至少授权一个公网监听地址")
    atomic_write(paths.config / "agent-policy.json", canonical(policy))
    return policy


def authorized_key(public_key, controller_address):
    from ..models import ip

    ip(controller_address, 4)
    parts = public_key.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValidationError("同步仅接受专用 Ed25519 SSH 公钥")
    import base64

    try:
        raw = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise ValidationError("SSH 公钥编码无效") from exc
    if len(raw) != 51 or raw[:15] != b"\x00\x00\x00\x0bssh-ed25519":
        raise ValidationError("SSH Ed25519 公钥结构无效")
    return f'restrict,from="{controller_address}/32",command="/usr/local/bin/ra agent receive" ssh-ed25519 {parts[1]} relayaxis-sync'
