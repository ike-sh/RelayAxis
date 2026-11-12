import base64
import hashlib
import ipaddress
import time
from dataclasses import asdict

from ..errors import ApplyError, ConflictError, ValidationError
from ..models import Tunnel, identifier
from ..storage import canonical
from .resources import ResourceFiles
from .system import atomic_write, file_lock
from .wg_link import WireGuardLink, load_config


def validate_key(key):
    try:
        raw = base64.b64decode(key, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError("无效 WireGuard 公钥") from exc
    if len(raw) != 32 or raw == bytes(32):
        raise ValidationError("WireGuard 公钥必须是非零 32 字节")
    return key


def render(tunnel, private_key):
    tunnel.validate()
    validate_key(tunnel.public_key)
    validate_key(tunnel.peer_public_key)
    validate_key(private_key)
    local = str(ipaddress.ip_interface(tunnel.local_address).ip)
    peer = str(ipaddress.ip_interface(tunnel.peer_address).ip)
    lines = [
        "# Managed by RelayAxis",
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {local}/32",
        f"ListenPort = {tunnel.listen_port}",
        f"MTU = {tunnel.mtu}",
        "Table = off",
        "",
        "[Peer]",
        f"PublicKey = {tunnel.peer_public_key}",
        f"AllowedIPs = {peer}/32",
    ]
    if tunnel.endpoint:
        lines.append(f"Endpoint = {tunnel.endpoint}")
    if tunnel.role == "controller":
        lines.append(f"PersistentKeepalive = {tunnel.keepalive}")
    return "\n".join(lines) + "\n"


def pairing_bundle(tunnel):
    tunnel.validate()
    payload = {
        "schema": 1,
        "tunnel_id": tunnel.tunnel_id,
        "role": tunnel.role,
        "public_key": validate_key(tunnel.public_key),
        "local_address": tunnel.local_address,
        "peer_address": tunnel.peer_address,
        "listen_port": tunnel.listen_port,
        "mtu": tunnel.mtu,
    }
    return {"payload": payload, "sha256": hashlib.sha256(canonical(payload).encode()).hexdigest()}


def accept_pairing(tunnel, bundle):
    if set(bundle) != {"payload", "sha256"}:
        raise ValidationError("配对信息字段无效")
    payload = bundle["payload"]
    if set(payload) != {
        "schema",
        "tunnel_id",
        "role",
        "public_key",
        "local_address",
        "peer_address",
        "listen_port",
        "mtu",
    }:
        raise ValidationError("配对信息包含未知字段；私钥不得通过配对传输")
    if hashlib.sha256(canonical(payload).encode()).hexdigest() != bundle["sha256"]:
        raise ValidationError("配对校验值错误")
    if (
        payload["schema"] != 1
        or payload["tunnel_id"] != tunnel.tunnel_id
        or payload["role"] not in ("controller", "ingress")
        or payload["role"] == tunnel.role
    ):
        raise ValidationError("配对 ID 或双端角色不匹配")
    if (
        ipaddress.ip_interface(payload["local_address"]).ip
        != ipaddress.ip_interface(tunnel.peer_address).ip
        or ipaddress.ip_interface(payload["peer_address"]).ip
        != ipaddress.ip_interface(tunnel.local_address).ip
    ):
        raise ValidationError("配对两端内网地址不互补")
    if payload["mtu"] != tunnel.mtu:
        raise ValidationError("双端 MTU 不一致")
    tunnel.peer_public_key = validate_key(payload["public_key"])
    return tunnel


def allocate_subnet(used, pool="10.203.0.0/16"):
    network = ipaddress.ip_network(pool)
    if network.version != 4 or network.prefixlen > 30:
        raise ValidationError("WG 地址池需要 IPv4 /30 或更大网段")
    occupied = [ipaddress.ip_network(n, strict=False) for n in used]
    for candidate in network.subnets(new_prefix=30):
        if not any(candidate.overlaps(n) for n in occupied if n.version == 4):
            hosts = list(candidate.hosts())
            return {
                "subnet": str(candidate),
                "controller": f"{hosts[0]}/30",
                "ingress": f"{hosts[1]}/30",
            }
    raise ConflictError("地址池无可用子网")


class WireGuard:
    def __init__(self, paths, store, runner, services, network):
        self.paths, self.store, self.runner = paths, store, runner
        self.services, self.network = services, network

    def key_path(self, tunnel_id):
        identifier(tunnel_id)
        return self.paths.config / "keys" / f"{tunnel_id}.key"

    def create(self, data):
        data = dict(data)
        used_ports = {t["listen_port"] for t in self.store.list("tunnel")}
        if "listen_port" not in data:
            data["listen_port"] = next((p for p in range(51820, 65536) if p not in used_ports), 0)
        tunnel = Tunnel(**data).validate()
        with file_lock(self.paths.state / "wg.lock"):
            if any(
                t["tunnel_id"] == tunnel.tunnel_id or t["interface"] == tunnel.interface
                for t in self.store.list("tunnel")
            ):
                raise ConflictError("隧道 ID 或接口已存在；请使用 wg update")
            if tunnel.listen_port in {t["listen_port"] for t in self.store.list("tunnel")}:
                raise ConflictError("WG 监听端口已被其他受管隧道预留，请选择不同端口")
            for other in self.store.list("tunnel"):
                if any(
                    ipaddress.ip_interface(a).network.overlaps(ipaddress.ip_interface(b).network)
                    for a in (tunnel.local_address, tunnel.peer_address)
                    for b in (other["local_address"], other["peer_address"])
                ):
                    raise ConflictError("WG 子网与已配置隧道重叠")
            if self.key_path(tunnel.tunnel_id).exists():
                raise ConflictError("已存在未登记的密钥文件，拒绝覆盖")
            private = self.runner.run(["wg", "genkey"]).stdout.strip()
            validate_key(private)
            tunnel.public_key = self.runner.run(
                ["wg", "pubkey"], input=private + "\n"
            ).stdout.strip()
            validate_key(tunnel.public_key)
            atomic_write(self.key_path(tunnel.tunnel_id), private + "\n")
            try:
                return self.store.put("tunnel", tunnel.tunnel_id, asdict(tunnel), 0)
            except Exception:
                self.key_path(tunnel.tunnel_id).unlink()
                raise

    def update(self, tunnel_id, patch):
        if set(patch) & {
            "tunnel_id",
            "public_key",
            "peer_public_key",
            "role",
            "interface",
            "local_address",
            "peer_address",
        }:
            raise ValidationError(
                "update 仅允许修改 Endpoint、端口、MTU、保活和启停；地址/密钥变更需要重新配对"
            )
        with file_lock(self.paths.state / "wg.lock"):
            old = self.store.get("tunnel", tunnel_id)
            data = {**old, **patch}
            tunnel = Tunnel(**data).validate()
            if any(
                t["tunnel_id"] != tunnel_id and t["listen_port"] == tunnel.listen_port
                for t in self.store.list("tunnel")
            ):
                raise ConflictError("WG 监听端口与其他隧道冲突")
            return self.store.put("tunnel", tunnel_id, asdict(tunnel), old["revision"])

    def pair(self, tunnel_id, bundle, replace=False):
        with file_lock(self.paths.state / "wg.lock"):
            old = self.store.get("tunnel", tunnel_id)
            if old.get("peer_public_key") and not replace:
                raise ConflictError("已配对，重新配对需显式 --replace-peer")
            tunnel = accept_pairing(Tunnel(**old), bundle)
            return self.store.put("tunnel", tunnel_id, asdict(tunnel), old["revision"])

    def activate(self, tunnel_id):
        identity = self.store.get("tunnel", tunnel_id)
        path = self.paths.config / "wireguard" / f"{identity['interface']}.conf"
        tunnel, private = load_config(path.read_text(encoding="utf-8"), identity)
        return WireGuardLink(self.runner, self.store).up(tunnel, private)

    def deactivate(self, tunnel_id):
        identity = self.store.get("tunnel", tunnel_id)
        return WireGuardLink(self.runner, self.store).down(tunnel_id, identity["interface"])

    def apply(self, tunnel_id, restart=False):
        self.runner.require_root()
        with file_lock(self.paths.state / "wg.lock"):
            tunnel = Tunnel(**self.store.get("tunnel", tunnel_id)).validate()
            unit = f"relayaxis-wg-{tunnel_id}.service"
            if not tunnel.enabled:
                previous = self.store.runtime("wg:" + tunnel_id, {})
                if previous.get("unit"):
                    self.services.action("stop", unit)
                    self.services.action("disable", unit)
                self.store.set_runtime(
                    "wg:" + tunnel_id,
                    {**previous, "state": "DISABLED", "revision": tunnel.revision},
                )
                return {"state": "DISABLED"}
            for link in self.network.addresses():
                if link["ifname"] == tunnel.interface:
                    if not self.store.runtime("wg:" + tunnel_id):
                        raise ConflictError("接口已由外部创建，拒绝接管")
                    continue
                for address in link.get("addr_info", []):
                    if address.get("family") == "inet" and ipaddress.ip_interface(
                        tunnel.local_address
                    ).network.overlaps(
                        ipaddress.ip_network(
                            f"{address['local']}/{address['prefixlen']}", strict=False
                        )
                    ):
                        raise ConflictError("WG 网段与现有网卡网段重叠")
                    if address.get("family") == "inet" and ipaddress.ip_interface(
                        tunnel.peer_address
                    ).network.overlaps(
                        ipaddress.ip_network(
                            f"{address['local']}/{address['prefixlen']}", strict=False
                        )
                    ):
                        raise ConflictError("WG peer 地址与现有物理网段重叠")
            content = render(tunnel, self.key_path(tunnel_id).read_text(encoding="utf-8").strip())
            config = self.paths.config / "wireguard" / f"{tunnel.interface}.conf"
            unit_path = self.paths.units / unit
            prior = self.store.runtime("wg:" + tunnel_id, {})
            for path in (config, unit_path):
                if path.is_symlink() or (path.exists() and not prior):
                    raise ConflictError("拒绝覆盖非受管 WG 文件")
            text = f"""# Managed by RelayAxis
[Unit]
Description=RelayAxis WireGuard {tunnel_id}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ra --json wg activate {tunnel_id}
ExecStop=/usr/local/bin/ra --json wg deactivate {tunnel_id}
ExecStopPost=-/usr/local/bin/ra --json wg deactivate {tunnel_id}

[Install]
WantedBy=multi-user.target
"""
            if (
                prior.get("revision") == tunnel.revision
                and self.services.state(unit)["active"]
                and not restart
                and config.exists()
                and config.read_text(encoding="utf-8") == content
                and unit_path.exists()
                and unit_path.read_text(encoding="utf-8") == text
            ):
                return {"state": "ACTIVE", "changed": False}
            resource = ResourceFiles(self.paths, self.store, self.services)
            state = self.services.state(unit)
            with resource.transaction(unit, [config, unit_path]) as transaction_id:
                if state["active"]:
                    self.services.action("stop", unit)
                atomic_write(config, content)
                atomic_write(unit_path, text)
                self.services.daemon_reload()
                self.services.action("enable", unit)
                self.services.action("start", unit)
                if not self.services.healthy(unit):
                    raise ApplyError("WG 接口启动失败")
                resource.commit(
                    transaction_id,
                    lambda db: self.store.set_runtime(
                        "wg:" + tunnel_id,
                        {
                            "state": "ACTIVE",
                            "revision": tunnel.revision,
                            "unit": unit,
                            "config": str(config),
                        },
                        db,
                    ),
                )
            return {
                "state": "ACTIVE",
                "changed": True,
                "note": "接口已启动，握手状态请使用 wg status 检查",
            }

    def delete(self, tunnel_id):
        self.runner.require_root()
        if any(s["tunnel_id"] == tunnel_id for s in self.store.list("server")):
            raise ConflictError("隧道仍有关联前置机")
        with file_lock(self.paths.state / "wg.lock"):
            data = self.store.get("tunnel", tunnel_id)
            import json

            with self.store.connect() as db:
                manifests = db.execute(
                    "SELECT data FROM runtime WHERE key LIKE 'deployment:%'"
                ).fetchall()
            if any(
                e.get("interface") == data["interface"]
                or data["local_address"].split("/")[0] == e.get("listen_address")
                for row in manifests
                for e in json.loads(row[0]).values()
            ):
                raise ConflictError("隧道仍被受管 Realm 入口使用，请先撤销并同步业务")
            prior = self.store.runtime("wg:" + tunnel_id, {})
            if prior.get("unit"):
                unit = prior["unit"]
                config = self.paths.config / "wireguard" / f"{data['interface']}.conf"
                resource = ResourceFiles(self.paths, self.store, self.services)
                with resource.transaction(
                    unit, [config, self.paths.units / unit]
                ) as transaction_id:
                    self.services.action("stop", unit)
                    self.services.action("disable", unit)
                    (self.paths.units / unit).unlink(missing_ok=True)
                    config.unlink(missing_ok=True)
                    self.services.daemon_reload()

                    def commit(db):
                        self.store.remove("tunnel", tunnel_id, db)
                        self.store.set_runtime("wg:" + tunnel_id, {}, db)

                    resource.commit(transaction_id, commit)
            else:
                self.store.remove("tunnel", tunnel_id)
                self.store.set_runtime("wg:" + tunnel_id, {})
            self.key_path(tunnel_id).unlink(missing_ok=True)
            return {"deleted": tunnel_id}

    def status(self, tunnel_id):
        data = self.store.get("tunnel", tunnel_id)
        # Never use wg show all dump: its first line exposes the interface private key.
        values = {}
        for field in ("latest-handshakes", "transfer", "endpoints", "persistent-keepalive"):
            values[field] = self.runner.run(
                ["wg", "show", data["interface"], field], check=False
            ).stdout.strip()
        timestamps = [
            int(line.split()[-1])
            for line in values["latest-handshakes"].splitlines()
            if line.split() and line.split()[-1].isdigit()
        ]
        latest = max(timestamps, default=0)
        age = max(0, int(time.time()) - latest) if latest else None
        connected = age is not None and age <= 180
        service = self.services.state(f"relayaxis-wg-{tunnel_id}.service")
        return {
            "tunnel_id": tunnel_id,
            "interface": data["interface"],
            **values,
            "service": service,
            "handshake_age_seconds": age,
            "connected": connected,
            "ok": not data["enabled"] or service["active"] and connected,
        }
