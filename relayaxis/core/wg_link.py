"""Native WG lifecycle: fixed argv, private key on stdin, no shell or wg-quick hooks."""

import ipaddress

from ..errors import ApplyError, ConflictError
from ..models import identifier, new_id


class WireGuardLink:
    def __init__(self, runner, store):
        self.runner, self.store = runner, store

    def _links(self, device):
        links = self.runner.json(["ip", "-j", "link", "show"])
        return [link for link in links if link["ifname"] == device]

    def down(self, tunnel_id, device):
        self.runner.require_root()
        identifier(tunnel_id)
        current = self._links(device)
        owner = self.store.runtime("wg-owner:" + tunnel_id, {})
        if current:
            if not owner or current[0].get("ifalias") != owner.get("alias"):
                raise ConflictError("WG 接口的所有权标记不匹配，拒绝删除")
            self.runner.run(["ip", "link", "delete", "dev", device])
        self.store.set_runtime("wg-owner:" + tunnel_id, {})
        return {"state": "DISABLED"}

    def up(self, tunnel, private_key):
        from .wireguard import validate_key

        self.runner.require_root()
        tunnel.validate()
        validate_key(private_key)
        validate_key(tunnel.peer_public_key)
        device = tunnel.interface
        if self._links(device):
            self.down(tunnel.tunnel_id, device)
        alias = f"relayaxis:{tunnel.tunnel_id}:{new_id()}"
        previous = self.store.runtime("wg-owner:" + tunnel.tunnel_id, {})
        # Persist ownership BEFORE adding the interface. The same atomic netlink
        # creation attaches an unpredictable alias, closing the crash/ownership gap.
        self.store.set_runtime(
            "wg-owner:" + tunnel.tunnel_id, {"interface": device, "alias": alias}
        )
        local = str(ipaddress.ip_interface(tunnel.local_address).ip)
        peer = str(ipaddress.ip_interface(tunnel.peer_address).ip)
        lines = [
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"ListenPort = {tunnel.listen_port}",
            "",
            "[Peer]",
            f"PublicKey = {tunnel.peer_public_key}",
            f"AllowedIPs = {peer}/32",
        ]
        if tunnel.endpoint:
            lines.append(f"Endpoint = {tunnel.endpoint}")
        if tunnel.role == "controller":
            lines.append(f"PersistentKeepalive = {tunnel.keepalive}")
        created = False
        try:
            self.runner.run(
                ["ip", "link", "add", "dev", device, "alias", alias, "type", "wireguard"]
            )
            created = True
            self.runner.run(["ip", "-4", "address", "add", local + "/32", "dev", device])
            self.runner.run(["wg", "setconf", device, "/dev/stdin"], input="\n".join(lines) + "\n")
            self.runner.run(["ip", "link", "set", "dev", device, "mtu", str(tunnel.mtu), "up"])
            self.runner.run(
                ["ip", "-4", "route", "add", peer + "/32", "dev", device, "proto", "186"]
            )
            link = self._links(device)
            if not link or link[0].get("ifalias") != alias or "UP" not in link[0].get("flags", []):
                raise ApplyError("WG 创建后接口/所有权健康检查失败")
        except Exception as exc:
            if created:
                try:
                    self.down(tunnel.tunnel_id, device)
                except Exception as cleanup_error:
                    raise ApplyError(
                        "WG 启动失败且接口清理未完成，所有权状态已保留"
                    ) from cleanup_error
            else:
                self.store.set_runtime("wg-owner:" + tunnel.tunnel_id, previous)
            raise ApplyError("WG 启动失败，已清理本次创建的接口") from exc
        return {"state": "ACTIVE", "interface": device, "handshake_verified": False}


def load_config(raw, identity):
    """Read only our data fields; reject hooks and global allowed routes."""
    import configparser

    from ..errors import ValidationError
    from ..models import Tunnel, ip
    from .wireguard import validate_key

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(raw)
    except configparser.Error as exc:
        raise ValidationError("受管 WG 配置语法错误（敏感内容不回显）") from exc
    if set(parser.sections()) != {"Interface", "Peer"}:
        raise ValidationError("受管 WG 配置只允许一个 Interface 和一个 Peer")
    interface, peer = dict(parser["Interface"]), dict(parser["Peer"])
    if set(interface) != {"privatekey", "address", "listenport", "mtu", "table"} or set(peer) - {
        "publickey",
        "allowedips",
        "endpoint",
        "persistentkeepalive",
    }:
        raise ValidationError("受管 WG 配置含有未知字段或 Shell hook")
    if interface["table"] != "off":
        raise ValidationError("受管 WG 不允许自动导入全局路由")
    addresses = [
        ipaddress.ip_interface(interface["address"]),
        ipaddress.ip_interface(peer["allowedips"]),
    ]
    if any(a.version != 4 or a.network.prefixlen != 32 for a in addresses):
        raise ValidationError("受管 WG 只允许两端 IPv4 /32")
    private = validate_key(interface["privatekey"])
    tunnel = Tunnel(
        identity["tunnel_id"],
        identity["interface"],
        identity["role"],
        str(addresses[0]),
        str(addresses[1]),
        int(interface["listenport"]),
        peer.get("endpoint", ""),
        identity["public_key"],
        validate_key(peer["publickey"]),
        int(interface["mtu"]),
        int(peer.get("persistentkeepalive", "0")),
    )
    if (
        ip(str(addresses[0].ip), 4) != identity["local_address"].split("/")[0]
        or str(addresses[1].ip) != identity["peer_address"].split("/")[0]
    ):
        raise ValidationError("受管 WG 配置地址与隧道身份不一致")
    return tunnel.validate(), private
