import ipaddress
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from .errors import ValidationError


def now():
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_id():
    return uuid.uuid4().hex[:16]


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}", value):
        raise ValidationError("ID 只能包含 1–48 个字母、数字、下划线或短横线")
    return value


def interface(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}", value):
        raise ValidationError("无效的 Linux 网卡名称（最长 15 字符）")
    return value


def port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValidationError("端口必须是 1–65535 的整数")
    return value


def ip(value, version=None):
    if not isinstance(value, str):
        raise ValidationError("IP 地址必须使用字符串字面地址")
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"无效的 IP 地址: {value}") from exc
    if "%" in str(address) or (version and address.version != version):
        raise ValidationError(f"需要 IPv{version or '4/6'} 字面地址，不接受 scope ID")
    if address.is_multicast:
        raise ValidationError("不支持组播地址")
    return str(address)


def hostname(value):
    try:
        return ip(value, 4)
    except ValidationError:
        pass
    if (
        not isinstance(value, str)
        or len(value) > 253
        or not re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.?", value)
    ):
        raise ValidationError("目标必须是 IPv4 地址或有效域名；首版不支持 IPv6 落地")
    for label in value.rstrip(".").split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValidationError("无效域名")
    if all(c.isdigit() or c == "." for c in value):
        raise ValidationError("无效 IPv4 地址")
    return value.lower()


def text(value, name, limit=512):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValidationError(f"{name} 过长或包含控制字符")
    return value


class State(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    PENDING_SYNC = "PENDING_SYNC"
    APPLYING = "APPLYING"
    FAILED = "FAILED"
    OUT_OF_SYNC = "OUT_OF_SYNC"


@dataclass
class Binding:
    listen_address: str
    listen_port: int
    server_id: str = "local"
    wg_target_address: str = ""
    wg_internal_port: int = 0

    def validate(self):
        self.listen_address = ip(self.listen_address)
        port(self.listen_port)
        identifier(self.server_id)
        if self.server_id == "local":
            ip(self.listen_address, 6)
            if self.wg_target_address or self.wg_internal_port:
                raise ValidationError("IPv6 直连入口无需 WG 内部映射")
        else:
            ip(self.listen_address, 4)
            if self.wg_target_address:
                self.wg_target_address = ip(self.wg_target_address, 4)
            if self.wg_internal_port:
                port(self.wg_internal_port)


@dataclass
class Rule:
    name: str
    remote_host: str
    remote_port: int
    egress_id: str
    bindings: list[Binding]
    rule_id: str = field(default_factory=new_id)
    remark: str = ""
    enabled: bool = True
    protocol: str = "both"
    revision: int = 0
    created_at: str = ""
    updated_at: str = ""
    deleted: bool = False
    external_service: str = ""

    def validate(self):
        identifier(self.rule_id)
        identifier(self.egress_id)
        text(self.name, "规则名", 100)
        text(self.remark, "备注")
        if not self.name.strip() or not self.bindings:
            raise ValidationError("规则名和至少一个入口不能为空")
        if len(self.bindings) > 64:
            raise ValidationError("每条规则最多支持 64 个入口")
        if type(self.enabled) is not bool or type(self.deleted) is not bool:
            raise ValidationError("enabled/deleted 必须是布尔值")
        self.remote_host = hostname(self.remote_host)
        port(self.remote_port)
        if self.protocol not in ("tcp", "udp", "both"):
            raise ValidationError("协议必须是 tcp、udp 或 both")
        for binding in self.bindings:
            binding.validate()
        if self.external_service and not re.fullmatch(
            r"[a-zA-Z0-9_.@-]+\.service", self.external_service
        ):
            raise ValidationError("无效的外部 systemd 服务名")
        return self

    @property
    def ingress_server_ids(self):
        return sorted({b.server_id for b in self.bindings if b.server_id != "local"})

    @property
    def ingress_type(self):
        return (
            "mixed"
            if self.ingress_server_ids and any(b.server_id == "local" for b in self.bindings)
            else ("ipv4" if self.ingress_server_ids else "ipv6")
        )

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        data["bindings"] = [Binding(**b) for b in data.get("bindings", [])]
        return cls(**data).validate()


@dataclass
class Egress:
    egress_id: str
    name: str
    interface: str
    source: str
    gateway: str = ""
    table: str = "main"
    priority: int = 0
    managed: bool = False
    dependency_service: str = ""
    revision: int = 0

    def validate(self):
        if type(self.managed) is not bool:
            raise ValidationError("managed 必须是布尔值")
        identifier(self.egress_id)
        text(self.name, "出口名", 100)
        interface(self.interface)
        self.source = ip(self.source, 4)
        if self.gateway:
            self.gateway = ip(self.gateway, 4)
        self.table = str(self.table)
        if self.table != "main" and (not self.table.isdigit() or not 1 <= int(self.table) < 2**32):
            raise ValidationError("路由表使用 main 或数字 ID")
        if self.managed and (
            self.table == "main"
            or int(self.table) in (253, 254, 255)
            or not self.priority
            or not self.gateway
        ):
            raise ValidationError("自建出口需要独立路由表、非零优先级和网关，禁止修改系统默认表")
        if type(self.priority) is not int or not 0 <= self.priority < 32766:
            raise ValidationError("策略优先级必须在 0–32765 之间")
        if self.dependency_service and not re.fullmatch(
            r"[a-zA-Z0-9_.@-]+\.service", self.dependency_service
        ):
            raise ValidationError("无效的 PBR 服务名")
        return self


@dataclass
class Server:
    server_id: str
    server_name: str
    public_ipv4: str
    tunnel_id: str
    ssh_user: str = "root"
    ssh_port: int = 22
    identity_file: str = ""
    known_hosts_file: str = ""
    enabled: bool = True
    transport_mode: str = "wireguard"
    revision: int = 0

    def validate(self):
        identifier(self.server_id)
        identifier(self.tunnel_id)
        if self.server_id == "local":
            raise ValidationError("local 为保留 ID")
        text(self.server_name, "前置机名称", 100)
        self.public_ipv4 = ip(self.public_ipv4, 4)
        identifier(self.ssh_user)
        port(self.ssh_port)
        if self.transport_mode not in ("wireguard", "mimic"):
            raise ValidationError("无效传输模式")
        for path in (self.identity_file, self.known_hosts_file):
            if path and (not path.startswith("/") or any(c in path for c in "\n\r\x00")):
                raise ValidationError("SSH 凭据和 known_hosts 必须是绝对路径")
        if type(self.enabled) is not bool:
            raise ValidationError("enabled 必须是布尔值")
        return self


@dataclass
class Tunnel:
    tunnel_id: str
    interface: str
    role: str
    local_address: str
    peer_address: str
    listen_port: int = 51820
    endpoint: str = ""
    public_key: str = ""
    peer_public_key: str = ""
    mtu: int = 1420
    keepalive: int = 25
    enabled: bool = True
    revision: int = 0

    def validate(self):
        if type(self.enabled) is not bool:
            raise ValidationError("enabled 必须是布尔值")
        identifier(self.tunnel_id)
        interface(self.interface)
        if not self.interface.startswith("ra-"):
            raise ValidationError("受管 WG 接口必须以 ra- 开头")
        if self.role not in ("controller", "ingress"):
            raise ValidationError("隧道角色只能是 controller 或 ingress")
        for value in (self.local_address, self.peer_address):
            try:
                addr = ipaddress.ip_interface(value)
            except ValueError as exc:
                raise ValidationError("WG 地址需要 CIDR 格式") from exc
            if (
                addr.version != 4
                or not 30 <= addr.network.prefixlen <= 32
                or addr.ip.is_unspecified
                or addr.ip.is_multicast
            ):
                raise ValidationError("WG 地址需要 IPv4 /30、/31 或 /32")
        local = ipaddress.ip_interface(self.local_address)
        peer = ipaddress.ip_interface(self.peer_address)
        if local.ip == peer.ip:
            raise ValidationError("隧道两端地址不能相同")
        port(self.listen_port)
        if type(self.mtu) is not int or not 1280 <= self.mtu <= 9000:
            raise ValidationError("MTU 必须在 1280–9000 之间")
        if type(self.keepalive) is not int or not 0 <= self.keepalive <= 65535:
            raise ValidationError("无效保活间隔")
        if self.role == "controller" and not self.endpoint:
            raise ValidationError("NAT 侧 Controller 必须主动指定公网前置机 Endpoint")
        if self.endpoint:
            host, sep, number = self.endpoint.rpartition(":")
            if not sep or not number.isdigit():
                raise ValidationError("Endpoint 格式应为 IPv4/域名:端口 或 [IPv6]:端口")
            if host.startswith("[") and host.endswith("]"):
                ip(host[1:-1], 6)
            else:
                hostname(host)
            port(int(number))
        return self


def protocols(protocol):
    return {"tcp", "udp"} if protocol == "both" else {protocol}


def address_conflict(a, b):
    a, b = ipaddress.ip_address(a), ipaddress.ip_address(b)
    # All generated IPv6 sockets use IPV6_V6ONLY.
    return a.version == b.version and (a == b or a.is_unspecified or b.is_unspecified)


def networks_overlap(a, b):
    return ipaddress.ip_network(a, strict=False).overlaps(ipaddress.ip_network(b, strict=False))
