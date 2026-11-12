import hashlib
import json
import re
import shlex
import socket
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

from ..errors import ConflictError, ValidationError
from ..models import Binding, Rule, hostname, identifier, ip, port
from .network import egress_from_dict


def hostport(host, number):
    return f"[{host}]:{number}" if ":" in host else f"{host}:{number}"


def split_address(value):
    host, separator, number = value.rpartition(":")
    if not separator or not number.isdigit():
        raise ValidationError("无效的 Realm 监听/目标地址")
    port(int(number))
    return host.strip("[]"), int(number)


@dataclass
class Endpoint:
    endpoint_id: str
    rule_id: str
    listen_address: str
    listen_port: int
    remote_host: str
    remote_port: int
    protocol: str
    through: str = ""
    interface: str = ""
    dependency: str = ""

    def validate(self):
        identifier(self.endpoint_id)
        identifier(self.rule_id)
        ip(self.listen_address)
        hostname(self.remote_host)
        port(self.listen_port)
        port(self.remote_port)
        if self.protocol not in ("tcp", "udp", "both"):
            raise ValidationError("无效 Realm 协议")
        if self.through:
            ip(self.through, 4)
        from ..models import interface

        if self.interface:
            interface(self.interface)
        if self.dependency and not re.fullmatch(
            r"[a-zA-Z0-9_.@-]+\.service(?: [a-zA-Z0-9_.@-]+\.service)*", self.dependency
        ):
            raise ValidationError("无效启动依赖")
        return self

    @property
    def unit(self):
        return f"relayaxis-realm-{self.endpoint_id}.service"


def render(endpoint):
    endpoint.validate()

    def quote(value):
        return json.dumps(value, ensure_ascii=False)

    lines = [
        "# Managed by RelayAxis; edit desired state with ra.",
        "[log]",
        'level = "info"',
        'output = "stdout"',
        "",
        "[dns]",
        'mode = "ipv4_only"',
        "",
        "[network]",
        f"no_tcp = {str(endpoint.protocol == 'udp').lower()}",
        f"use_udp = {str(endpoint.protocol != 'tcp').lower()}",
        "ipv6_only = true",
        "",
        "[[endpoints]]",
        f"listen = {quote(hostport(endpoint.listen_address, endpoint.listen_port))}",
        f"remote = {quote(hostport(endpoint.remote_host, endpoint.remote_port))}",
    ]
    if endpoint.through:
        lines.append(f"through = {quote(endpoint.through)}")
    if endpoint.interface:
        lines.append(f"interface = {quote(endpoint.interface)}")
    result = "\n".join(lines) + "\n"
    tomllib.loads(result)
    return result


def unit_text(endpoint, config_path, realm_binary):
    if getattr(config_path, "drive", ""):
        # Windows can generate/test Linux units without pretending to run systemd.
        config_path = "/etc/relayaxis/realm/" + config_path.name
    for path in (str(config_path), str(realm_binary)):
        if not re.fullmatch(r"/[a-zA-Z0-9_./-]+", path):
            raise ValidationError("systemd 路径需要不含空格的绝对路径")
    dependency = (
        f"Requires={endpoint.dependency}\nAfter={endpoint.dependency}\n"
        if endpoint.dependency
        else ""
    )
    return f"""# Managed by RelayAxis
[Unit]
Description=RelayAxis Realm {endpoint.endpoint_id}
After=network-online.target
Wants=network-online.target
{dependency}
[Service]
Type=simple
ExecStart={realm_binary} -c {config_path}
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""


class Compiler:
    def __init__(self, store, network):
        self.store = store
        self.network = network

    def local(self, data, validate_network=True, unavailable=None):
        rule = Rule.from_dict(data)
        if not rule.enabled or rule.deleted:
            return []
        if rule.external_service:
            raise ConflictError("该规则来自外部服务；完成受控迁移前拒绝启动受管监听")
        egress = egress_from_dict(self.store.get("egress", rule.egress_id))
        # Pin IPv4 at apply time, so a later DNS answer cannot bypass route validation.
        remote = (
            self.network.resolve4(rule.remote_host)[0] if validate_network else rule.remote_host
        )
        if validate_network:
            self.network.validate_egress(egress, remote, rule.remote_port, rule.protocol)
        result = []
        for index, binding in enumerate(rule.bindings):
            local = binding.server_id == "local"
            address = binding.listen_address if local else binding.wg_target_address
            number = binding.listen_port if local else binding.wg_internal_port
            identity = hashlib.sha256(
                f"{binding.server_id}|{address}|{number}".encode()
            ).hexdigest()[:10]
            dependency = egress.dependency_service
            try:
                if validate_network:
                    self.network.ensure_local_listen(address)
                if not local:
                    server = self.store.get("server", binding.server_id)
                    tunnel = self.store.get("tunnel", server["tunnel_id"])
                    if not tunnel["enabled"]:
                        raise ValidationError("关联 WG 隧道已禁用")
                    dependency = " ".join(
                        filter(None, [dependency, f"relayaxis-wg-{tunnel['tunnel_id']}.service"])
                    )
            except ValidationError as exc:
                if unavailable is None:
                    raise
                unavailable.append(
                    {
                        "index": index,
                        "server_id": binding.server_id,
                        "endpoint_id": f"{rule.rule_id}-{identity}",
                        "error": str(exc),
                    }
                )
                continue
            result.append(
                Endpoint(
                    f"{rule.rule_id}-{identity}",
                    rule.rule_id,
                    address,
                    number,
                    remote,
                    rule.remote_port,
                    rule.protocol,
                    egress.source,
                    egress.interface,
                    dependency,
                )
            )
        return result

    def ingress(self, server_id, rules=None):
        server = self.store.get("server", server_id)
        tunnel = self.store.get("tunnel", server["tunnel_id"])
        result = []
        if not server["enabled"]:
            return result
        for data in rules if rules is not None else self.store.list("rule"):
            rule = Rule.from_dict(data)
            if not rule.enabled or rule.deleted:
                continue
            for b in rule.bindings:
                if b.server_id != server_id:
                    continue
                identity = hashlib.sha256(
                    f"{server_id}|{b.listen_address}|{b.listen_port}".encode()
                ).hexdigest()[:10]
                result.append(
                    Endpoint(
                        f"{rule.rule_id}-{identity}",
                        rule.rule_id,
                        b.listen_address,
                        b.listen_port,
                        b.wg_target_address,
                        b.wg_internal_port,
                        rule.protocol,
                        tunnel["peer_address"].split("/")[0],
                        tunnel["interface"],
                        f"relayaxis-wg-{tunnel['tunnel_id']}.service",
                    )
                )
        return result


def check_bind(endpoint):
    """Probe both transports; no socket is left open and no service is stopped."""
    family = socket.AF_INET6 if ":" in endpoint.listen_address else socket.AF_INET
    for proto in ("tcp", "udp") if endpoint.protocol == "both" else (endpoint.protocol,):
        with socket.socket(
            family, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        ) as sock:
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                sock.bind((endpoint.listen_address, endpoint.listen_port))
            except OSError as exc:
                raise ConflictError(
                    f"监听不可用 {endpoint.listen_address}:{endpoint.listen_port}/{proto}"
                ) from exc


def scan_existing(runner, directories=None):
    """Read-only discovery, without executing anything from a unit/config file."""
    directories = directories or [Path("/etc/systemd/system"), Path("/usr/lib/systemd/system")]
    result = []
    seen = set()
    for directory in directories:
        for unit in sorted(Path(directory).glob("*.service")):
            if unit.name.startswith("relayaxis-") or unit.name in seen:
                continue
            seen.add(unit.name)
            try:
                # systemctl cat includes drop-ins, unlike reading just the main file.
                content = (
                    runner.run(["systemctl", "cat", unit.name], check=False).stdout
                    or unit.read_text()
                )
                for line in content.splitlines():
                    if not line.strip().startswith("ExecStart="):
                        continue
                    argv = shlex.split(line.split("=", 1)[1])
                    if not argv or "realm" not in Path(argv[0]).name.lower():
                        continue
                    config = next(
                        (
                            argv[i + 1]
                            for i, arg in enumerate(argv[:-1])
                            if arg in ("-c", "--config")
                        ),
                        None,
                    )
                    config = config or next(
                        (a.split("=", 1)[1] for a in argv if a.startswith("--config=")), None
                    )
                    if not config or not Path(config).is_absolute():
                        result.append(
                            {"service": unit.name, "error": "未能识别绝对配置路径；需要人工检查"}
                        )
                        continue
                    raw = Path(config).read_bytes()
                    parsed = tomllib.loads(raw.decode())
                    result.append(
                        {
                            "service": unit.name,
                            "config": config,
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "config_data": parsed,
                            "unit_path": str(unit),
                            "unit_text": content,
                            "active": runner.run(
                                ["systemctl", "is-active", unit.name], check=False
                            ).stdout.strip()
                            == "active",
                        }
                    )
            except (OSError, ValueError) as exc:
                result.append({"service": unit.name, "error": type(exc).__name__})
    return result


def import_existing(store, rules, discovered, egress_id, backup_directory):
    from .system import atomic_write

    backup_directory = Path(backup_directory)
    identifier(discovered["service"].removesuffix(".service"))
    backup_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    raw = Path(discovered["config"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != discovered["sha256"]:
        raise ConflictError("扫描后外部配置已更改，请重新扫描")
    atomic_write(backup_directory / "realm.toml", raw)
    atomic_write(backup_directory / "original.service", discovered["unit_text"])
    atomic_write(backup_directory / "source.json", json.dumps(discovered, ensure_ascii=False))
    parsed = tomllib.loads(raw.decode())
    if set(parsed) - {"log", "network", "dns", "endpoints"}:
        raise ValidationError("外部配置包含无法导入的全局扩展，请人工转换")
    if parsed.get("dns") and parsed["dns"] != {"mode": "ipv4_only"}:
        raise ValidationError("外部自定义 DNS 行为无法无损导入，请人工转换")
    network = parsed.get("network", {})
    if any(k not in {"no_tcp", "use_udp", "ipv6_only"} for k in network):
        raise ValidationError("外部配置包含无法无损导入的网络选项，请人工转换")
    egress = egress_from_dict(store.get("egress", egress_id))
    if network.get("no_tcp", False) and not network.get("use_udp", False):
        raise ValidationError("外部配置同时禁用 TCP 和 UDP，不能导入为活动转发")
    candidates = []
    for index, endpoint in enumerate(parsed.get("endpoints", [])):
        if set(endpoint) - {"listen", "remote", "through", "interface"}:
            raise ValidationError("外部端点含有高级选项，拒绝有损导入")
        if (
            endpoint.get("through", egress.source) != egress.source
            or endpoint.get("interface", egress.interface) != egress.interface
        ):
            raise ValidationError("所选出口与现有 through/interface 不一致")
        addr, number = split_address(endpoint["listen"])
        ip(addr, 6)
        if addr == "::" and not network.get("ipv6_only", False):
            raise ValidationError("外部双栈通配监听不能直接导入为 IPv6-only")
        remote, remote_port = split_address(endpoint["remote"])
        protocol = (
            "udp"
            if network.get("no_tcp", False)
            else ("both" if network.get("use_udp", False) else "tcp")
        )
        candidates.append(
            Rule(
                name=f"{discovered['service']}-{index + 1}",
                remote_host=remote,
                remote_port=remote_port,
                egress_id=egress_id,
                bindings=[Binding(addr, number)],
                enabled=False,
                protocol=protocol,
                external_service=discovered["service"],
            ).validate()
        )
    if not candidates:
        raise ValidationError("外部配置没有可导入的端点")
    # Validate the whole batch before saving, and commit all imported endpoints together.
    with store.transaction() as db:
        output = []
        for rule in candidates:
            rules._validate_graph(rule, db)
            output.append(store.put("rule", rule.rule_id, asdict(rule), 0, db))
    return output
