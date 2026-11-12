import ipaddress
import socket

from ..errors import ValidationError
from ..models import Egress, ip, protocols


def table_name(value):
    return {"254": "main", "255": "local", "253": "default"}.get(str(value), str(value))


class Network:
    def __init__(self, runner):
        self.runner = runner

    def addresses(self):
        return self.runner.json(["ip", "-j", "address", "show"])

    def routes(self, version=4):
        return self.runner.json(["ip", "-j", f"-{version}", "route", "show", "table", "all"])

    def policy_rules(self):
        return self.runner.json(["ip", "-j", "-4", "rule", "show"])

    def discover_egresses(self):
        addresses, routes, rules = self.addresses(), self.routes(), self.policy_rules()
        result = []
        for link in addresses:
            for address in link.get("addr_info", []):
                if address.get("family") != "inet" or address.get("scope") != "global":
                    continue
                source = address["local"]
                matching = [
                    r
                    for r in rules
                    if r.get("src") in (source, source + "/32")
                    and not any(
                        k in r for k in ("fwmark", "ipproto", "dport", "sport", "dst", "iif", "oif")
                    )
                ]
                tables = [table_name(r.get("table", "main")) for r in matching] or ["main"]
                for table in dict.fromkeys(tables):
                    defaults = [
                        r
                        for r in routes
                        if r.get("dst") == "default"
                        and r.get("dev") == link["ifname"]
                        and table_name(r.get("table", "main")) == table
                    ]
                    for route in defaults or [{}]:
                        policy = next(
                            (r for r in matching if table_name(r.get("table")) == table), {}
                        )
                        result.append(
                            {
                                "interface": link["ifname"],
                                "source": source,
                                "prefixlen": address["prefixlen"],
                                "gateway": route.get("gateway", ""),
                                "table": table,
                                "priority": policy.get("priority", 0),
                                "external": True,
                                "has_default": bool(route),
                            }
                        )
        return result

    def resolve4(self, host):
        try:
            return [ip(host, 4)]
        except ValidationError:
            try:
                addresses = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            except OSError as exc:
                raise ValidationError(f"无法解析目标 IPv4: {host}") from exc
            result = list(dict.fromkeys(item[4][0] for item in addresses))
            if not result:
                raise ValidationError("目标没有 IPv4 地址") from None
            return result

    def source_present(self, egress):
        return any(
            link["ifname"] == egress.interface
            and any(
                a.get("local") == egress.source and a.get("family") == "inet"
                for a in link.get("addr_info", [])
            )
            for link in self.addresses()
        )

    def validate_egress(self, egress, target, target_port, protocol="both", source_port=None):
        egress.validate()
        if not self.source_present(egress):
            raise ValidationError(f"出口源地址 {egress.source} 未配置在 {egress.interface}")
        target = ip(target, 4)
        results = []
        for proto in sorted(protocols(protocol)):
            base = [
                "ip",
                "-j",
                "-4",
                "route",
                "get",
                target,
                "from",
                egress.source,
                "ipproto",
                proto,
                "dport",
                str(target_port),
            ]
            if source_port is not None:
                base.extend(["sport", str(source_port)])
            # First verify ordinary source policy; then verify Realm's SO_BINDTODEVICE lookup.
            for bound in (False, True):
                routes = self.runner.json(base + (["oif", egress.interface] if bound else []))
                if not routes:
                    raise ValidationError("找不到目标的源地址路由")
                route = routes[0]
                if (
                    route.get("type", "unicast") != "unicast"
                    or route.get("dev") != egress.interface
                ):
                    raise ValidationError(f"{proto} 出口路由回落或接口不匹配，拒绝应用")
                if egress.gateway and route.get("gateway") != egress.gateway:
                    raise ValidationError(f"{proto} 实际网关与所选出口不一致，拒绝静默串线")
                if table_name(route.get("table", "main")) != table_name(egress.table):
                    raise ValidationError(f"{proto} 实际路由表与所选出口不一致")
                if route.get("src", route.get("prefsrc", egress.source)) != egress.source:
                    raise ValidationError("实际源地址与所选出口不一致")
                results.append({**route, "bound_interface_lookup": bound})
        return results

    def ensure_local_listen(self, address):
        addr = ipaddress.ip_address(address)
        if addr.is_unspecified:
            return
        if not any(
            a.get("local") == address
            and "tentative" not in a.get("flags", [])
            and not a.get("tentative")
            for link in self.addresses()
            for a in link.get("addr_info", [])
        ):
            raise ValidationError(f"监听地址未配置在本机: {address}")

    def listeners(self):
        return self.runner.run(["ss", "-H", "-lntup"]).stdout


def egress_from_dict(data):
    return Egress(**data).validate()
