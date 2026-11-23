import ipaddress
import socket
from copy import deepcopy

from ..errors import RelayAxisError, ValidationError
from ..models import Egress, EgressHealth, ip, port, protocols


def table_name(value):
    return {"254": "main", "255": "local", "253": "default"}.get(str(value), str(value))


def _default(route):
    return route.get("dst", "default") in ("default", "0.0.0.0/0")


def _metric(route):
    value = route.get("metric", route.get("priority", 0))
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class Network:
    def __init__(self, runner):
        self.runner = runner

    def addresses(self):
        return self.runner.json(["ip", "-j", "address", "show"])

    def routes(self, version=4):
        return self.runner.json(["ip", "-j", f"-{version}", "route", "show", "table", "all"])

    def policy_rules(self):
        return self.runner.json(["ip", "-j", "-4", "rule", "show"])

    @staticmethod
    def _route_variants(routes):
        """Expand multipath nexthops while retaining route-level facts."""
        result = []
        for route in routes:
            if route.get("nexthops"):
                for nexthop in route["nexthops"]:
                    item = {**route, **nexthop}
                    item.pop("nexthops", None)
                    result.append(item)
            else:
                result.append(route)
        return result

    @staticmethod
    def _global_addresses(addresses):
        result = {}
        for link in addresses:
            values = []
            for address in link.get("addr_info", []):
                if address.get("family") != "inet" or address.get("scope", "global") != "global":
                    continue
                flags = set(address.get("flags", []))
                values.append(
                    {
                        **address,
                        "usable": not flags.intersection({"tentative", "dadfailed", "deprecated"})
                        and not address.get("tentative", False),
                    }
                )
            result[link.get("ifname", "")] = {
                "addresses": values,
                "operstate": link.get("operstate", "UNKNOWN"),
                "flags": link.get("flags", []),
                "ifindex": link.get("ifindex"),
            }
        return result

    @staticmethod
    def _source_for(route, links):
        explicit = route.get("prefsrc", route.get("src", ""))
        if explicit and "/" not in str(explicit):
            return str(explicit), False, False
        candidates = [
            a for a in links.get(route.get("dev"), {}).get("addresses", []) if a.get("usable", True)
        ]
        if not candidates:
            return "", False, True
        primary = [a for a in candidates if "secondary" not in a.get("flags", [])]
        candidates = primary or candidates
        return candidates[0]["local"], True, len(candidates) != 1

    @staticmethod
    def _simple_source_rule(rule):
        src = rule.get("src", "")
        if not src or src in ("all", "0.0.0.0/0"):
            return False
        if rule.get("dst") not in (None, "", "all", "0.0.0.0/0"):
            return False
        return not any(
            rule.get(key) not in (None, "")
            for key in ("fwmark", "ipproto", "dport", "sport", "iif", "oif", "uidrange")
        )

    def default_route_state(self, routes=None):
        """Return an immutable safety fingerprint of main-table default routes."""
        routes = self._route_variants(self.routes() if routes is None else routes)
        defaults = [
            route
            for route in routes
            if _default(route)
            and table_name(route.get("table", "main")) == "main"
            and route.get("type", "unicast") == "unicast"
        ]
        facts = sorted(
            [
                route.get("dev", ""),
                route.get("gateway", ""),
                route.get("prefsrc", route.get("src", "")),
                _metric(route),
                str(route.get("protocol", "")),
            ]
            for route in defaults
        )
        if not defaults:
            return {"resolved": False, "ambiguous": False, "routes": facts}
        best_metric = min(_metric(route) for route in defaults)
        best = [route for route in defaults if _metric(route) == best_metric]
        identities = {
            (
                route.get("dev", ""),
                route.get("gateway", ""),
                route.get("prefsrc", route.get("src", "")),
            )
            for route in best
        }
        return {
            "resolved": len(identities) == 1,
            "ambiguous": len(identities) > 1,
            "best_metric": best_metric,
            "routes": facts,
        }

    def discover_egresses(self):
        """Read kernel facts without assigning carrier names or changing routes.

        A unique lowest-metric main-table default is marked ``is_default``. Equal
        best routes are all shown and none is selected, so callers must obtain a
        human decision rather than silently choosing one ECMP/member route.
        """
        addresses = self.addresses()
        routes = self._route_variants(self.routes())
        rules = self.policy_rules()
        links = self._global_addresses(addresses)
        result = []
        seen = set()
        default_state = self.default_route_state(routes)
        main_defaults = [
            route
            for route in routes
            if _default(route)
            and table_name(route.get("table", "main")) == "main"
            and route.get("type", "unicast") == "unicast"
        ]
        best_metric = default_state.get("best_metric")
        source_ambiguous = bool(
            default_state["resolved"]
            and any(
                not source or uncertain
                for route in main_defaults
                if _metric(route) == best_metric
                for source, _inferred, uncertain in [self._source_for(route, links)]
            )
        )
        if source_ambiguous:
            default_state = {**default_state, "resolved": False, "source_ambiguous": True}

        def append(route, source, table, priority, management, *, policy=None):
            device = route.get("dev", "")
            if not device and source:
                device = next(
                    (
                        name
                        for name, link in links.items()
                        if any(a.get("local") == source for a in link["addresses"])
                    ),
                    "",
                )
            inferred = False
            uncertain = False
            if not source:
                source, inferred, uncertain = self._source_for(route, links)
            prefixlen = next(
                (
                    a.get("prefixlen", 32)
                    for a in links.get(device, {}).get("addresses", [])
                    if a.get("local") == source
                ),
                32,
            )
            key = (
                device,
                source,
                route.get("gateway", ""),
                table,
                int(priority or 0),
                _metric(route),
            )
            if key in seen:
                return None
            seen.add(key)
            candidate = table == "main" and _default(route)
            is_default = bool(
                candidate and default_state["resolved"] and _metric(route) == best_metric
            )
            link = links.get(device, {})
            result.append(
                {
                    "interface": device,
                    "source": source,
                    "prefixlen": prefixlen,
                    "gateway": route.get("gateway", ""),
                    "table": table,
                    "priority": int(priority or 0),
                    "metric": _metric(route),
                    "protocol": route.get("protocol", ""),
                    "management": management,
                    "backend": "system" if management == "system" else "external",
                    "external": management != "system",
                    "has_default": route.get("dst") in ("default", "0.0.0.0/0"),
                    "default_candidate": candidate,
                    "is_default": is_default,
                    "default_ambiguous": default_state["ambiguous"],
                    "default_resolved": default_state["resolved"],
                    "default_requires_confirmation": not default_state["resolved"]
                    or default_state["ambiguous"],
                    "confirmation_message": (
                        "默认路由没有唯一源地址，需要管理员确认"
                        if source_ambiguous
                        else "main 默认出口不唯一或缺失，需要管理员确认"
                        if not default_state["resolved"] or default_state["ambiguous"]
                        else ""
                    ),
                    "source_inferred": inferred,
                    "source_uncertain": uncertain,
                    "device_state": link.get("operstate", "UNKNOWN"),
                    "device_flags": link.get("flags", []),
                    "policy_rule": deepcopy(policy) if policy else None,
                    "source_selector": policy.get("src", "") if policy else source,
                }
            )
            return result[-1]

        for route in sorted(main_defaults, key=lambda item: (_metric(item), item.get("dev", ""))):
            source, inferred, uncertain = self._source_for(route, links)
            item = append(route, source, "main", 0, "system")
            if item:
                item["source_inferred"] = inferred
                item["source_uncertain"] = uncertain
                if uncertain and item["is_default"]:
                    item["is_default"] = False
                    item["default_resolved"] = False
                    item["default_requires_confirmation"] = True
                    item["confirmation_message"] = "默认路由没有唯一源地址，需要管理员确认"

        for rule in sorted(rules, key=lambda item: int(item.get("priority", 32766))):
            if not self._simple_source_rule(rule):
                continue
            table = table_name(rule.get("table", "main"))
            if table in ("local", "default", "main"):
                continue
            try:
                source_network = ipaddress.ip_network(rule["src"], strict=False)
            except ValueError:
                continue
            sources = [
                (name, address["local"])
                for name, link in links.items()
                for address in link["addresses"]
                if ipaddress.ip_address(address["local"]) in source_network
            ]
            # A missing /32 source is still an important discovered fact: it
            # allows health/status to report SOURCE_MISSING instead of hiding
            # the configured policy route completely.
            if not sources and source_network.prefixlen == 32:
                sources = [("", str(source_network.network_address))]
            table_defaults = [
                route
                for route in routes
                if _default(route)
                and table_name(route.get("table", "main")) == table
                and route.get("type", "unicast") == "unicast"
            ]
            for device, source in sources:
                matching = [route for route in table_defaults if route.get("dev") == device]
                for route in matching or table_defaults or [{"dev": device}]:
                    append(
                        route,
                        source,
                        table,
                        rule.get("priority", 0),
                        "external",
                        policy=rule,
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
            link.get("ifname") == egress.interface
            and any(
                a.get("local") == egress.source
                and a.get("family") == "inet"
                and "tentative" not in a.get("flags", [])
                and not a.get("tentative", False)
                for a in link.get("addr_info", [])
            )
            for link in self.addresses()
        )

    def egress_health(self, egress, target="198.51.100.1", target_port=443, protocol="tcp"):
        """Inspect the real rule, table and effective lookup for one egress."""
        egress.validate()
        report = {
            "egress_id": egress.egress_id,
            "status": EgressHealth.UNKNOWN,
            "ok": False,
            "target": target,
            "checks": {},
        }
        addresses = self.addresses()
        link = next((item for item in addresses if item.get("ifname") == egress.interface), None)
        source_ok = bool(
            link
            and any(
                item.get("family") == "inet"
                and item.get("local") == egress.source
                and "tentative" not in item.get("flags", [])
                for item in link.get("addr_info", [])
            )
        )
        report["checks"]["source"] = source_ok
        if not source_ok:
            report["status"] = EgressHealth.SOURCE_MISSING
            return report
        state = link.get("operstate", "UNKNOWN")
        report["checks"]["device_state"] = state
        if state in ("DOWN", "LOWERLAYERDOWN", "DORMANT", "NOTPRESENT"):
            report["status"] = EgressHealth.DEGRADED
            return report

        rules = self.policy_rules()
        if table_name(egress.table) != "main":
            source_rules = [
                rule
                for rule in rules
                if rule.get("src") in (egress.source, egress.source + "/32")
                and (not egress.priority or int(rule.get("priority", -1)) == egress.priority)
            ]
            expected_rule = next(
                (
                    rule
                    for rule in source_rules
                    if table_name(rule.get("table", "main")) == table_name(egress.table)
                    and self._simple_source_rule(rule)
                ),
                None,
            )
            report["checks"]["rule"] = expected_rule or False
            if not expected_rule:
                report["status"] = (
                    EgressHealth.WRONG_TABLE if source_rules else EgressHealth.RULE_MISSING
                )
                return report

        table_routes = [
            route
            for route in self._route_variants(self.routes())
            if table_name(route.get("table", "main")) == table_name(egress.table)
            and _default(route)
            and route.get("type", "unicast") == "unicast"
        ]
        report["checks"]["default_routes"] = table_routes
        if not table_routes:
            report["status"] = EgressHealth.ROUTE_MISSING
            return report
        expected_device = [route for route in table_routes if route.get("dev") == egress.interface]
        if not expected_device:
            report["status"] = EgressHealth.WRONG_INTERFACE
            return report
        if egress.gateway and not any(
            route.get("gateway", "") == egress.gateway for route in expected_device
        ):
            report["status"] = EgressHealth.WRONG_GATEWAY
            return report
        try:
            lookups = self.validate_egress(egress, ip(target, 4), target_port, protocol)
        except ValidationError as exc:
            message = str(exc)
            report["error"] = message
            report["status"] = (
                EgressHealth.WRONG_INTERFACE
                if "接口" in message or "回落" in message
                else EgressHealth.WRONG_GATEWAY
                if "网关" in message
                else EgressHealth.WRONG_TABLE
                if "路由表" in message
                else EgressHealth.UNREACHABLE
            )
            return report
        except RelayAxisError as exc:
            report["error"] = str(exc)
            report["status"] = EgressHealth.UNREACHABLE
            return report
        report["checks"]["lookups"] = lookups
        report["status"] = EgressHealth.HEALTHY
        report["ok"] = True
        return report

    def validate_egress(self, egress, target, target_port, protocol="both", source_port=None):
        egress.validate()
        port(target_port)
        if source_port is not None:
            port(source_port)
        if protocol not in ("tcp", "udp", "both"):
            raise ValidationError("协议必须是 tcp、udp 或 both")
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
