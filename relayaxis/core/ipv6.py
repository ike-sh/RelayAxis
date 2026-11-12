import ipaddress
import socket


def discover(network, runner, labels=None):
    labels = labels or {}
    result = []
    for link in network.addresses():
        for address in link.get("addr_info", []):
            if address.get("family") != "inet6":
                continue
            addr = ipaddress.ip_address(address["local"])
            if not addr.is_global:
                continue
            prefix = str(ipaddress.ip_network(f"{addr}/{address['prefixlen']}", strict=False))
            result.append(
                {
                    "address": str(addr),
                    "interface": link["ifname"],
                    "prefix": prefix,
                    "label": labels.get(str(addr), "未标记"),
                    "deprecated": address.get("deprecated", False)
                    or address.get("preferred_life_time") == 0,
                }
            )
    for item in result:
        item["shared_prefix_interfaces"] = sorted(
            {a["interface"] for a in result if a["prefix"] == item["prefix"]}
        )
    units = runner.run(
        ["systemctl", "list-units", "--all", "--no-pager", "--plain", "--no-legend"], check=False
    ).stdout
    return {
        "addresses": result,
        "routes": network.routes(6),
        "existing_managers": [
            line.strip()
            for line in units.splitlines()
            if any(
                word in line.lower()
                for word in ("ipv6_manager", "ddns", "cloudflare", "ipv6-manager")
            )
        ],
    }


def check_aaaa(host, expected):
    # Read-only adapter: no DNS credentials, API writes, or competing timer.
    try:
        records = sorted({entry[4][0] for entry in socket.getaddrinfo(host, None, socket.AF_INET6)})
    except OSError:
        records = []
    return {
        "host": host,
        "aaaa": records,
        "expected": sorted(expected),
        "matches": bool(records) and set(records) == set(expected),
        "resolver": "system (DNS provider attribution not inferred)",
    }
