import os
import socket
import statistics
import struct
import time

from ..errors import ValidationError
from ..models import port
from .realm import Endpoint
from .system import environment


def bound_socket(egress, socktype):
    sock = socket.socket(socket.AF_INET, socktype)
    try:
        sock.bind((egress.source, 0))
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, egress.interface.encode() + b"\0"
            )
        else:
            raise ValidationError("当前平台无法验证按网卡绑定的网络探测")
        return sock
    except Exception:
        sock.close()
        raise


def tcp_probe(network, egress, host, target_port, timeout=3):
    target = network.resolve4(host)[0]
    network.validate_egress(egress, target, port(target_port), "tcp")
    with bound_socket(egress, socket.SOCK_STREAM) as sock:
        network.validate_egress(
            egress, target, target_port, "tcp", source_port=sock.getsockname()[1]
        )
        sock.settimeout(timeout)
        started = time.monotonic()
        try:
            sock.connect((target, target_port))
            connect_ms = (time.monotonic() - started) * 1000
            minimum = None
            if hasattr(socket, "TCP_INFO"):
                info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232)
                # Linux tcp_info.tcpi_min_rtt is a u32 at byte 148 (usec).
                if len(info) >= 152:
                    value = struct.unpack_from("=I", info, 148)[0]
                    if 0 < value < 0xFFFFFFFF:
                        minimum = value / 1000
            return {
                "ok": True,
                "target": target,
                "source": sock.getsockname()[0],
                "source_port": sock.getsockname()[1],
                "connect_ms": connect_ms,
                "tcp_min_rtt_ms": minimum,
            }
        except OSError as exc:
            return {"ok": False, "target": target, "error": type(exc).__name__}


def udp_probe(network, egress, host, target_port, payload=b"RelayAxis UDP diagnostic", timeout=2):
    target = network.resolve4(host)[0]
    network.validate_egress(egress, target, port(target_port), "udp")
    with bound_socket(egress, socket.SOCK_DGRAM) as sock:
        network.validate_egress(
            egress, target, target_port, "udp", source_port=sock.getsockname()[1]
        )
        sock.settimeout(timeout)
        sock.connect((target, target_port))
        try:
            sock.send(payload)
            response = sock.recv(65535)
            return {
                "state": "RESPONSE",
                "received_bytes": len(response),
                "echo_matches": response == payload,
            }
        except TimeoutError:
            return {
                "state": "INCONCLUSIVE",
                "reason": "已发送但没有响应；UDP 无响应不能证明可达或不可达",
            }
        except OSError as exc:
            return {"state": "ERROR", "error": type(exc).__name__}


def ecmp_sample(network, egress, host, target_port, count=10, interval=0.2, timeout=3):
    if not 2 <= count <= 200 or not 0 <= interval <= 30 or not 0.1 <= timeout <= 10:
        raise ValidationError("采样次数 2–200，间隔 0–30 秒，超时 0.1–10 秒")
    target = network.resolve4(host)[0]
    samples = []
    for index in range(count):
        # New source port / TCP flow for each sample; verify the route on every flow.
        samples.append(tcp_probe(network, egress, target, target_port, timeout))
        if index + 1 < count:
            time.sleep(interval)
    rtts = [
        s["tcp_min_rtt_ms"] if s.get("tcp_min_rtt_ms") is not None else s["connect_ms"]
        for s in samples
        if s["ok"]
    ]
    distribution = (
        {}
        if not rtts
        else {
            "min_ms": min(rtts),
            "median_ms": statistics.median(rtts),
            "max_ms": max(rtts),
            "stdev_ms": statistics.pstdev(rtts),
        }
    )
    return {
        "target": target,
        "port": target_port,
        "egress_id": egress.egress_id,
        "valid_samples": len(rtts),
        "failed_samples": count - len(rtts),
        "distribution": distribution,
        "samples": samples,
        "conclusion": "仅显示不同 TCP flow 的 RTT 差异；不能据此确认 ECMP，需要路径证据",
    }


def doctor(context):
    checks = []

    def check(name, action):
        try:
            value = action()
            checks.append(
                {
                    "name": name,
                    "ok": value.get("ok", True) if isinstance(value, dict) else True,
                    "data": value,
                }
            )
        except Exception as exc:
            checks.append(
                {
                    "name": name,
                    "ok": False,
                    "error": str(exc) if isinstance(exc, ValidationError) else type(exc).__name__,
                }
            )

    check("environment", environment)
    check("installation", context.verify_install)
    check("addresses", context.network.addresses)
    check("routes_ipv4", context.network.routes)
    check("routes_ipv6", lambda: context.network.routes(6))
    check("policy_rules", context.network.policy_rules)
    check("listeners", context.network.listeners)
    for tunnel in context.store.list("tunnel"):
        check("wg:" + tunnel["tunnel_id"], lambda t=tunnel: context.wg.status(t["tunnel_id"]))
    for rule in context.rules.list():
        if rule["enabled"] and not rule["external_service"]:
            check(
                "rule-routing:" + rule["rule_id"],
                lambda r=rule: [e.__dict__ for e in context.compiler.local(r)],
            )
            endpoints = list(context.deployment.manifest("rule-" + rule["rule_id"]).values())
            check(
                "rule-services:" + rule["rule_id"],
                lambda es=endpoints: {
                    "ok": bool(es) and all(context.deployment._healthy(Endpoint(**e)) for e in es),
                    "units": [e["endpoint_id"] for e in es],
                },
            )
    journals = [p.name for p in (context.paths.state / "journals").glob("*.json")]
    checks.append({"name": "unfinished_transactions", "ok": not journals, "data": journals})
    return {"checks": checks, "ok": all(c["ok"] for c in checks), "pid": os.getpid()}
