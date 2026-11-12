import platform
import re
from pathlib import Path

from ..errors import ApplyError, ConflictError, ValidationError
from ..models import Tunnel, interface, ip, port
from .resources import ResourceFiles
from .system import atomic_write, file_lock


class Mimic:
    """Optional upstream executable adapter. Never copies upstream implementation."""

    def __init__(self, paths, store, runner, services):
        self.paths, self.store, self.runner, self.services = paths, store, runner, services

    def install(self):
        self.runner.require_root()
        self.runner.run(["apt-get", "update"], timeout=180)
        self.runner.run(
            ["apt-get", "install", "-y", "--no-install-recommends", "mimic", "dkms", "bpftool"],
            timeout=600,
        )
        return self.check()

    def check(self, device=None):
        version = self.runner.run(["mimic", "--version"], check=False).stdout.strip()
        match = re.match(r"(\d+)\.(\d+)", platform.release())
        kernel_ok = bool(match and tuple(map(int, match.groups())) >= (6, 1))
        module = self.runner.run(["modinfo", "mimic"], check=False)
        data = {
            "kernel": platform.release(),
            "kernel_ge_6_1": kernel_ok,
            "btf": Path("/sys/kernel/btf/vmlinux").is_file(),
            "version": version,
            "module_available": module.returncode == 0,
            "dkms": self.runner.run(["dkms", "status"], check=False).stdout.strip(),
            "bpf_features": self.runner.run(
                ["bpftool", "-j", "feature", "probe", "kernel"], check=False
            ).stdout.strip(),
        }
        if device:
            interface(device)
            data["link"] = self.runner.json(["ip", "-j", "-d", "link", "show", "dev", device])
        data["prerequisites_ok"] = (
            kernel_ok and data["btf"] and bool(version) and data["module_available"]
        )
        data["note"] = "最终兼容性以 mimic run --check 和实际启动为准；不会调整内核或 offload"
        return data

    def configure(self, tunnel_id, device, public_address, udp_port, xdp_mode="skb"):
        interface(device)
        ip(public_address)
        port(udp_port)
        tunnel = Tunnel(**self.store.get("tunnel", tunnel_id)).validate()
        if xdp_mode not in ("skb", "native"):
            raise ValidationError("XDP 模式必须是 skb 或 native")
        for other in self.store.list("tunnel"):
            config = self.store.runtime("mimic-config:" + other["tunnel_id"], {})
            if other["tunnel_id"] != tunnel_id and config.get("device") == device:
                raise ConflictError("首版每个物理接口只允许一个受管 Mimic 实例，避免争用 XDP")
        unit = f"relayaxis-mimic-{tunnel_id}.service"
        if self.services.state(unit)["active"]:
            raise ConflictError("先切回原生 WG，再修改 Mimic 配置")
        data = {
            "tunnel_id": tunnel_id,
            "device": device,
            "public_address": public_address,
            "udp_port": udp_port,
            "xdp_mode": xdp_mode,
            "role": tunnel.role,
        }
        self.store.set_runtime("mimic-config:" + tunnel_id, data)
        return data

    def status(self, tunnel_id):
        config = self.store.runtime("mimic-config:" + tunnel_id, {})
        unit = f"relayaxis-mimic-{tunnel_id}.service"
        version = self.runner.run(["mimic", "--version"], check=False).stdout.strip()
        return {
            "tunnel_id": tunnel_id,
            "configured": bool(config),
            "version": version,
            "xdp_mode": config.get("xdp_mode"),
            "enabled": self.services.state(unit)["active"],
            "device": config.get("device"),
            "public_address": config.get("public_address"),
            "udp_port": config.get("udp_port"),
            "verified_pair": False,
        }

    def toggle(self, tunnel_id, enabled):
        self.runner.require_root()
        with file_lock(self.paths.state / "mimic.lock"):
            config = self.store.runtime("mimic-config:" + tunnel_id)
            if not config:
                raise ValidationError("请先配置本端 Mimic 的网卡、匹配地址和 UDP 端口")
            unit = f"relayaxis-mimic-{tunnel_id}.service"
            if not enabled:
                if self.store.runtime("mimic-owned:" + tunnel_id):
                    self.services.action("stop", unit)
                    self.services.action("disable", unit)
                return self.status(tunnel_id)
            preflight = self.check(config["device"])
            if not preflight["prerequisites_ok"]:
                raise ValidationError("Mimic 前置条件不满足，可以继续使用原生 WireGuard")
            path = self.paths.config / "mimic" / f"{tunnel_id}.conf"
            unit_path = self.paths.units / unit
            owned = self.store.runtime("mimic-owned:" + tunnel_id)
            if (path.exists() or unit_path.exists()) and not owned:
                raise ConflictError("拒绝覆盖非受管 Mimic 配置")
            attached = any(
                link.get("xdp", {}).get("attached") for link in preflight.get("link", [])
            )
            if attached and not self.services.state(unit)["active"]:
                raise ConflictError("网卡已有 XDP 程序，拒绝自动覆盖")
            host = config["public_address"]
            if ":" in host:
                host = f"[{host}]"
            origin = "remote" if config["role"] == "controller" else "local"
            resource = ResourceFiles(self.paths, self.store, self.services)
            with resource.transaction(unit, [path, unit_path]) as transaction_id:
                atomic_write(
                    path,
                    f"# Managed by RelayAxis\nxdp_mode = {config['xdp_mode']}\nfilter = {origin}={host}:{config['udp_port']}\n",
                )
                self.runner.run(["modprobe", "mimic"])
                self.runner.run(["mimic", "run", "--check", "--file", str(path), config["device"]])
                atomic_write(
                    unit_path,
                    f"""# Managed by RelayAxis
[Unit]
Description=RelayAxis Mimic {tunnel_id}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/sbin/modprobe mimic
ExecStart=/usr/bin/mimic run --file {path} {config["device"]}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
""",
                )
                self.services.daemon_reload()
                self.services.action("enable", unit)
                self.services.action("start", unit)
                if not self.services.healthy(unit):
                    self.services.action("stop", unit)
                    self.services.action("disable", unit)
                    raise ApplyError("本端 Mimic 启动失败，已停用")
                resource.commit(
                    transaction_id,
                    lambda db: self.store.set_runtime(
                        "mimic-owned:" + tunnel_id, {"unit": unit, "config": str(path)}, db
                    ),
                )
            return self.status(tunnel_id)

    def verify_pair(self, server_id, transport):
        server = self.store.get("server", server_id)
        local = self.status(server["tunnel_id"])
        remote = transport.request(server, {"operation": "mimic-status"})
        consistent = local["enabled"] == remote.get("enabled") and (
            not local["enabled"]
            or (
                bool(local["version"])
                and remote.get("tunnel_id") == server["tunnel_id"]
                and local["version"] == remote.get("version")
                and local["xdp_mode"] == remote.get("xdp_mode")
                and local["public_address"] == remote.get("public_address")
                and local["udp_port"] == remote.get("udp_port")
            )
        )
        if not consistent:
            raise ApplyError("双端 Mimic 状态不一致，不能声明模式切换成功")
        return {
            "verified_pair": True,
            "mode": "mimic" if local["enabled"] else "wireguard",
            "local": local,
            "remote": remote,
        }
