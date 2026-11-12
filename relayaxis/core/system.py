import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..errors import SystemError


@dataclass
class Result:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class Runner:
    """All subprocesses have argv, bounded time, no shell, and scrubbed errors."""

    def run(self, argv, *, input=None, timeout=15, check=True):
        try:
            completed = subprocess.run(
                [str(a) for a in argv],
                input=input,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
        except FileNotFoundError as exc:
            if not check:
                return Result(127)
            raise SystemError(f"缺少系统工具: {Path(str(argv[0])).name}") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemError(
                f"无法运行 {Path(str(argv[0])).name}（缺少工具、权限或执行超时）"
            ) from exc
        result = Result(completed.returncode, completed.stdout, completed.stderr)
        if check and result.returncode:
            # Do not echo argv, stderr or stdin: they may contain private material.
            raise SystemError(f"{Path(str(argv[0])).name} 执行失败，退出码 {result.returncode}")
        return result

    def json(self, argv):
        try:
            return json.loads(self.run(argv).stdout)
        except ValueError as exc:
            raise SystemError("系统工具返回了无效 JSON") from exc

    def require_linux(self):
        if platform.system() != "Linux":
            raise SystemError("此操作需要 Linux；当前平台仅支持配置和纯逻辑命令")

    def require_root(self):
        self.require_linux()
        if os.geteuid() != 0:
            raise SystemError("应用系统配置需要 root，请使用 sudo")


def environment():
    return {
        "platform": platform.system(),
        "kernel": platform.release(),
        "root": hasattr(os, "geteuid") and os.geteuid() == 0,
        "systemd": Path("/run/systemd/system").is_dir(),
        "tools": {
            tool: shutil.which(tool)
            for tool in ("ip", "ss", "wg", "wg-quick", "realm", "ssh", "systemctl", "mimic")
        },
    }


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    if any(parent.is_symlink() for parent in path.parents):
        raise SystemError("拒绝通过符号链接目录写入配置")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise SystemError(f"拒绝写入符号链接: {path.name}")
    fd, temporary = tempfile.mkstemp(prefix=".ra-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), mode)
            else:
                os.chmod(temporary, mode)
            handle.write(content.encode() if isinstance(content, str) else content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def file_lock(path, timeout=20):
    """Never unlink lockfiles: waiters must keep locking the same inode."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a+b") as handle:
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    if handle.read(1) == b"":
                        handle.write(b"0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    raise SystemError("配置被其他任务锁定，请稍后重试") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class Services:
    def __init__(self, runner):
        self.runner = runner

    def daemon_reload(self):
        self.runner.run(["systemctl", "daemon-reload"])

    def state(self, unit):
        result = self.runner.run(
            ["systemctl", "show", unit, "--property=ActiveState,UnitFileState", "--value"],
            check=False,
        )
        lines = result.stdout.splitlines()
        return {
            "active": "active" in lines,
            "enabled": any(v in lines for v in ("enabled", "enabled-runtime")),
        }

    def action(self, action, unit):
        if action not in {"start", "stop", "restart", "enable", "disable", "reset-failed"}:
            raise SystemError("无效服务操作")
        self.runner.run(["systemctl", action, unit], timeout=45)

    def healthy(self, unit):
        return self.state(unit)["active"]

    def endpoint_healthy(self, endpoint):
        deadline = time.monotonic() + 2
        while True:
            if self._endpoint_listening(endpoint):
                return True
            if not self.state(endpoint.unit)["active"] or time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def _endpoint_listening(self, endpoint):
        from ..models import protocols

        if not self.healthy(endpoint.unit):
            return False
        raw = self.runner.run(
            ["systemctl", "show", endpoint.unit, "--property=MainPID", "--value"]
        ).stdout.strip()
        if not raw.isdigit() or int(raw) < 1:
            return False
        listeners = self.runner.run(["ss", "-H", "-lntup"]).stdout.splitlines()
        found = set()
        for line in listeners:
            parts = line.split()
            if len(parts) < 6 or not re.search(r"pid=" + raw + r"(?:,|\))", line):
                continue
            address, separator, number = parts[4].rpartition(":")
            if not separator or number != str(endpoint.listen_port):
                continue
            address = address.strip("[]")
            if address == endpoint.listen_address or (
                address == "*" and endpoint.listen_address in ("::", "0.0.0.0")
            ):
                found.add(parts[0])
        return protocols(endpoint.protocol) <= found
