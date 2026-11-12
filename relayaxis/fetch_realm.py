"""Pinned upstream dependency downloader; never installs over an existing Realm."""

import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

from .core.system import atomic_write
from .errors import ConflictError, ValidationError

VERSION = "v2.9.6"
ASSETS = {
    "x86_64": (
        "x86_64-unknown-linux-musl",
        "b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65",
    ),
    "aarch64": (
        "aarch64-unknown-linux-musl",
        "f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488",
    ),
}


def download(destination):
    destination = Path(destination)
    if destination.exists():
        raise ConflictError("Realm 目标已存在，拒绝覆盖")
    arch = platform.machine().lower()
    if arch not in ASSETS:
        raise ValidationError("此架构没有固定校验值，请自行安装 Realm 并指定 --realm-binary")
    asset, digest = ASSETS[arch]
    url = f"https://github.com/zhboner/realm/releases/download/{VERSION}/realm-{asset}.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read(64 * 1024 * 1024 + 1)
    if len(raw) > 64 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValidationError("Realm 下载包大小或 SHA-256 校验失败")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = [m for m in archive if m.isfile() and PurePosixPath(m.name).name == "realm"]
        if len(members) != 1 or members[0].size > 64 * 1024 * 1024:
            raise ValidationError("Realm 压缩包结构异常")
        atomic_write(destination, archive.extractfile(members[0]).read(), 0o755)
    return {"version": VERSION, "path": str(destination), "archive_sha256": digest}


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(download(sys.argv[1])))
