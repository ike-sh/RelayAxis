#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_root=/
purge=0
confirmed=0
while (($#)); do
    case "$1" in
        --purge) purge=1; shift ;;
        --confirm-purge) confirmed=1; shift ;;
        --staging) install_root=${2:?缺少隔离目录}; shift 2 ;;
        *) echo '用法: sudo bash uninstall.sh [--purge --confirm-purge] [--staging /目录]' >&2; exit 2 ;;
    esac
done
if ((purge && !confirmed)); then
    echo '完全清理需要显式传入 --purge --confirm-purge。' >&2; exit 2
fi
if [[ $install_root == / ]]; then
    ((EUID == 0)) || { echo '请使用 sudo 运行。' >&2; exit 1; }
else
    [[ $install_root == /* ]] || { echo '隔离目录需要绝对路径。' >&2; exit 2; }
fi
uninstall_args=(--root "$install_root")
if ((purge)); then
    uninstall_args+=(--purge)
fi
PYTHONPATH="$source_dir" python3 -m relayaxis.maintenance "${uninstall_args[@]}"
