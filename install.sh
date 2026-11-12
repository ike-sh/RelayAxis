#!/usr/bin/env bash
# RelayAxis installer. No remote script execution, firewall or host tuning.
set -Eeuo pipefail
umask 077

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_root=/
role=
node_id=
realm_binary=
upgrade=0
skip_deps=0
staging=0

usage() {
    cat <<'EOF'
用法: sudo bash install.sh [--role controller|ingress] [--node-id ID]
       [--upgrade] [--realm-binary /绝对路径/realm] [--skip-deps]
测试打包: bash install.sh --staging /临时目录 --role controller --skip-deps
EOF
}

while (($#)); do
    case "$1" in
        --role) role=${2:?缺少角色}; shift 2 ;;
        --node-id) node_id=${2:?缺少节点ID}; shift 2 ;;
        --realm-binary) realm_binary=${2:?缺少Realm路径}; shift 2 ;;
        --upgrade) upgrade=1; shift ;;
        --skip-deps) skip_deps=1; shift ;;
        --staging) install_root=${2:?缺少隔离目录}; staging=1; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[[ $(uname -s) == Linux ]] || { echo '安装器只支持 Linux。' >&2; exit 1; }
if ((staging)); then
    [[ $install_root == /* && $install_root != / ]] || { echo '隔离目录必须是非 / 的绝对路径。' >&2; exit 2; }
    install_root=$(realpath -m -- "$install_root")
    [[ $install_root != / ]] || { echo '隔离目录不能指向系统根目录。' >&2; exit 2; }
    skip_deps=1
else
    ((EUID == 0)) || { echo '请使用 sudo 运行安装器。' >&2; exit 1; }
    [[ -d /run/systemd/system ]] || { echo '需要运行中的 systemd。' >&2; exit 1; }
fi
if ! command -v python3 >/dev/null; then
    if ((!skip_deps && EUID == 0)) && command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y --no-install-recommends python3
    else
        echo '需要 Python 3.11+；请先安装 Python 或允许自动安装依赖。' >&2; exit 1
    fi
fi
python3 -c 'import sys; assert sys.version_info >= (3,11), "需要 Python 3.11+"'
python_binary=$(readlink -f -- "$(command -v python3)")
[[ $python_binary =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'Python 路径无效。' >&2; exit 1; }
[[ $install_root =~ ^/[a-zA-Z0-9_./-]*$ ]] || { echo '安装路径不能含空格或特殊字符。' >&2; exit 2; }
install_root=${install_root%/}
prefix="$install_root/opt/relayaxis"
state_dir="$install_root/var/lib/relayaxis"
settings="$install_root/etc/relayaxis/settings.json"
global_command="$install_root/usr/local/bin/ra"

if [[ -z $role ]]; then
    if ((upgrade)) && [[ -f $settings ]]; then
        role=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["role"])' "$settings")
    else
        printf '1. 中转管理中心 Controller\n2. IPv4 公网前置机 Ingress\n3. 检查现有安装\n4. 升级 RelayAxis\n0. 退出\n'
        read -r -p '请选择: ' choice
        case "$choice" in
            1) role=controller ;;
            2) role=ingress ;;
            3) [[ -x $global_command ]] && "$global_command" verify-install; exit ;;
            4) [[ -f $settings ]] || { echo '未找到现有安装。' >&2; exit 1; }
               upgrade=1
               role=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["role"])' "$settings") ;;
            0) exit 0 ;;
            *) echo '无效选择。' >&2; exit 2 ;;
        esac
    fi
fi
[[ $role == controller || $role == ingress ]] || { echo '角色无效。' >&2; exit 2; }
if [[ -f $settings ]]; then
    existing_role=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["role"])' "$settings")
    [[ $role == "$existing_role" ]] || { echo '不能覆盖已有角色。' >&2; exit 1; }
    existing_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node_id"])' "$settings")
    [[ -z $node_id || $node_id == "$existing_id" ]] || { echo '不能覆盖已有节点身份。' >&2; exit 1; }
    node_id=$existing_id
fi
node_id=${node_id:-$(hostname -s)}
[[ $node_id =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$ ]] || { echo '节点 ID 无效。' >&2; exit 2; }
if [[ -e $prefix && ! -f $prefix/.relayaxis-owned ]]; then
    echo '程序目录已存在且未由 RelayAxis 登记，拒绝覆盖。' >&2; exit 1
fi
if [[ -e $global_command && ! -f $state_dir/installation.json ]]; then
    echo 'ra 命令已存在且未登记，拒绝覆盖。' >&2; exit 1
fi
[[ ! -L $global_command ]] || { echo 'ra 路径是符号链接，拒绝覆盖。' >&2; exit 1; }
mkdir -p -- "$install_root/run" "$state_dir"
command -v flock >/dev/null || { echo '需要 util-linux 的 flock。' >&2; exit 1; }
exec {install_lock_fd}>"$install_root/run/relayaxis-install.lock"
flock -n "$install_lock_fd" || { echo '另一个安装或卸载正在运行。' >&2; exit 1; }
exec {control_lock_fd}>"$state_dir/control.lock"
flock -w 60 "$control_lock_fd" || { echo 'Controller 正忙，请稍后升级。' >&2; exit 1; }
if ((!staging)); then
    for unit in relayaxis-reconcile.service relayaxis-reconcile.timer; do
        destination="/etc/systemd/system/$unit"
        [[ ! -L $destination ]] || { echo "服务路径是符号链接: $unit" >&2; exit 1; }
        if [[ -e $destination && ! -f $state_dir/installation.json ]]; then
            echo "拒绝覆盖未登记的服务: $unit" >&2; exit 1
        fi
    done
fi

if ((!skip_deps)); then
    command -v apt-get >/dev/null || { echo '自动依赖安装支持 Debian/Ubuntu；其他发行版请自行安装依赖并使用 --skip-deps。' >&2; exit 1; }
    apt-get update
    apt-get install -y --no-install-recommends python3 iproute2 wireguard-tools openssh-client iputils-ping ca-certificates
fi
if ((!staging)); then
    for tool in ip ss wg ssh systemctl; do
        command -v "$tool" >/dev/null || { echo "缺少依赖: $tool" >&2; exit 1; }
    done
fi

if [[ -x $global_command && -f $settings ]]; then
    "$global_command" --json backup create
fi
mkdir -p -- "$prefix/releases" "$prefix/bin" "$(dirname -- "$global_command")" "$state_dir"
touch "$prefix/.relayaxis-owned"
chmod 700 "$state_dir"
release_id=$(python3 -c 'import uuid; print(uuid.uuid4().hex[:16])')
candidate="$prefix/releases/$release_id"
mkdir -p -- "$candidate"
cp -a -- "$source_dir/relayaxis" "$source_dir/ra" "$source_dir/install.sh" "$source_dir/uninstall.sh" "$source_dir/pyproject.toml" "$source_dir/README.md" "$source_dir/LICENSE" "$candidate/"
cp -a -- "$source_dir/systemd" "$source_dir/docs" "$source_dir/examples" "$candidate/"
chmod 755 "$candidate/ra"
if [[ -z $realm_binary ]]; then
    if [[ -f $settings ]]; then
        realm_binary=$(PYTHONPATH="$candidate" python3 -c 'from relayaxis.storage import Store; import sys; print(Store(sys.argv[1]).runtime("realm-binary", ""))' "$state_dir/state.sqlite3")
    fi
    if [[ -z $realm_binary ]]; then
        realm_binary=$(command -v realm || true)
    fi
    if [[ -z $realm_binary ]]; then
        realm_binary="$prefix/bin/realm"
        if [[ ! -x $realm_binary ]] && ((!staging)); then
            PYTHONPATH="$candidate" python3 -m relayaxis.fetch_realm "$realm_binary"
        fi
    fi
fi
[[ $realm_binary =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'Realm 路径无效。' >&2; exit 2; }
if ((!staging)); then
    [[ -x $realm_binary ]] || { echo 'Realm 不可执行。' >&2; exit 1; }
    "$realm_binary" --version
fi

old_release=$(readlink "$prefix/current" || true)
rollback_dir=$(mktemp -d "$state_dir/install-XXXXXXXX")
if [[ -f $global_command ]]; then
    cp -a -- "$global_command" "$rollback_dir/ra"
fi
timer_active=0
timer_enabled=0
if ((!staging)); then
    systemctl is-active --quiet relayaxis-reconcile.timer && timer_active=1
    systemctl is-enabled --quiet relayaxis-reconcile.timer && timer_enabled=1
    for unit in relayaxis-reconcile.service relayaxis-reconcile.timer; do
        if [[ -f /etc/systemd/system/$unit ]]; then
            cp -a -- "/etc/systemd/system/$unit" "$rollback_dir/$unit"
        fi
    done
fi
rollback_install() {
    status=$?
    if ((status)); then
        set +e
        echo '安装验证失败，正在恢复原程序链接；升级前备份已保留。' >&2
        if ((!staging)); then
            systemctl stop relayaxis-reconcile.timer relayaxis-reconcile.service
        fi
        if [[ -n $old_release ]]; then
            ln -sfn -- "$old_release" "$prefix/current"
        else
            rm -f -- "$prefix/current"
        fi
        if [[ -f $rollback_dir/ra ]]; then
            cp -a -- "$rollback_dir/ra" "$global_command"
        else
            rm -f -- "$global_command"
        fi
        if ((!staging)); then
            for unit in relayaxis-reconcile.service relayaxis-reconcile.timer; do
                if [[ -f $rollback_dir/$unit ]]; then
                    cp -a -- "$rollback_dir/$unit" "/etc/systemd/system/$unit"
                else
                    rm -f -- "/etc/systemd/system/$unit"
                fi
            done
            systemctl daemon-reload
            if ((timer_enabled)); then systemctl enable relayaxis-reconcile.timer; fi
            if ((timer_active)); then systemctl start relayaxis-reconcile.timer; fi
        fi
    fi
    rm -rf -- "$rollback_dir"
    exit "$status"
}
trap rollback_install EXIT
if ((!staging)) && [[ -f $state_dir/installation.json ]]; then
    systemctl stop relayaxis-reconcile.timer relayaxis-reconcile.service
fi
ln -s -- "releases/$release_id" "$prefix/.current-$release_id"
mv -Tf -- "$prefix/.current-$release_id" "$prefix/current"
cat > "$global_command.new-$release_id" <<EOF
#!/bin/sh
exec "$python_binary" "$prefix/current/ra" --root "${install_root:-/}" "\$@"
EOF
chmod 755 "$global_command.new-$release_id"
mv -Tf -- "$global_command.new-$release_id" "$global_command"
"$global_command" --json init --role "$role" --node-id "$node_id" --realm-binary "$realm_binary"

if ((!staging)); then
    for unit in relayaxis-reconcile.service relayaxis-reconcile.timer; do
        destination="/etc/systemd/system/$unit"
        if [[ -e $destination && ! -f $state_dir/installation.json ]]; then
            echo "拒绝覆盖未登记的服务: $unit" >&2; exit 1
        fi
        install -m 600 "$candidate/systemd/$unit" "$destination"
    done
    systemctl daemon-reload
    if [[ $role == controller ]]; then
        systemctl enable --now relayaxis-reconcile.timer
    fi
    "$global_command" --json verify-install
else
    "$global_command" --json version
    "$global_command" --json rules list >/dev/null 2>&1 || [[ $role == ingress ]]
fi
python3 - "$state_dir/installation.json" "$prefix" "$prefix/current" "$release_id" <<'PY'
import json,os,sys,tempfile
target,prefix,source,release=sys.argv[1:]
fd,temp=tempfile.mkstemp(dir=os.path.dirname(target))
with os.fdopen(fd,'w') as f:
    json.dump({'schema':1,'prefix':prefix,'source':source,'release':release,'units':['relayaxis-reconcile.service','relayaxis-reconcile.timer']},f)
    f.flush(); os.fsync(f.fileno())
os.chmod(temp,0o600); os.replace(temp,target)
PY
trap - EXIT
rm -rf -- "$rollback_dir"
printf 'RelayAxis 安装完成，角色: %s。运行 %s 进入中文菜单。\n' "$role" "$global_command"
