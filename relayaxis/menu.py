import argparse
import json
import shlex

from .errors import RelayAxisError


class Cancelled(Exception):
    pass


def ask(label, default=""):
    value = input(
        f"{label}{' [' + str(default) + ']' if default != '' else ''}（输入 / 取消）: "
    ).strip()
    if value == "/":
        raise Cancelled
    return value or str(default)


def number(label, default=""):
    while True:
        value = ask(label, default)
        try:
            value = int(value)
            if 1 <= value <= 65535:
                return value
        except ValueError:
            pass
        print("请输入 1–65535 的整数。")


def show(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def create_rule(app):
    app.require_role("controller")
    show(app.store.list("egress"))
    data = {
        "name": ask("规则名称"),
        "egress_id": ask("出口 ID"),
        "remote_host": ask("最终落地 IPv4 / 域名"),
        "remote_port": number("落地端口"),
        "remark": ask("备注"),
        "protocol": ask("协议 tcp / udp / both", "both"),
        "bindings": [],
    }
    while True:
        server = ask("入口前置机 ID，IPv6 直连填 local", "local")
        binding = {
            "server_id": server,
            "listen_address": ask("公网监听地址", "::" if server == "local" else "0.0.0.0"),
            "listen_port": number("公网业务端口"),
        }
        data["bindings"].append(binding)
        if ask("继续添加其他入口？y / n", "n").lower() != "y":
            break
    app.backups.create()
    result = app.rules.create(data)
    show(result)
    if ask("立即应用并同步？y / n", "n").lower() == "y":
        app.require_live()
        show(app.coordinator.apply_rule(result["rule_id"]))
    else:
        print("已保存，状态 PENDING_SYNC。")


# Each menu action is a real CLI command; complex object editing uses reviewed JSON.
CONTROLLER_MENUS = [
    (
        "系统状态",
        [("概览", "status", []), ("安装检查", "verify-install", []), ("完整诊断", "doctor", [])],
    ),
    (
        "IPv4 多出口管理",
        [
            ("发现现有出口 / PBR", "egress discover", []),
            ("已保存出口", "egress list", []),
            ("添加出口", "egress add --file", ["JSON 配置文件"]),
            ("修改出口", "egress update --file", ["完整 JSON 配置文件"]),
            ("应用自建出口", "egress apply", ["出口 ID"]),
            ("删除出口", "egress delete", ["出口 ID"]),
            ("路由校验", "egress check", ["出口 ID", "目标 IPv4 / 域名", "端口"]),
        ],
    ),
    (
        "IPv6 入口管理",
        [
            ("地址 / 默认路由 / 管理器", "ipv6 list", []),
            ("设置运营商标签", "ipv6 label", ["IPv6 地址", "标签"]),
            ("核对 AAAA", "ipv6 ddns", ["域名", "--address", "当前 IPv6 地址"]),
        ],
    ),
    (
        "WireGuard 组网",
        [
            ("查看隧道", "wg list", []),
            ("分配可用网段", "wg allocate", []),
            ("创建隧道", "wg create --file", ["本端隧道 JSON 文件"]),
            ("导出配对包", "wg export", ["隧道 ID"]),
            ("导入对端配对包", "wg pair", ["隧道 ID", "--file", "对端配对 JSON 文件"]),
            ("修改 Endpoint / MTU / 端口", "wg update", ["隧道 ID", "--file", "修改 JSON 文件"]),
            ("应用隧道", "wg apply", ["隧道 ID"]),
            ("握手 / 流量", "wg status", ["隧道 ID"]),
            ("重启", "wg restart", ["隧道 ID"]),
            ("禁用并应用", "wg disable", ["隧道 ID", "--apply"]),
            ("删除", "wg delete", ["隧道 ID"]),
        ],
    ),
    (
        "Mimic 管理",
        [
            ("兼容性检查", "mimic check", []),
            ("安装可选组件", "mimic install", []),
            (
                "配置本端",
                "mimic configure",
                [
                    "隧道 ID",
                    "--interface",
                    "物理接口",
                    "--public-address",
                    "前置机公网地址",
                    "--udp-port",
                    "WG 监听端口",
                ],
            ),
            ("状态", "mimic status", ["隧道 ID"]),
            ("本端启用", "mimic enable", ["隧道 ID"]),
            ("本端禁用", "mimic disable", ["隧道 ID"]),
            ("核验双端状态", "mimic verify", ["前置机 ID"]),
        ],
    ),
    (
        "Realm 转发管理",
        [
            ("新增规则（向导）", "wizard", []),
            ("查看 / 搜索", "rules list --search", ["名称或备注（留空列出全部）"]),
            ("详情", "rules show", ["规则 ID"]),
            ("修改并应用", "rules update", ["规则 ID", "--file", "修改 JSON 文件", "--apply"]),
            ("删除并同步撤销", "rules delete", ["规则 ID", "--apply"]),
            ("启用并应用", "rules enable", ["规则 ID", "--apply"]),
            ("禁用并撤销", "rules disable", ["规则 ID", "--apply"]),
            ("重启独立规则", "rules restart", ["规则 ID"]),
            ("端口映射", "rules mapping", []),
            ("历史版本", "rules history", ["规则 ID"]),
            ("回滚并应用", "rules rollback", ["规则 ID", "历史版本号", "--apply"]),
            ("验证配置及出口", "rules validate", ["规则 ID"]),
            (
                "复制规则",
                "rules copy",
                ["原规则 ID", "--name", "新名称", "--file", "新入口 bindings JSON 文件"],
            ),
            ("导出全部规则", "rules export --file", ["输出文件"]),
            ("只读扫描现有 Realm", "realm scan", []),
            (
                "安全导入并保留旧服务",
                "realm import --service",
                ["现有服务名", "--egress", "出口 ID"],
            ),
            ("受控迁移现有服务", "realm migrate", ["现有服务名", "--confirm-migrate"]),
        ],
    ),
    (
        "公网前置机管理",
        [
            ("列表", "ingress list", []),
            ("添加", "ingress add --file", ["前置机 JSON 文件"]),
            ("修改", "ingress update --file", ["完整前置机 JSON 文件"]),
            ("状态 / 关联规则", "ingress show", ["前置机 ID"]),
            ("删除管理记录", "ingress delete", ["前置机 ID"]),
        ],
    ),
    (
        "规则同步管理",
        [
            ("同步状态", "sync status", []),
            ("应用全部待同步规则", "sync reconcile", []),
            ("手动同步前置机", "sync push", ["前置机 ID"]),
            ("预览前置机快照", "sync snapshot", ["前置机 ID"]),
        ],
    ),
    (
        "网络诊断 / ECMP",
        [
            ("全部网络检查", "doctor", []),
            ("出口 TCP 测试", "diagnose tcp", ["目标", "端口", "--egress", "出口 ID"]),
            (
                "出口 UDP 诊断",
                "diagnose udp",
                ["目标（需支持应答）", "端口", "--egress", "出口 ID"],
            ),
            (
                "ECMP RTT 采样",
                "diagnose ecmp",
                ["目标", "端口", "--egress", "出口 ID", "--count", "采样次数"],
            ),
            ("延迟 / 丢包", "diagnose ping", ["目标", "--egress", "出口 ID"]),
            ("IPv4 DNS", "diagnose dns", ["域名"]),
        ],
    ),
    (
        "配置备份恢复",
        [
            ("创建完整备份", "backup create", []),
            ("备份列表", "backup list", []),
            ("检查备份", "backup inspect", ["备份文件"]),
            ("恢复期望配置", "backup restore", ["备份文件", "--confirm-restore"]),
            ("未完成事务", "recovery status", []),
            ("修复应用中断", "recovery repair", []),
        ],
    ),
    (
        "日志与系统维护",
        [
            ("服务日志", "diagnose logs", ["systemd 服务名"]),
            ("状态", "status", []),
            ("故障诊断", "doctor", []),
        ],
    ),
    ("更新管理", [("从审阅过的本地源码更新", "update --source", ["源码目录绝对路径"])]),
    (
        "卸载 RelayAxis",
        [
            ("普通卸载（保留配置）", "uninstall", []),
            ("完全清理（需要确认）", "uninstall --purge --confirm-purge", []),
        ],
    ),
]


def menu(app):
    from .cli import dispatch, parser

    if not app.settings():
        print("请先初始化角色。")
        try:
            role = ask("角色：1 Controller / 2 Ingress", "1")
            if role not in ("1", "2"):
                raise Cancelled
            app.initialize("controller" if role == "1" else "ingress", ask("节点 ID"))
        except (Cancelled, KeyboardInterrupt, EOFError):
            return 0
    menus = CONTROLLER_MENUS
    if app.settings()["role"] == "ingress":
        menus = [m for i, m in enumerate(CONTROLLER_MENUS) if i in (0, 2, 3, 4, 9, 10, 11, 12)]
        menus.insert(
            4,
            (
                "Ingress Agent 管理",
                [
                    ("已应用版本", "agent status", []),
                    (
                        "配置授权策略",
                        "agent configure --server-id",
                        ["前置机 ID", "--tunnel-id", "隧道 ID", "--listen-address", "公网监听地址"],
                    ),
                    (
                        "生成受限密钥授权行",
                        "agent key-line --public-key",
                        ["Controller SSH 公钥文件", "--controller-address", "Controller WG 地址"],
                    ),
                ],
            ),
        )
    while True:
        try:
            print(f"\n========== RelayAxis {app.settings()['role']} ==========\n")
            for index, (label, _) in enumerate(menus, 1):
                print(f"{index}. {label}")
            print("0. 退出\n")
            selection = input("请选择: ").strip()
            if selection == "0":
                return 0
            if not selection.isdigit() or not 1 <= int(selection) <= len(menus):
                print("无效选项，请重新输入。")
                continue
            label, actions = menus[int(selection) - 1]
            while True:
                print(f"\n--- {label} ---")
                for index, (name, _, _) in enumerate(actions, 1):
                    print(f"{index}. {name}")
                print("0. 返回上一级")
                option = input("请选择: ").strip()
                if option == "0":
                    break
                if not option.isdigit() or not 1 <= int(option) <= len(actions):
                    print("无效选项。")
                    continue
                try:
                    name, command, fields = actions[int(option) - 1]
                    if (
                        any(word in name for word in ("删除", "卸载", "迁移", "恢复期望"))
                        and ask(f"确认{name}？输入 yes") != "yes"
                    ):
                        continue
                    if command == "wizard":
                        create_rule(app)
                        continue
                    argv = shlex.split(command)
                    for field in fields:
                        argv.append(field if field.startswith("--") else ask(field))
                    args = parser().parse_args(argv)
                    show(dispatch(args, app))
                except (Cancelled, KeyboardInterrupt):
                    print("操作已取消。")
                except (
                    RelayAxisError,
                    OSError,
                    ValueError,
                    TypeError,
                    KeyError,
                    argparse.ArgumentError,
                ) as exc:
                    print(
                        f"操作失败: {exc if isinstance(exc, RelayAxisError) else type(exc).__name__}"
                    )
                except SystemExit:
                    print("参数无效，请重试。")
        except (KeyboardInterrupt, EOFError):
            print("\n已退出。")
            return 0
