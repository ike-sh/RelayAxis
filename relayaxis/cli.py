import argparse
import json
import os
import sqlite3
import sys
import tarfile
from pathlib import Path

from . import __version__
from .app import App
from .config import Paths
from .core import diagnostics, ipv6, realm
from .core.network import egress_from_dict
from .core.sync import authorized_key, write_policy
from .core.system import atomic_write, file_lock
from .core.wireguard import Tunnel, allocate_subnet, pairing_bundle
from .errors import RelayAxisError, ValidationError
from .models import new_id
from .roles.ingress import receive


def parser():
    root = argparse.ArgumentParser(prog="ra", description="RelayAxis 多入口、多出口中转管理")
    root.add_argument("--json", action="store_true", help="以 JSON 输出")
    root.add_argument(
        "--root", type=Path, default=Path("/"), help="隔离的配置根目录，禁止向宿主机应用"
    )
    commands = root.add_subparsers(dest="command")
    commands.add_parser("version", help="版本")
    init = commands.add_parser("init", help="初始化角色和节点身份")
    init.add_argument("--role", choices=("controller", "ingress"), required=True)
    init.add_argument("--node-id", required=True)
    init.add_argument("--realm-binary")
    for name in ("status", "doctor", "verify-install"):
        commands.add_parser(name)

    def group(name, actions):
        sub = commands.add_parser(name).add_subparsers(dest="action", required=True)
        return {action: sub.add_parser(action) for action in actions}

    rules = group(
        "rules",
        (
            "list",
            "show",
            "add",
            "update",
            "delete",
            "enable",
            "disable",
            "restart",
            "apply",
            "copy",
            "batch",
            "history",
            "rollback",
            "validate",
            "mapping",
            "export",
            "import",
            "test",
        ),
    )
    rules["list"].add_argument("--search", default="")
    rules["list"].add_argument("--all", action="store_true")
    for name in (
        "show",
        "update",
        "delete",
        "enable",
        "disable",
        "restart",
        "apply",
        "copy",
        "history",
        "rollback",
        "validate",
        "test",
    ):
        rules[name].add_argument("rule_id")
    for name in ("add", "update", "copy", "import"):
        rules[name].add_argument("--file", type=Path, required=True)
    rules["copy"].add_argument("--name", required=True)
    rules["update"].add_argument("--expected-revision", type=int)
    rules["rollback"].add_argument("revision", type=int)
    rules["batch"].add_argument("operation", choices=("enable", "disable", "delete"))
    rules["batch"].add_argument("ids", nargs="+")
    for name in ("add", "update", "delete", "enable", "disable", "copy", "batch", "rollback"):
        rules[name].add_argument("--apply", action="store_true")
    rules["validate"].add_argument("--offline", action="store_true")
    rules["export"].add_argument("--file", type=Path, required=True)
    rules["test"].add_argument("--protocol", choices=("tcp", "udp"), default="tcp")

    egress = group(
        "egress",
        (
            "list",
            "discover",
            "add",
            "update",
            "delete",
            "apply",
            "activate",
            "deactivate",
            "check",
            "test",
        ),
    )
    for name in ("add", "update"):
        egress[name].add_argument("--file", type=Path, required=True)
    for name in ("delete", "apply", "activate", "deactivate", "check", "test"):
        egress[name].add_argument("egress_id")
    egress["activate"].add_argument("--from-config", action="store_true", help=argparse.SUPPRESS)
    for name in ("check", "test"):
        egress[name].add_argument("host")
        egress[name].add_argument("port", type=int)
        egress[name].add_argument("--protocol", choices=("tcp", "udp", "both"), default="tcp")

    v6 = group("ipv6", ("list", "label", "ddns"))
    v6["label"].add_argument("address")
    v6["label"].add_argument("label")
    v6["ddns"].add_argument("host")
    v6["ddns"].add_argument("--address", action="append", required=True)

    wg = group(
        "wg",
        (
            "list",
            "allocate",
            "create",
            "update",
            "export",
            "pair",
            "apply",
            "enable",
            "disable",
            "restart",
            "delete",
            "status",
            "activate",
            "deactivate",
        ),
    )
    wg["allocate"].add_argument("--pool", default="10.203.0.0/16")
    for name in ("create", "update", "pair"):
        wg[name].add_argument("--file", type=Path, required=True)
    for name in (
        "update",
        "export",
        "pair",
        "apply",
        "enable",
        "disable",
        "restart",
        "delete",
        "status",
        "activate",
        "deactivate",
    ):
        wg[name].add_argument("tunnel_id")
    wg["pair"].add_argument("--replace-peer", action="store_true")
    wg["export"].add_argument("--file", type=Path)
    for name in ("create", "update", "pair", "enable", "disable"):
        wg[name].add_argument("--apply", action="store_true")

    ingress = group("ingress", ("list", "add", "update", "delete", "show", "sync", "status"))
    for name in ("add", "update"):
        ingress[name].add_argument("--file", type=Path, required=True)
    for name in ("delete", "show", "sync", "status"):
        ingress[name].add_argument("server_id")

    sync = group("sync", ("status", "reconcile", "push", "snapshot", "set-revision"))
    for name in ("push", "snapshot", "set-revision"):
        sync[name].add_argument("server_id")
    sync["set-revision"].add_argument("revision", type=int)
    sync["set-revision"].add_argument("--confirm-reseed", action="store_true", required=True)

    agent = group("agent", ("configure", "receive", "key-line", "status"))
    agent["configure"].add_argument("--server-id", required=True)
    agent["configure"].add_argument("--tunnel-id", required=True)
    agent["configure"].add_argument("--listen-address", action="append", required=True)
    agent["configure"].add_argument("--port-min", type=int, default=1)
    agent["configure"].add_argument("--port-max", type=int, default=65535)
    agent["configure"].add_argument("--allow-mimic", action="store_true")
    agent["key-line"].add_argument("--public-key", type=Path, required=True)
    agent["key-line"].add_argument("--controller-address", required=True)

    existing = group("realm", ("scan", "import", "migrate"))
    for name in ("scan", "import"):
        existing[name].add_argument("--directory", type=Path, action="append")
    existing["import"].add_argument("--service", required=True)
    existing["import"].add_argument("--egress", required=True)
    existing["migrate"].add_argument("service")
    existing["migrate"].add_argument("--confirm-migrate", action="store_true", required=True)

    backup = group("backup", ("create", "list", "inspect", "restore"))
    backup["create"].add_argument("--file", type=Path)
    for name in ("inspect", "restore"):
        backup[name].add_argument("file", type=Path)
    backup["restore"].add_argument("--confirm-restore", action="store_true", required=True)
    backup["restore"].add_argument("--with-keys", action="store_true")
    group("recovery", ("status", "repair"))

    diagnose = group("diagnose", ("network", "tcp", "udp", "ecmp", "dns", "ping", "logs", "events"))
    for name in ("tcp", "udp", "ecmp"):
        diagnose[name].add_argument("host")
        diagnose[name].add_argument("port", type=int)
        diagnose[name].add_argument("--egress", required=True)
    diagnose["ecmp"].add_argument("--count", type=int, default=10)
    diagnose["ecmp"].add_argument("--interval", type=float, default=0.2)
    diagnose["ecmp"].add_argument("--timeout", type=float, default=3)
    diagnose["dns"].add_argument("host")
    diagnose["ping"].add_argument("host")
    diagnose["ping"].add_argument("--egress", required=True)
    diagnose["ping"].add_argument("--count", type=int, default=5)
    diagnose["events"].add_argument("--limit", type=int, default=100)
    diagnose["logs"].add_argument("unit")
    diagnose["logs"].add_argument("--lines", type=int, default=100)

    mimic = group(
        "mimic", ("install", "check", "configure", "status", "enable", "disable", "verify")
    )
    mimic["check"].add_argument("--interface")
    for name in ("configure", "status", "enable", "disable"):
        mimic[name].add_argument("tunnel_id")
    mimic["configure"].add_argument("--interface", required=True)
    mimic["configure"].add_argument("--public-address", required=True)
    mimic["configure"].add_argument("--udp-port", required=True, type=int)
    mimic["configure"].add_argument("--xdp-mode", choices=("skb", "native"), default="skb")
    mimic["verify"].add_argument("server_id")

    update = commands.add_parser("update")
    update.add_argument("--source", type=Path, required=True, help="已经审阅的本地源码目录")
    uninstall = commands.add_parser("uninstall")
    uninstall.add_argument("--purge", action="store_true")
    uninstall.add_argument("--confirm-purge", action="store_true")
    return root


def read_json(path):
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValidationError("JSON 输入超过 4 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def dispatch(args, app):
    cmd, action = args.command, getattr(args, "action", None)
    if cmd == "init":
        return app.initialize(args.role, args.node_id, args.realm_binary)
    if cmd == "status":
        return app.status()
    if cmd == "doctor":
        return diagnostics.doctor(app)
    if cmd == "verify-install":
        return app.verify_install()
    # An Ingress cannot author controller rules, egresses, or arbitrary snapshots.
    if cmd in {"rules", "egress", "ingress", "sync", "realm"}:
        app.require_role("controller")
    if cmd == "agent":
        app.require_role("ingress")
    if cmd == "rules":
        if action == "list":
            return [
                {
                    **r,
                    "runtime": app.store.runtime("rule:" + r["rule_id"], {"state": "PENDING_SYNC"}),
                }
                for r in app.rules.list(args.search, args.all)
            ]
        if action == "show":
            endpoints = app.deployment.manifest("rule-" + args.rule_id)
            return {
                **app.rules.get(args.rule_id),
                "runtime": app.store.runtime("rule:" + args.rule_id, {}),
                "services": {
                    realm.Endpoint(**e).unit: app.services.state(realm.Endpoint(**e).unit)
                    for e in endpoints.values()
                },
            }
        if action == "history":
            return app.store.history("rule", args.rule_id)
        if action == "mapping":
            return [
                {
                    "rule_id": r["rule_id"],
                    "name": r["name"],
                    "protocol": r["protocol"],
                    "bindings": r["bindings"],
                    "target": realm.hostport(r["remote_host"], r["remote_port"]),
                    "egress_id": r["egress_id"],
                }
                for r in app.rules.list()
            ]
        if action == "export":
            return app.backups.export_rules(args.file)
        if action == "import":
            return app.backups.import_rules(args.file, app.rules)
        if action == "validate":
            endpoints = app.compiler.local(app.rules.get(args.rule_id), not args.offline)
            return {
                "network_validated": not args.offline,
                "configs": [realm.render(e) for e in endpoints],
            }
        if action == "test":
            rule = app.rules.get(args.rule_id)
            egress = egress_from_dict(app.store.get("egress", rule["egress_id"]))
            function = diagnostics.tcp_probe if args.protocol == "tcp" else diagnostics.udp_probe
            return {
                "scope": "最终落地连通性；完整双层转发见集成测试",
                "result": function(app.network, egress, rule["remote_host"], rule["remote_port"]),
            }
        if action in ("apply", "restart"):
            app.require_live()
            return app.coordinator.apply_rule(args.rule_id, action == "restart")
        if getattr(args, "apply", False):
            app.require_live()
        app.backups.create()
        if action == "add":
            result = app.rules.create(read_json(args.file))
        elif action == "update":
            result = app.rules.update(args.rule_id, read_json(args.file), args.expected_revision)
        elif action == "delete":
            result = app.rules.delete(args.rule_id)
        elif action in ("enable", "disable"):
            result = app.rules.enable(args.rule_id, action == "enable")
        elif action == "rollback":
            result = app.rules.rollback(args.rule_id, args.revision)
        elif action == "copy":
            result = app.rules.copy(args.rule_id, args.name, read_json(args.file)["bindings"])
        elif action == "batch":
            result = []
            for rule_id in args.ids:
                try:
                    value = (
                        app.rules.delete(rule_id)
                        if args.operation == "delete"
                        else app.rules.enable(rule_id, args.operation == "enable")
                    )
                    result.append(
                        {"rule": value, "application": app.coordinator.apply_rule(rule_id)}
                        if args.apply
                        else {"rule": value, "state": "PENDING_SYNC"}
                    )
                except RelayAxisError as exc:
                    result.append({"rule_id": rule_id, "state": "FAILED", "error": str(exc)})
            return result
        else:
            raise ValidationError("未知规则操作")
        return (
            {"rule": result, "application": app.coordinator.apply_rule(result["rule_id"])}
            if args.apply
            else {
                "rule": result,
                "state": "PENDING_SYNC",
                "note": "已保存期望配置；运行 rules apply 或 sync reconcile 才会应用",
            }
        )
    if cmd == "egress":
        if action == "list":
            return app.store.list("egress")
        if action == "discover":
            return app.network.discover_egresses()
        if action in ("add", "update"):
            app.backups.create()
            return app.routing.save(read_json(args.file), action == "update")
        if action in ("check", "test"):
            egress = egress_from_dict(app.store.get("egress", args.egress_id))
            if action == "check":
                return app.network.validate_egress(
                    egress, app.network.resolve4(args.host)[0], args.port, args.protocol
                )
            if args.protocol == "both":
                return {
                    "tcp": diagnostics.tcp_probe(app.network, egress, args.host, args.port),
                    "udp": diagnostics.udp_probe(app.network, egress, args.host, args.port),
                }
            return (diagnostics.tcp_probe if args.protocol == "tcp" else diagnostics.udp_probe)(
                app.network, egress, args.host, args.port
            )
        app.require_live()
        if action == "activate":
            return app.routing.activate(args.egress_id, args.from_config)
        return getattr(app.routing, action)(args.egress_id)
    if cmd == "ipv6":
        if action == "list":
            return ipv6.discover(app.network, app.runner, app.store.runtime("ipv6-labels", {}))
        if action == "ddns":
            return ipv6.check_aaaa(args.host, args.address)
        from .models import ip, text

        ip(args.address, 6)
        text(args.label, "标签", 100)
        data = app.store.runtime("ipv6-labels", {})
        data[args.address] = args.label
        app.store.set_runtime("ipv6-labels", data)
        return data
    if cmd == "wg":
        if action in ("activate", "deactivate"):
            app.require_live()
            return getattr(app.wg, action)(args.tunnel_id)
        if action == "list":
            return app.store.list("tunnel")
        if action == "allocate":
            used = [t["local_address"] for t in app.store.list("tunnel")]
            used.extend(
                f"{a['local']}/{a['prefixlen']}"
                for link in app.network.addresses()
                for a in link.get("addr_info", [])
                if a.get("family") == "inet"
            )
            return allocate_subnet(used, args.pool)
        if action == "status":
            return app.wg.status(args.tunnel_id)
        if action == "export":
            result = pairing_bundle(Tunnel(**app.store.get("tunnel", args.tunnel_id)))
            if args.file:
                atomic_write(args.file, json.dumps(result, ensure_ascii=False, indent=2))
            return result
        if getattr(args, "apply", False) or action in ("apply", "restart", "delete"):
            app.require_live()
        app.backups.create()
        if action == "create":
            data = read_json(args.file)
            if data["role"] != app.settings().get("role"):
                raise ValidationError("隧道角色必须匹配安装角色")
            result = app.wg.create(data)
        elif action == "update":
            result = app.wg.update(args.tunnel_id, read_json(args.file))
        elif action == "pair":
            result = app.wg.pair(args.tunnel_id, read_json(args.file), args.replace_peer)
        elif action in ("enable", "disable"):
            result = app.wg.update(args.tunnel_id, {"enabled": action == "enable"})
        elif action == "delete":
            return app.wg.delete(args.tunnel_id)
        else:
            return app.wg.apply(args.tunnel_id, action == "restart")
        if args.apply:
            return {"tunnel": result, "application": app.wg.apply(result["tunnel_id"])}
        return result
    if cmd == "ingress":
        if action == "list":
            return [
                {**s, "sync": app.store.runtime("sync:" + s["server_id"], {})}
                for s in app.store.list("server")
            ]
        if action in ("show", "status"):
            server = app.store.get("server", args.server_id)
            return {
                **server,
                "sync": app.store.runtime("sync:" + args.server_id, {}),
                "rules": [
                    r
                    for r in app.rules.list()
                    if args.server_id in [b["server_id"] for b in r["bindings"]]
                ],
                "wg": app.wg.status(server["tunnel_id"]),
            }
        if action == "sync":
            app.require_live()
            return app.coordinator.sync_server(args.server_id)
        app.backups.create()
        return (
            app.ingresses.delete(args.server_id)
            if action == "delete"
            else app.ingresses.save(read_json(args.file), action == "update")
        )
    if cmd == "sync":
        if action == "status":
            return [
                {
                    "server_id": s["server_id"],
                    **app.store.runtime("sync:" + s["server_id"], {"state": "PENDING_SYNC"}),
                }
                for s in app.store.list("server")
            ]
        if action == "snapshot":
            return {
                "endpoints": [
                    e.__dict__
                    for e in app.compiler.ingress(
                        args.server_id, list(app.coordinator._ready().values())
                    )
                ],
                "note": "只包含本地已经准备的规则；只读预览",
            }
        if action == "set-revision":
            if args.revision < 1:
                raise ValidationError("恢复后的同步版本必须为正整数")
            with file_lock(app.paths.state / "control.lock"):
                old = app.store.runtime("sync:" + args.server_id, {})
                if args.revision <= old.get("desired_revision", 0):
                    raise ValidationError("只能提高同步版本，不能降低")
                app.store.get("server", args.server_id)
                app.store.set_runtime(
                    "sync:" + args.server_id,
                    {**old, "desired_revision": args.revision, "state": "PENDING_SYNC"},
                )
            return {"desired_revision_floor": args.revision}
        app.require_live()
        if action == "reconcile":
            return app.coordinator.reconcile()
        return app.coordinator.sync_server(args.server_id)
    if cmd == "agent":
        if action == "configure":
            policy = write_policy(
                app.paths,
                app.store,
                args.server_id,
                args.tunnel_id,
                args.listen_address,
                args.port_min,
                args.port_max,
            )
            if args.allow_mimic:
                policy["allow_mimic"] = True
                atomic_write(app.paths.config / "agent-policy.json", json.dumps(policy))
            return policy
        if action == "key-line":
            return {
                "authorized_keys_line": authorized_key(
                    args.public_key.read_text(encoding="utf-8"), args.controller_address
                )
            }
        if action == "status":
            return app.store.runtime("agent-applied", {"state": "PENDING_SYNC", "revision": 0})
        app.require_live()
        return receive(app, sys.stdin)
    if cmd == "realm":
        if action == "migrate":
            from .core.migration import Migration

            app.require_live()
            return Migration(app).migrate(args.service)
        discovered = realm.scan_existing(app.runner, args.directory)
        if action == "scan":
            return discovered
        match = next(
            (item for item in discovered if item["service"] == args.service and "config" in item),
            None,
        )
        if not match:
            raise ValidationError("未找到可导入的 Realm 服务")
        backup_dir = app.paths.backups / f"import-{new_id()}"
        result = realm.import_existing(app.store, app.rules, match, args.egress, backup_dir)
        app.store.set_runtime(
            "import:" + args.service,
            {
                **match,
                "backup_directory": str(backup_dir),
                "enabled": app.services.state(args.service)["enabled"],
            },
        )
        return {"rules": result, "state": "EXTERNAL_READ_ONLY", "backup": str(backup_dir)}
    if cmd == "backup":
        if action == "list":
            return [str(p) for p in sorted(app.paths.backups.glob("relayaxis-*.tar.gz"))]
        if action == "create":
            return app.backups.create(args.file)
        if action == "inspect":
            return app.backups.inspect(args.file)[0]
        return app.backups.restore(args.file, args.with_keys)
    if cmd == "recovery":
        if action == "status":
            return {
                "journals": [p.name for p in (app.paths.state / "journals").glob("*.json")],
                "migrations": [p.name for p in (app.paths.state / "migrations").glob("*.json")],
                "resource_journals": [
                    p.name for p in (app.paths.state / "resource-journals").glob("*.json")
                ],
                "routing_journals": [
                    p.name for p in (app.paths.state / "routing-journals").glob("*.json")
                ],
            }
        from .core.migration import Migration

        app.require_live()
        return {
            "routing": app.routing.recover(),
            "resources": app.resources.recover(),
            "deployments": app.deployment.recover(),
            "migrations": Migration(app).recover(),
        }
    if cmd == "diagnose":
        if action == "events":
            return app.store.events(args.limit)
        if action == "network":
            return diagnostics.doctor(app)
        if action == "logs":
            import re

            if (
                not re.fullmatch(r"[a-zA-Z0-9_.@-]+\.(service|timer)", args.unit)
                or not 1 <= args.lines <= 1000
            ):
                raise ValidationError("日志需要有效服务名和 1–1000 行范围")
            return {
                "unit": args.unit,
                "log": app.runner.run(
                    ["journalctl", "-u", args.unit, "-n", str(args.lines), "--no-pager"]
                ).stdout,
            }
        if action == "dns":
            return {"host": args.host, "ipv4": app.network.resolve4(args.host)}
        egress = egress_from_dict(app.store.get("egress", args.egress))
        if action == "ping":
            if not 1 <= args.count <= 100:
                raise ValidationError("ping 次数必须在 1–100")
            target = app.network.resolve4(args.host)[0]
            app.network.validate_egress(egress, target, 443, "tcp")
            return {
                "ping": app.runner.run(
                    [
                        "ping",
                        "-4",
                        "-n",
                        "-I",
                        egress.source,
                        "-c",
                        str(args.count),
                        "-W",
                        "2",
                        target,
                    ],
                    timeout=args.count * 3 + 5,
                    check=False,
                ).stdout
            }
        if action == "ecmp":
            return diagnostics.ecmp_sample(
                app.network, egress, args.host, args.port, args.count, args.interval, args.timeout
            )
        return (diagnostics.tcp_probe if action == "tcp" else diagnostics.udp_probe)(
            app.network, egress, args.host, args.port
        )
    if cmd == "mimic":
        if action == "check":
            return app.mimic.check(args.interface)
        if action == "status":
            return app.mimic.status(args.tunnel_id)
        if action == "configure":
            return app.mimic.configure(
                args.tunnel_id, args.interface, args.public_address, args.udp_port, args.xdp_mode
            )
        if action == "verify":
            app.require_role("controller")
            return app.mimic.verify_pair(args.server_id, app.transport)
        app.require_live()
        if action == "install":
            return app.mimic.install()
        return app.mimic.toggle(args.tunnel_id, action == "enable")
    if cmd in ("update", "uninstall"):
        app.require_live()
        manifest = app.paths.state / "installation.json"
        if not manifest.is_file():
            raise ValidationError("未找到安装清单，请使用源码目录的安装/卸载脚本")
        source = Path(json.loads(manifest.read_text(encoding="utf-8"))["source"])
        if cmd == "update":
            source = args.source.resolve()
            return {
                "output": app.runner.run(
                    [
                        "bash",
                        str(source / "install.sh"),
                        "--upgrade",
                        "--role",
                        app.settings()["role"],
                    ],
                    timeout=600,
                ).stdout
            }
        argv = ["bash", str(source / "uninstall.sh")]
        if args.purge:
            if not args.confirm_purge:
                raise ValidationError("完全清理需要 --purge --confirm-purge")
            argv.extend(["--purge", "--confirm-purge"])
        return {"output": app.runner.run(argv, timeout=120).stdout}
    raise ValidationError("未知命令")


def unsuccessful(result):
    if isinstance(result, dict):
        if result.get("state") in {"ERROR", "INCONCLUSIVE"}:
            return True
        if result.get("state") in {"FAILED", "PENDING_SYNC", "OUT_OF_SYNC"} and (
            "error" in result or "ingresses" in result
        ):
            return True
        if result.get("ok") is False:
            return True
        return any(unsuccessful(v) for v in result.values() if isinstance(v, (dict, list)))
    return isinstance(result, list) and any(unsuccessful(v) for v in result)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Output option is accepted before or after subcommands.
    json_output = "--json" in argv
    argv = [v for v in argv if v != "--json"]
    args = parser().parse_args((["--json"] if json_output else []) + argv)
    try:
        if args.command == "version":
            result = {"version": __version__}
        else:
            if os.name == "nt" and args.root == Path("/"):
                raise ValidationError("Windows 开发环境请使用 --root 指定隔离配置目录")
            if args.root != Path("/") and args.root.resolve() == Path("/"):
                raise ValidationError("隔离目录不能经符号链接指向系统根目录")
            app = App(Paths(args.root.resolve()))
            if args.command is None:
                from .menu import menu

                return menu(app)
            result = dispatch(args, app)
        # Agent protocol output is always JSON, regardless of the interactive preference.
        print(json.dumps(result, ensure_ascii=False, indent=None if json_output else 2))
        return 3 if unsuccessful(result) else 0
    except (
        RelayAxisError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        sqlite3.Error,
        tarfile.TarError,
    ) as exc:
        error = (
            str(exc)
            if isinstance(exc, RelayAxisError)
            else f"输入或系统操作失败: {type(exc).__name__}"
        )
        if json_output or (args.command == "agent" and args.action == "receive"):
            print(json.dumps({"state": "FAILED", "error": error}, ensure_ascii=False))
        else:
            print(f"错误: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n已取消", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
