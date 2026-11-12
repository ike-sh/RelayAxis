# Controller 与 Ingress 首次部署

以下地址是示例，不能直接作为生产配置。先确认管理员现有网络策略允许 WG UDP、WG 内 SSH 和业务 TCP/UDP。RelayAxis 不改防火墙。

## 1. 安装与只读检查

两端从同一版本源码安装：

```bash
# 中转端（可以只有 NAT IPv4）
sudo bash install.sh --role controller --node-id controller-1
# 公网前置机 A
sudo bash install.sh --role ingress --node-id ingress-a

sudo ra status
sudo ra doctor
```

Controller：

```bash
sudo ra egress discover
sudo ra ipv6 list
sudo ra realm scan
```

用实际地址编辑 `examples/egress-main.json`、`examples/egress-external-pbr.json`。表名使用 `main` 或数字 ID，外部 PBR 始终 `managed: false`。如已有 `ipv4-eth1-pbr.service`，填写 `dependency_service`，保留原服务。

```bash
sudo ra egress add --file /root/egress-main.json
sudo ra egress add --file /root/egress-cn2.json
sudo ra egress check line-cn2 192.0.2.80 5203 --protocol both
```

如果确实需要由 RelayAxis 创建新 PBR，使用空闲独立表、空闲优先级、现有本机源地址和网关，设置 `managed: true`，然后 `ra egress apply ID`。不要把现有外部表标为 managed。修改活动自建 PBR 前先禁用并同步相关业务。

## 2. 每个前置机创建一条 WG

Controller 可运行 `sudo ra wg allocate` 获取不重叠的 `/30`。两端隧道 `tunnel_id`、接口名保持一致；两端地址互换。Controller 的 Endpoint 是 **Ingress 公网地址:WG监听端口**；Ingress 无 Endpoint，等待 NAT 侧发起。

```bash
# Controller，编辑 tunnel-controller.json 后：
sudo ra wg create --file /root/tunnel-controller.json
sudo ra wg export front-a --file /root/controller-pair.json

# Ingress，编辑 tunnel-ingress.json 后：
sudo ra wg create --file /root/tunnel-ingress.json
sudo ra wg export front-a --file /root/ingress-pair.json
```

通过管理员已有可信通道交换两个公开 JSON 配对包，核对公钥指纹和内网地址。它们不含私钥，SHA-256 仅检测传输破损。

```bash
# Controller：
sudo ra wg pair front-a --file /root/ingress-pair.json
sudo ra wg apply front-a
# Ingress：
sudo ra wg pair front-a --file /root/controller-pair.json
sudo ra wg apply front-a
sudo ra wg status front-a
```

从 Controller `ping -c 3 10.203.0.2` 触发握手；确认两端 `latest-handshakes`、流量和 peer `/32` 路由。没有必要让最终落地安装 WG，不需要开启中转主机的 IP forwarding：业务由 Realm 本地套接字终止并重新连接。

添加前置机 B 时重复创建独立隧道，例如 Controller `10.203.0.5/30`、Ingress B `10.203.0.6/30`、接口 `ra-b`。同一条隧道可以承载任意多条业务规则。

## 3. 配置受限 SSH 同步

Controller 为每台 Ingress 生成专用密钥：

```bash
sudo install -d -m 700 /etc/relayaxis/ssh
sudo ssh-keygen -t ed25519 -N '' -f /etc/relayaxis/ssh/front-a
```

将 `front-a.pub` 通过可信通道送到 Ingress。Ingress 配置 Agent 和生成授权行：

```bash
sudo ra agent configure --server-id front-a --tunnel-id front-a \
    --listen-address 0.0.0.0 --port-min 1024 --port-max 65535
sudo ra agent key-line --public-key /root/front-a.pub \
    --controller-address 10.203.0.1
```

管理员把输出的 **完整 authorized_keys_line 值** 追加到目标 root 用户现有 `~/.ssh/authorized_keys`。保留其他授权行，不替换整个文件；检查目录 0700、文件 0600。首版 Agent 应以 root 执行固定受限协议；不会设置任意 sudo 或修改 `sshd_config`。

授权行限制来源为 Controller WG `/32`，禁用转发/PTY，并强制 `/usr/local/bin/ra agent receive`。Controller 发出的 SSH 命令固定为 `ra-agent-v1`。不要使用同一私钥作为不受限的运维登录密钥。

在 Ingress 控制台查看实际 SSH 主机公钥指纹：

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Controller 可以 `ssh-keyscan -p 22 10.203.0.2` 收集公钥到临时文件，但必须通过独立可信通道核对其指纹后才写入 `/etc/relayaxis/ssh/known_hosts`。不能把未核验的 keyscan 结果直接视为可信。非 22 端口记录需使用 `[10.203.0.2]:PORT` 格式。

编辑 `examples/ingress.json` 的 ID、公网地址、隧道、SSH 路径后：

```bash
sudo ra ingress add --file /root/ingress-a.json
sudo ra sync push front-a
sudo ra sync status
```

## 4. 添加转发规则

仅 IPv6 直连可以直接使用 `rule-direct.json` 的结构。多入口使用 `rule-multi.json`，先建立对应前置机。每个 binding 独立指定公网业务端口，不必等于最终落地端口。

```bash
sudo ra rules add --file /root/my-rule.json --apply
sudo ra rules list
sudo ra rules mapping
sudo ra rules show RULE_ID
sudo ra rules test RULE_ID --protocol tcp
sudo ra rules test RULE_ID --protocol udp
```

`rules test` 测的是 Controller 到最终落地；完整业务验证需在客户端通过 IPv6 入口和每个 IPv4 入口分别测试 TCP 及应用层 UDP 请求/响应。UDP 无响应不能视为成功。

更改 JSON 只需包含要修改的字段；修改 bindings 时给出完整列表。用 `--expected-revision` 可阻止覆盖其他人的并发编辑。

```bash
sudo ra rules update RULE_ID --file /root/patch.json --expected-revision 1 --apply
sudo ra rules disable RULE_ID --apply
sudo ra rules enable RULE_ID --apply
sudo ra rules delete RULE_ID --apply
```

## 5. 导入现有日本 / 香港服务

```bash
sudo ra realm scan
sudo ra realm import --service realm-jp-9929.service --egress line-main
sudo ra realm import --service realm-hk-cn2.service --egress line-cn2
```

扫描只读；导入前保存原配置和 unit，导入规则禁用且标记为外部。此时原服务继续运行，不会产生新监听。无法无损表达的高级选项会被拒绝，不能默默丢掉。

管理员审阅出口、配置与备份后，可以显式迁移：

```bash
sudo ra realm migrate realm-jp-9929.service --confirm-migrate
```

迁移核对原文件哈希，验证候选规则，停止原服务后才启用新监听；全部验证通过才禁用原 unit。失败会尝试撤销新监听并恢复原服务。原配置和 unit 文件始终保留。只想查看和保留手动服务时不运行 migrate。
