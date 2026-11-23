# 运维、恢复和诊断

## 状态与重试

`ra status` 区分规则期望 revision、实际 applied_revision 与状态；`ra sync status` 区分每台前置机期望/实际同步版本。离线节点显示 `PENDING_SYNC`，部分成功规则显示 `OUT_OF_SYNC`。不要仅根据 CLI 退出码 0 判断转发链路成功，仍应检查状态和客户端数据流。

`relayaxis-reconcile.timer` 在 Controller 启动后定期修复未完成事务、对 RelayAxis 自有且哈希一致的 PBR 做单接口恢复、重试最新规则，并复核活动规则路由。外部出口只报告。规则 CRUD 不触碰 WG；每条规则的服务可以短暂重启，其他规则服务不重启。计时器每分钟运行且没有高频 Restart 循环。

```bash
sudo ra doctor --json
sudo ra recovery status
sudo ra recovery repair
sudo ra egress discover
sudo ra egress health
sudo ra egress show line-cn2
sudo ra egress backend line-cn2
sudo ra sync reconcile
sudo ra wg status front-a
sudo ra diagnose events --limit 100
sudo ra diagnose logs relayaxis-reconcile.service
# 仅在审计尚未迁移的旧服务时：
sudo ra diagnose logs relayaxis-pbr-OLD_ID.service
```

若重试仍失败，先修复有效路由、源地址、WG 握手、SSH 主机指纹、Agent 授权范围或端口冲突，不要清空系统防火墙或修改默认路由来掩盖故障。

## 回滚与备份

```bash
sudo ra rules history RULE_ID
sudo ra rules rollback RULE_ID 2 --apply
sudo ra backup create --file /root/ra-backup.tar.gz
sudo ra backup inspect /root/ra-backup.tar.gz
sudo ra backup restore /root/ra-backup.tar.gz --confirm-restore
```

回滚使用新的 revision。完整备份包含 SQLite、`/etc/relayaxis` 普通文件以及已登记且哈希一致的 RelayAxis Netplan/networkd 片段快照，含本机私钥；不包含外部服务的原配置目录。原生网络快照用于审计，restore 不会直接应用主机网络，仍需 `egress plan/apply`。导入前保存的外部原文件位于 `backups/import-*`，也应独立异地保存。备份使用 tar 清单逐文件 SHA-256 校验；拒绝链接、重复成员和路径穿越，不直接 extractall。

恢复写入新期望版本，保留当前运行清单和同步计数，避免让过期确认状态覆盖当前服务器。备份中没有的当前规则会生成删除标记，等待有序撤销。不会直接替换运行中 systemd 配置或删除外部资源。

全新节点从灾难备份恢复时，先安装并初始化原角色/身份，再用 `--with-keys` 验证恢复 WG 私钥；已有不同密钥不会被覆盖。Agent 策略、同步 SSH 凭据、主机指纹需要管理员依据备份重新确认。活动节点的运行配置备份不会自动覆盖这些身份配置。

如果 Controller 数据库完全丢失，远端 Agent 的单调版本可能高于恢复后的计数。通过 Ingress 控制台 `ra agent status` 获取已应用版本，在 Controller 显式设置更高起始值：

```bash
sudo ra sync set-revision front-a 100 --confirm-reseed
sudo ra sync push front-a
```

不要降低远端 Agent 版本来接受旧配置。

## PBR 运行状态与故障排查

`active (exited)` 只表示 oneshot 的命令曾返回成功，不表示 rule/table 仍存在。统一按以下顺序查看真实状态：

```bash
sudo ra egress show line-cn2
sudo ra egress health line-cn2 --target 192.0.2.80 --port 443
ip -4 rule show
ip -4 route show table all
ip -4 route get 192.0.2.80 from SOURCE ipproto tcp dport 443
ip -4 route get 192.0.2.80 from SOURCE ipproto tcp dport 443 oif INTERFACE
```

常见状态与处理：

| 状态 | 含义 | 处理 |
|---|---|---|
| `SOURCE_MISSING` | 源 IPv4 已不在指定接口 | 先修复基础地址/DHCP/云网络配置 |
| `RULE_MISSING` | source rule 消失 | external 通知其管理者；relayaxis 检查受管片段后定向恢复 |
| `ROUTE_MISSING` | 指定表没有 default | 同上，不能用 main 可达冒充恢复 |
| `WRONG_INTERFACE` | 有效查找回落到其他网卡 | 对应 Realm 会暂停；检查 rule 优先级、表和网卡状态 |
| `WRONG_GATEWAY` / `WRONG_TABLE` | 内核结果与登记事实不同 | 审计冲突配置，保留现场，不覆盖外部条目 |
| `DEGRADED` / `UNREACHABLE` | 链路状态或 route get 异常 | 检查接口、网关邻居和网络管理器日志 |

### networkd 重启事故流程

若网络管理器重载后某条非默认出口消失：

1. 用 `egress health` 确认是 rule/table 缺失，而不是运营商标签或服务状态问题。
2. 用 `egress backend ID` 查看 `management`、持久化文件和所有权哈希。
3. `external`：保留只读，修复管理员原有 Netplan/networkd 文件后再次 verify。
4. `relayaxis + netplan/networkd`：定时器会在配置仍存在且哈希一致时执行 generate/reload 与该接口的 `networkctl reconfigure`；也可运行 `sudo ra egress reconcile`。它不会重启全部 networkd、刷新 main 或清空所有 rule。
5. 恢复后同时核对期望接口、网关、表和 Realm 目标端口的实际查找，再运行 `sync reconcile`。

若受管文件丢失或内容哈希漂移，自动恢复停止并报告。先从 `network-*.json` 快照或完整备份审计差异，再生成新的 plan；不要直接覆盖现场。

## 自建路由和隧道变更

外部 PBR 从不被修改。自建 PBR 只能使用独占的数字表和 source rule；不能把系统表 253/254/255 或 main 用于自建出口。Netplan 配置只声明该表的 default 和 routing-policy；基础文件继续拥有接口地址、连接网段、IPv6、DNS 和默认出口。

所有首次应用和删除都需要 diff/plan-id。应用前记录 main 与 SSH 管理对端路由，并启动独立回滚计时器；应用后逐项核验。修改自建 PBR、WG Endpoint/MTU/端口前先评估关联规则；这些操作会影响使用该资源的业务。规则增删不需要修改这些资源。接口或对端地址变更需明确重新配对，不在 update 中偷换密钥。重配仍保留本机私钥。

旧 oneshot 迁移期间不要手工 `systemctl stop`：其 ExecStop 可能删除已由原生后端建立的同名 rule/table。使用 `egress migrate` 的审计与分阶段流程：先提交原生后端，再重建 Realm 单元并确认反向依赖已经清零，最后只 disable 旧单元并保留文件。若结果为 `PENDING_SYNC` 或 `REALM_RECONCILE_REQUIRED`，保留旧 unit 的启用状态，处理列出的依赖后运行 `sync reconcile` 与 `recovery repair`；整机重启验证后再归档旧文件。

## 卸载与原生网络片段

普通卸载删除程序链接及 RelayAxis systemd 单元，保留 `/etc/relayaxis`、`/var/lib/relayaxis` 和已提交的 Netplan/networkd 片段；因此当前 PBR 不会因卸载程序而突然消失，之后重装仍可恢复所有权记录。`--purge --confirm-purge` 会删除数据库，执行前必须逐个用 `ra egress delete ID` 取得删除 diff，再用同一 `plan-id` 确认撤销原生片段。仍有 `persistence:*` 所有权或未完成 PBR 迁移日志时，完全清理会停止在删除配置数据之前。外部网络文件始终保留。

## Mimic

默认不安装、不启用。Debian 可运行 `ra mimic install` 安装发行版包；不会升级内核或修改 offload。兼容性检查涉及内核版本、BTF、BPF 功能、模块、DKMS 和网卡/XDP；最后以 upstream `mimic run --check` 和实际服务健康检查为准。

两端分别配置与启停，保留独立控制台：

```bash
# Controller：匹配远端 Ingress 公网地址和 WG 监听端口
sudo ra mimic configure front-a --interface eth0 \
    --public-address 198.51.100.20 --udp-port 51820 --xdp-mode skb
# Ingress：匹配本机公网地址和同一端口
sudo ra mimic configure front-a --interface eth0 \
    --public-address 198.51.100.20 --udp-port 51820 --xdp-mode skb
sudo ra mimic check --interface eth0
sudo ra mimic enable front-a
```

需要远程核验时，Ingress 的 `agent configure` 添加 `--allow-mimic`，只允许读取/启停已在本端预配置的该隧道 Mimic 服务。Controller `ra mimic verify front-a` 使用受限 SSH 查询实际远端版本和启用状态。状态不一致、版本或模式不一致时返回错误。通过唯一 WG 链路自动双端切换未实现；本端启用结果始终 `verified_pair: false`。

故障时从独立控制台两端 `ra mimic disable front-a`，然后检查原生 WG 握手；不会自动重置其他网卡的 XDP 程序。

## ECMP 与 UDP

```bash
sudo ra diagnose ecmp 192.0.2.80 443 --egress line-cn2 \
    --count 20 --interval 0.2 --timeout 3
sudo ra diagnose udp 192.0.2.80 5203 --egress line-cn2
```

每次 TCP flow 新分配源端口，绑定所选源地址和网卡，再验证含 sport/dport 的有效路由。优先读取 Linux TCP_INFO `tcpi_min_rtt`，不支持时使用握手耗时；报告有效/失败样本与 min/median/max/标准差。RTT 分组也可能是拥塞或对端负载，不能由此宣布检测到 ECMP。

UDP 诊断向支持响应的目标发送数据，区分响应、明确套接字错误和没有响应的 `INCONCLUSIVE`。不要对任意不响应载荷的 UDP 服务将超时判为丢包率。
