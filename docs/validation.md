# v0.1.1 验证记录

开发日期：2026-11-23（Asia/Shanghai）。开发和故障注入仅在 `D:\code\RelayAxis`、临时目录及随机命名的 WSL network namespace 中进行；没有连接题述生产服务器，也没有重启开发宿主机网络服务。

## 自动验证范围

| 检查 | v0.1.1 结果 |
|---|---|
| Windows 纯逻辑/编排回归 | **已执行通过**：`Ran 113 tests`，`OK (skipped=9)`；跳过项均为 Linux 特权集成、POSIX 权限或 Bash 安装器，随后由 WSL 全门禁补齐 |
| WSL Linux 全量回归 | **已执行通过**：root 下同时设置 Realm、netns、Netplan、networkd 环境变量，`Ran 119 tests`，`OK`，零失败、零错误、零跳过 |
| 原有功能 | WSL 全量覆盖 Realm TCP/UDP、IPv6 直连、原生 WG、双出口数据流、多前置机、同步/回滚/双端失败恢复、外部 Realm 导入及安装/卸载测试 |
| 默认出口发现 | 覆盖 9929 默认、CN2 默认、普通 BGP 默认、单出口、三出口、不规则接口、不同 metric、相同最低 metric 歧义、缺失 default、动态源地址和多 source-rule 优先级；测试名称只是场景标签，代码不识别运营商 |
| 事故回归 | 覆盖旧 oneshot 可视为 active、但 source rule 缺失及目标表为空；分别返回 `RULE_MISSING` / `ROUTE_MISSING`，不以服务状态或其他出口可达代替 |
| Netplan 逻辑测试 | 独立文件、cloud-init 基础文件原样保留、IPv4/IPv6/DNS/MAC match/其他 route 保留、`set-name` 定义映射、表/优先级冲突、外部文件保护、幂等和失败恢复 |
| 真实 Netplan generate | **已执行通过**：临时 root 中加载基础 YAML 与 RelayAxis 片段，真实运行 `netplan generate`；检查生成的 networkd 配置同时包含原地址/DNS/MAC/IPv6 route 和 table 108/rule 18080，第二次生成哈希一致 |
| 原生 networkd drop-in | **已执行通过**：基础 `.network` 放在隔离 `/run`，RelayAxis drop-in 放在隔离 `/etc`，验证跨搜索路径合并，不创建竞争 `.network` |
| networkd 重启恢复 | **已执行通过**：随机 netns 内启动真实 `systemd-networkd`，确认 rule 18080/table 108；停止进程、删除内核 rule/table、用同一持久化配置重启进程，再次确认 rule/default 和 `ip -j route get ... from SOURCE` 选择 eth1/table 108 |
| 旧 oneshot 迁移 | 覆盖直接 ip 与 v0.1.0 间接 ExecStart、ExecStop 审计、外部反向依赖阻断、plan-id、原生后端应用、Realm 依赖收敛后只 disable 不 stop、数据库兼容，以及“原生提交后进程中断”的恢复日志收敛 |
| 外部资源边界 | external 出口故障只报告；定向恢复仅在管理方式为 relayaxis、所有权记录存在、文件哈希一致时运行 |
| 卸载所有权 | 覆盖普通卸载保留原生片段；完全清理在仍有 native persistence 所有权时先停止，要求走出口删除 plan-id 流程 |
| Ruff / 格式 / ShellCheck / build | **已执行通过**：Windows Ruff check/format-check、WSL ShellCheck、Windows sdist/wheel build、`git diff --check` |

真实 networkd 测试通过 mount namespace 隔离 `/run/systemd/network`、`/run/systemd/netif`、`/etc/systemd/network`、vendor network 目录与 D-Bus 路径；物理 veth 和 network namespace 使用随机名称并在测试结束清理。测试没有调用宿主机 `systemctl restart systemd-networkd`。

真实 Realm 用例使用 v2.9.6 临时二进制 `/tmp/relayaxis-v011-realm`，SHA-256 为 `b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65`。该文件仅用于隔离测试，没有安装为宿主机服务。

## 复现

```bash
python3 -m unittest discover -v
ruff check relayaxis tests
ruff format --check relayaxis tests
shellcheck install.sh uninstall.sh
python3 -m build

# 固定 Realm + 原生 WG/双出口真实数据流（隔离 namespace）
sudo env RELAYAXIS_NETNS=1 RELAYAXIS_REALM=/tmp/relayaxis-realm \
  python3 -m unittest tests.integration.test_netns -v

# 真实 Netplan 生成与隔离 networkd 重启恢复
sudo env RELAYAXIS_NETPLAN=1 RELAYAXIS_NETWORKD_NETNS=1 \
  python3 -m unittest tests.integration.test_persistence_live -v

# 一次运行全部逻辑和特权集成测试，预期零 skip
sudo env RELAYAXIS_REALM=/tmp/relayaxis-v011-realm \
  RELAYAXIS_NETNS=1 RELAYAXIS_NETPLAN=1 RELAYAXIS_NETWORKD_NETNS=1 \
  python3 -m unittest discover -v
```

CI 的 `linux-network` job 明确设置上述环境变量，因此对应测试缺依赖时会报错，而不是把条件跳过记作持久化验证成功。普通 Windows/非特权矩阵仍会对只适用于 Linux 内核的测试显示明确 skip；Linux 特权 job 是其正式补充门禁。

## 未执行及边界

以下项目不由隔离测试结果代替：

- 题述生产环境或任何真实业务主机操作；
- 干净 Debian 13 KVM 的安装、升级、卸载和整机重启；
- 物理双/三运营商出口、动态网关变化和长时间链路稳定性；
- 真实 SSH 会话跨 `netplan apply` 的远端回滚演练；代码会建立独立 systemd 回滚计时器并比较 SSH 对端选路，但仍需在可失联的测试克隆机验收；
- 已有第三方 oneshot 的自动迁移。只有 v0.1.0 RelayAxis 所有权记录、预期 unit、可用原生后端和可收敛的 RelayAxis Realm 反向依赖同时匹配时才进入自动分阶段迁移，其他服务保持审计模式；
- 跨公网 NAT/SSH、干净系统开机时序、双端 Mimic/eBPF/XDP。

首次在 Debian 13 测试克隆机验收时，应按 [部署](deployment.md) 的 plan/apply 流程操作，并按 [运维](operations.md) 记录重启前后 `egress health`、`ip rule`、目标表和实际业务数据流。正式 Release 仍等待该实机验收。
