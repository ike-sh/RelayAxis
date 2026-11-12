# v0.1.0 验证记录

开发日期：2026-11-12（Asia/Shanghai）。环境为 Windows 本地仓库、WSL2 Linux 6.6、Python 3.12.3；普通用户，没有无密码 sudo。测试没有部署生产服务器，没有在宿主机安装服务或修改路由/防火墙。

## 自动验证

| 检查 | 结果 |
| --- | --- |
| 完整测试套件 | **81 项通过，0 失败，0 错误；本机另 1 组特权测试明确跳过**。完整运行耗时约 13 秒 |
| 真实 Realm 数据流 | 固定 v2.9.6、校验 SHA-256；IPv6→IPv4 TCP/UDP、双前置机两层转发、独立进程停止/恢复、同数字端口 TCP-only 与 UDP-only |
| 安装器隔离验证 | 重复安装、失败候选回退、卸载后重装、普通卸载和完全清理均保留外部 Realm/PBR/官方 IPv6 文件 |
| Ruff 静态检查 / 格式 | 通过 |
| ShellCheck | 通过 |
| sdist + wheel | 构建通过；构建物不提交 Git |
| 敏感信息扫描 | 未发现私钥块、字面 WG 私钥、GitHub Token、AWS Access Key；测试密钥为明确的合成数据 |
| 本机 namespace + 原生 WG + 双 PBR | **跳过：当前用户没有 root** |
| GitHub Linux 特权网络任务 | **实际通过，未跳过**：Controller + 两台 Ingress + 落地端、原生 WG、两条源地址出口、多 TCP/UDP 规则、IPv6 直连与故障隔离 |
| GitHub 跨平台矩阵 | Ubuntu / Windows，Python 3.11 / 3.13，四个任务均通过；不适用的真实 Linux/Realm 用例按条件跳过 |

测试覆盖 IP/端口/网段冲突、TOML、WG 配对与方向、端口预留、源地址路由及绑定接口查找、规则 CRUD/历史/回滚、单条服务隔离、离线和部分成功、旧入口持续撤销、WG 接口消失时其余入口保持、Agent 校验与重放、凭据边界、快照恢复、外部服务只读导入与失败迁移补偿、WG/Mimic 文件事务、受管 PBR 精确修复与回撤。

真实转发测试在 WSL 最初暴露出 `127.0.0.1` 经 `loopback0` 而不是 `lo` 的策略路由差异，已经按实际源地址选路选择测试网卡；运行时也同时检查无 oif 与指定 oif 的内核选择。完整测试曾出现随机端口碰撞，夹具已改为为 TCP/UDP 共同预留测试端口并避开普通客户端临时端口范围。

复现：

```bash
RELAYAXIS_REALM=/tmp/relayaxis-realm RELAYAXIS_NETNS=1 python3 -m unittest discover -v
ruff check relayaxis tests
ruff format --check relayaxis tests
shellcheck install.sh uninstall.sh
python3 -m build
```

## 需要真实 Linux 验证的项目

以下命令已在 GitHub Ubuntu runner 实际执行通过，也可在独立测试机复现（不要对生产宿主机执行故障注入）：

```bash
sudo env RELAYAXIS_NETNS=1 RELAYAXIS_REALM=/tmp/relayaxis-realm \
    python3 -m unittest tests.integration.test_netns -v
```

特权测试创建随机名称的四个 namespace，覆盖 Controller、两台 Ingress、落地端，两条原生 WG、两条源地址出口、多个 TCP/UDP 业务和 IPv6 直接入口，并清理所有测试进程与 namespace。它验证 WG 主动连接方向及监听端学习 Endpoint，不等价于真实公网 NAT 验收。无 namespace / WG 内核能力时会明确跳过。

仍需独立验证：干净 Debian 13 实机安装/升级/卸载、systemd 开机恢复、跨公网 NAT 与 SSH、已有日本/香港服务的实际迁移、双端 Mimic/eBPF/XDP、物理双出口及长时间连接稳定性。对应代码提交 `d5ed9ec` 的 [GitHub Actions](https://github.com/ike-sh/RelayAxis/actions/runs/43232274504) 五个任务全部通过：Linux 网络任务内 3 项真实 Realm 数据流用例及 1 项真实 namespace/WG/PBR 集成用例均实际执行成功。Windows 的 Bash/内核相关用例明确跳过。该证据不覆盖真实 Debian 13 systemd 安装或公网 NAT。

部署命令与人工验收流程见 [部署](deployment.md) 和 [运维](operations.md)。
