# RelayAxis

基于 **Realm + WireGuard** 的 Linux 多入口、多 IPv4 出口中转管理工具。版本 **0.1.0**，MIT 许可，Python 标准库实现，简体中文终端菜单，全局命令 `ra`。

项目处于首版验证阶段。已实现管理与执行代码；实际通过和跳过的测试、需要服务器验证的项目见 [验证记录](docs/validation.md)。不要将离线编排测试视为公网组网验收。

## 能力与边界

- **Ingress** 决定客户端从哪些 IPv6 地址、哪些 IPv4 前置机进入；一条逻辑规则可以有多个入口和不同公网端口。
- **Transport** 使用每台前置机独立的 WG 隧道。NAT 侧 Controller 主动连接公网 Ingress，默认保活 25 秒。只安装 peer `/32` 路由，不导入全局默认路由。
- **Egress** 指定到最终落地的 IPv4 源地址、接口、网关和路由表。应用前同时核对普通源地址路由与绑定接口的路由。域名在应用时解析并固定为 IPv4。
- 完整规则增删改查、启停、复制、搜索、批量操作、版本历史、单条回滚、映射表、规则导入导出。
- 每个监听端点一个 Realm 进程和 systemd 单元。更改单条规则只操作该规则所属单元；两层 Realm 均支持 TCP、UDP 和 TCP+UDP。
- SQLite 保存期望配置、运行版本和历史；文件原子替换、进程锁、应用前备份、持久恢复日志、失败补偿。
- Controller 通过 **SSH over WG** 下发完整专属快照。Ingress 限定可用监听地址、端口范围、WG 目标、网卡和固定启动依赖；只返回实际应用版本。
- 只读发现外部 Realm、源地址 PBR、IPv6 地址与现有 DDNS 服务。导入默认禁用并保留外部服务，显式受控迁移另有命令。
- 自建 PBR 使用独立路由表和 `proto 186`；外部 PBR 只读复用。
- 网络诊断、源地址 TCP/UDP 探测、TCP minRTT 采样、服务日志、Mimic 本端可选管理及双端状态核验。

**不会管理防火墙、修改 SSH 全局配置、替换内核、调整 TCP 参数、重写系统默认路由或接管官方 IPv6/DDNS。** 需要的业务端口和 WG/SSH 可达性由管理员现有网络策略保证。

## 安装

首版支持使用 systemd 的 Debian 13，以及具备 Python 3.11+ 和依赖的 Linux。自动安装依赖使用 apt；其他发行版自行准备依赖后使用 `--skip-deps`。Windows 用于开发和纯逻辑测试。

```bash
git clone https://github.com/ike-sh/RelayAxis.git
cd RelayAxis
sudo bash install.sh --role controller --node-id controller-1
# 前置机：
sudo bash install.sh --role ingress --node-id front-a
sudo ra
```

无参数运行安装器会选择角色、检查现有安装或升级。已安装节点重复运行不会重置数据库、密钥或角色。Realm 优先复用已有可执行文件；缺失时安装到 `/opt/relayaxis/bin/realm`，固定版本及 SHA-256 校验值保存在 `relayaxis/fetch_realm.py`。不会替换已有手动 Realm。

```bash
sudo bash install.sh --role controller --realm-binary /usr/local/bin/realm
sudo ra verify-install --json
sudo ra doctor --json
```

程序位于 `/opt/relayaxis/releases/`，`current` 链接切换程序版本；配置 `/etc/relayaxis/`，数据库及备份 `/var/lib/relayaxis/`。需要 root 读取受保护状态或应用系统配置。

## 首次部署

详细可执行步骤见 [Controller / Ingress 部署](docs/deployment.md)，示例 JSON 见 [examples](examples)。**示例使用文档专用地址，必须替换成本机参数。**

1. Controller 运行 `ra egress discover`，将所需出口保存为命名记录。已有表 108、优先级 18080、`ipv4-eth1-pbr.service` 可以按实际参数复用，`managed` 设置为 `false`。
2. 两端分别 `ra wg create --file ...`，各自产生本机私钥；互换 `wg export` 的公开配对包，分别 `wg pair` 和 `wg apply`。
3. Ingress 配置 `agent configure` 授权范围，在现有 `authorized_keys` 中追加生成的受限同步密钥授权行。
4. Controller 核验 SSH 主机指纹，将前置机记录中的专用私钥路径、known_hosts、隧道 ID 配置正确。
5. 添加规则后 `ra rules apply ID`，或添加时使用 `--apply`。Controller 定时器每分钟重试待同步规则，并校验活动规则的出口与服务状态。

仅使用 IPv6 直连时，可以跳过 WG、前置机与 SSH 配对步骤。

## CLI

```bash
sudo ra status --json
sudo ra egress discover
sudo ra egress add --file examples/egress-main.json
sudo ra egress check line-main 192.0.2.80 443 --protocol both
sudo ra ipv6 list
sudo ra realm scan                         # 只读，不停止任何现有服务
sudo ra realm import --service realm-old.service --egress line-main
sudo ra rules list --search 日本
sudo ra rules add --file examples/rule-direct.json
sudo ra rules apply RULE_ID
sudo ra rules update RULE_ID --file patch.json --apply
sudo ra rules disable RULE_ID --apply
sudo ra rules rollback RULE_ID 1 --apply
sudo ra rules batch disable ID1 ID2 --apply
sudo ra rules delete RULE_ID --apply
sudo ra wg list
sudo ra ingress list
sudo ra sync status
sudo ra sync reconcile
sudo ra backup create
sudo ra recovery status
sudo ra version
```

`add/update/delete/enable/disable` 不带 `--apply` 时只保存期望配置，显示 `PENDING_SYNC`；安装的 Controller 定时器会自动收敛。要集中暂存多项编辑，请先 `systemctl stop relayaxis-reconcile.timer`，审阅后手动应用并重启定时器。

每个命令支持 `--help`；`--json` 可以放在命令前后。退出码：`0` 操作完成/期望配置已保存，`2` 输入或环境错误，`3` 应用失败、待同步或检查不通过，`130` 取消。JSON 字段名保持稳定，界面提示为中文。

```bash
# 不修改宿主机网络/systemd 的隔离配置目录：
python3 -m relayaxis --root /tmp/relayaxis-dev init --role controller --node-id dev
python3 -m relayaxis --root /tmp/relayaxis-dev rules list --json
```

## 升级、恢复与卸载

```bash
git pull --ff-only
sudo bash install.sh --upgrade --role controller
# 或指向已审阅的本地源码：
sudo ra update --source /path/to/RelayAxis

sudo ra backup create --file /root/relayaxis-before-change.tar.gz
sudo ra backup inspect /root/relayaxis-before-change.tar.gz
sudo ra backup restore /root/relayaxis-before-change.tar.gz --confirm-restore
# 恢复保存为新的期望版本；核对出口、WG 后再运行 sync reconcile。

sudo bash uninstall.sh                      # 删除本工具及自己的服务，保留配置数据
sudo bash uninstall.sh --purge --confirm-purge
```

卸载按登记清单操作，不按 `realm*`、`wg*` 等宽泛匹配删除。外部 Realm、PBR、官方 IPv6 管理器和既有 DDNS 服务均保留。备份包含本机私钥，文件为 0600，需通过管理员现有的加密备份方式异地保存。

## 开发与测试

```bash
python3 -m unittest discover -v
python3 -m venv .venv
.venv/bin/pip install ruff build
.venv/bin/ruff check relayaxis tests
.venv/bin/ruff format --check relayaxis tests
shellcheck install.sh uninstall.sh

# 固定校验的 Realm，可放在临时目录，不安装系统服务：
python3 -m relayaxis.fetch_realm /tmp/realm
RELAYAXIS_REALM=/tmp/realm python3 -m unittest discover -v
# 隔离 network namespace + 真实 WireGuard/PBR 测试：
sudo env RELAYAXIS_NETNS=1 RELAYAXIS_REALM=/tmp/realm \
    python3 -m unittest tests.integration.test_netns -v
```

实际网络用例会明确跳过缺失的 Realm、root、namespace 或 WG 内核条件。测试使用隔离目录和专用 namespace，不部署生产服务器。CI 覆盖跨平台纯逻辑、真实 Realm 数据流与 Linux 特权集成测试。

## 首版限制

- 已在 CI 通过原生 WG 与双 PBR namespace 数据流测试；尚未完成干净 Debian 13 实机安装、重启、跨公网 NAT 或双端 Mimic 验收；见 [验证记录](docs/validation.md)。
- 分布式应用没有全局原子提交。前置机失败时保留本机旧/新内部监听，其他前置机与 IPv6 可继续运行，状态显示部分成功。全部确认后才清理旧监听。
- 每条被修改规则可能短暂中断自己的现有连接；不承诺无损重载或迁移既有 TCP/UDP 会话。
- 每个物理网卡首版只管理一个 Mimic 实例；通过两端独立控制台启停，再用 `mimic verify` 核验。不经唯一 WG 管理链路盲目自动切换。
- AAAA 检查使用系统 DNS 查询；不写 Cloudflare API、不安装新的 DDNS 定时器。ECMP 仅采样，RTT 波动不等于 ECMP。
- 最终落地仅支持 IPv4；系统防火墙、物理网络和管理员外部服务仍需独立维护。

技术设计：[架构与事务](docs/architecture.md) · [恢复与运维](docs/operations.md) · [参考资料核对](docs/references.md) · [后续工作](docs/roadmap.md)。

English: RelayAxis orchestrates Realm forwarding and host-only WireGuard transports. Ingress, transport and IPv4 egress are independent. It uses per-endpoint systemd services, SQLite intent/history, crash journals and restricted SSH snapshot synchronization. See the validation report before production deployment.
