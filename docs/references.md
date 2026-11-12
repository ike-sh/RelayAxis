# 上游核对与实现来源

2026-11-12 开发时只参考设计和公开接口，未复制参考项目的实现或目录。

| 来源 | 核对事项 |
| --- | --- |
| [Realm upstream](https://github.com/zhboner/realm) | TOML、network.no_tcp/use_udp/ipv6_only、through/interface、IPv4 DNS；固定 v2.9.6 Linux musl 包并校验 GitHub asset SHA-256 |
| [WireGuard Quick Start](https://www.wireguard.com/quickstart/) | 两端分别产生密钥、peer AllowedIPs、Endpoint、PersistentKeepalive |
| [mimic upstream](https://github.com/hack3ric/mimic) | mimic run --file / --check、local/remote filter、XDP 模式、内核与模块依赖；作为外部程序调用，其许可证独立于本项目 |
| [wg-mimic-fabric](https://github.com/ike-sh/wg-mimic-fabric) | 双端角色、NAT 主动连接、多业务共享隧道、可选增强 |
| [liqun-route](https://github.com/ccqwertyui/liqun-route) | 多出口及端口策略可能影响实际路由；必须查询内核选择 |
| [gost-ecmp-pathlock](https://github.com/zcp1997/gost-ecmp-pathlock) | 多 TCP flow 的 minRTT 采样思路；未安装 GOST/MTCP 或实现 PathLock |
| [ip-route(8)](https://man7.org/linux/man-pages/man8/ip-route.8.html) | route get from / oif / ipproto / sport / dport 参数 |

官方脚本 `https://files.leikwanhost.com/dual-route.sh`、`https://files.leikwanhost.com/v6-mng.sh` 在当前环境访问出现 TLS EOF，未取得可核验内容。RelayAxis 不执行这两个脚本，也不假定它们的文件接口固定。兼容性通过 `ip -j` 实际状态、systemd 只读发现和用户提供的服务依赖实现。
