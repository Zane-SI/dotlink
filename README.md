# Dotlink

自托管的 overlay 网络。把分散在不同网络里的设备放进同一个虚拟网段，扫码入网，能打洞就走直连，打不通就走自己的中继。

```
mac-mini (家里)  ←── 直连 / 中继 ──→  MacBook (外地)
      │                                    │
   192.168.1.0/24                     iPhone (4G)
```

- **自己部署**：Control Plane + Relay 是一个二进制，配一份 `docker-compose.yml` 就能跑。
- **扫码入网**：一次性二维码，24 小时有效，里面不含任何私钥。
- **没有账号**：没有第三方托管，没有遥测，抓包就能证明。
- **MIT**。

## 状态

`v1` 的数据面已经跑通：Node 入网、Peer Map 长轮询、UDP Relay、打洞与直连切换、DERP 兼容退路、macOS 菜单栏客户端。Windows 与 iOS 客户端、MagicDNS、TLS 还没做——见 [issues](https://github.com/Zane-SI/dotlink/issues) 里的依赖图。

## 试一下

```sh
make build                # 三个二进制，全部 CGO_ENABLED=0

# 一台机器当 Control Plane（下面说到的“Gateway”）
./bin/dotlink-server control -db dotlink.db -public-url http://<公网 IP>:8080 &
./bin/dotlink-server relay -db dotlink.db -udp :3478 &

# 签一张邀请，装到第二台机器上
./bin/dotlink-server invite --server http://127.0.0.1:8080 --admin-token <启动时打印的 token>
sudo ./bin/dotlink-agent join 'dotlink://enroll?...'

# 两台机器各起一个 Agent，然后 `dotlink-agent nodes` 看路径
sudo ./bin/dotlink-agent up
```

菜单栏客户端：`/Applications/Dotlink.app`（`sudo packaging/macos/install.sh` 安装），生成二维码、看直连/中继、断开与重连。

## Subnet Router（Gateway）

默认 Agent 只把自己放进 Overlay。要让别的 Node 访问这台机器所在的局域网，启动时用 `--advertise-routes`（打包版也可以写配置文件）：

```sh
sudo ./bin/dotlink-agent up --advertise-routes=192.168.1.0/24
```

launchd 没有 shell，不能把 flag 拼进启动命令，因此打包版从 `/usr/local/etc/dotlink/advertise-routes` 读取前缀。安装时传入：

```sh
ADVERTISE_ROUTES=192.168.1.0/24 ./packaging/macos/install.sh
```

也可以之后编辑该文件（逗号或换行分隔，`#` 开头是注释），再执行 `sudo launchctl kickstart -k system/com.dotlink.agent`。文件不存在就是普通 Node；`--advertise-routes` 仍然优先于文件，前台运行不受影响。安装脚本只会在传入 `ADVERTISE_ROUTES` 时写这个文件，重装不会清掉已有配置。

通告被拒绝时（例如与别的 Gateway 的 409 冲突），Agent 会报错并保持停止，而不是每两秒重试；解决冲突后重新连接即可。同样的策略也用于本机没有到 advertised LAN 的路由：明确报错并停止，避免把 peer 的流量引向黑洞，而不是静默降级成普通 Node。

Subnet Router 在 macOS 上用 pf，在 Linux 上用 `iproute2` + `iptables`/`ip6tables`（需要 root；只装了 nft 而没有 iptables 的环境会明确报错）。Linux 的安装包尚未提供，按源码构建后用 `sudo ./bin/dotlink-agent up --advertise-routes=...` 即可。Windows 及其他平台带 `--advertise-routes` 启动时仍会报 “not implemented”。

## 文档

- [`GLOSSARY.md`](GLOSSARY.md) — 术语表，读代码前先读这个
- [`docs/spec/v1.md`](docs/spec/v1.md) — v1 规格：协议、数据面、客户端、验收标准
- [`docs/adr/`](docs/adr/) — 架构决策记录

## 已知限制

- 任一侧是 hard NAT（对称 NAT / CGNAT / 移动网络）时打洞基本失败，只能走中继。
- DERP 兼容中继是 TCP-over-TCP，单流吞吐有天花板，只能当退路。
- iOS 客户端只走 TestFlight（App Store 审核指南 5.4 要求 VPN 类应用由 organization 账号提供）。
- Subnet Router 的 Windows 版本尚未实现；Linux 版本依赖 `iptables`/`ip6tables`，在只提供 nft 的环境里需要先装兼容层。

## 许可证

[MIT](LICENSE)
