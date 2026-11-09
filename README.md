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

## 文档

- [`GLOSSARY.md`](GLOSSARY.md) — 术语表，读代码前先读这个
- [`docs/spec/v1.md`](docs/spec/v1.md) — v1 规格：协议、数据面、客户端、验收标准
- [`docs/adr/`](docs/adr/) — 架构决策记录

## 已知限制

- 任一侧是 hard NAT（对称 NAT / CGNAT / 移动网络）时打洞基本失败，只能走中继。
- DERP 兼容中继是 TCP-over-TCP，单流吞吐有天花板，只能当退路。
- iOS 客户端只走 TestFlight（App Store 审核指南 5.4 要求 VPN 类应用由 organization 账号提供）。

## 许可证

[MIT](LICENSE)
