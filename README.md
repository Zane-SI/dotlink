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

设计阶段。规格与决策已定，代码还没开始写。

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
