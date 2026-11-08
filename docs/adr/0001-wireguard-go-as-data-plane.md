# 数据面用 wireguard-go，不用内核 WireGuard 或 boringtun

三端（macOS / Windows / iOS）共用同一份 Go 数据面实现 `wireguard-go`，由 Agent 内嵌运行，而不是调用各平台的内核 WireGuard 模块。

## 为什么

1. **iOS 没得选。** iOS 上唯一受支持的隧道 API 是 `NEPacketTunnelProvider`，它只给你一个 TUN 文件描述符。内核 WireGuard 在 iOS 上根本不存在，必须跑 userspace 实现。既然 iOS 必须用 wireguard-go，桌面端也用同一份，行为才一致。
2. **打洞要求运行时换 Endpoint。** 内核 WireGuard 的 peer 配置改一次要重建接口或走 `wg set`，延迟在几十到几百毫秒，且切换期间丢包。wireguard-go 的 `device` 支持运行时 `SetPeerEndpoint`，我们能在 1ms 内把流量从 Relay 切到刚打通的 Direct Path。
3. **MIT + 纯 Go。** 不用 cgo，交叉编译到 darwin/arm64、windows/amd64、ios/arm64 都是单命令。iOS 侧用 gomobile 打成静态库，这正是 WireGuardKit 自己的做法。

## 代价

- 单流吞吐低于内核实现（用户态收发 + 内存拷贝）。实测同代硬件上约 1–2 Gbps，对「访问家里 NAS」这个场景绰绰有余。
- 电池与 CPU 占用比内核版高，移动端要限制 keepalive 频率。

## 考虑过但没选

- **boringtun**（Rust）：iOS 要 Rust 工具链 + FFI 桥接，三端构建链复杂度翻倍，且它的 `Device` 抽象没有运行时改 endpoint 的一等支持。
- **内核 WireGuard**：macOS 没有官方内核实现，Windows 需要驱动签名，iOS 不可用。三端三套实现，最坏的选择。
