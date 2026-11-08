# Control Plane 自己写，不 fork Headscale 也不部署 NetBird

Control Plane 是一个新的最小实现：设备登记、Invite 签发/兑换/Revoke、Peer Map 下发、ACL 编译，全部走我们自己的 HTTP+JSON 协议。

## 为什么

1. **需求形状不一样。** 我们要的是：一次性二维码、单 Network、无账号、自研打洞信令。Headscale 的形状是：多用户、多 tailnet、完整兼容 Tailscale 控制协议（因为它必须喂饱官方客户端）。为了我们的五个 API 去改造并长期跟随上游，成本估在 2–4 人月，还背上了「上游改协议我们跟着改」的长期债。
2. **许可证。** NetBird 的 management/signal/relay 是 AGPLv3。Dotlink 是 MIT，直接部署或改造 AGPL 组件会把整个分发模型拖进 AGPL 的传染范围。
3. **协议是我们唯一的护城河。** 打洞信令、Relay 寻址、Invite 兑换都长在 Control Plane 的协议上。协议是自己的，客户端才能薄；协议是别人的，客户端就得跟着别人的演进走。

## 代价

- ACL 编译、密钥轮换、Peer Map 的增量下发、在线状态判定，这些 Headscale 已经踩过的坑我们要重新踩一遍。
- 没有现成客户端能用（这正是「现成 iOS App」那条路走不通的原因，见 0005）。
