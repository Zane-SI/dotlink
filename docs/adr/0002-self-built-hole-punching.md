# 打洞自己实现，不引入 pion/ice 或 Tailscale disco

Hole Punching 用自建 STUN + 双端同时发包 + 运行时切换 Endpoint 实现，走我们自己的信令通道，不依赖 ICE 的 SDP 协商，也不兼容 Tailscale 的 disco 协议。

## 为什么

1. **信令通道必须是我们的。** ICE 的候选交换是绑在 SDP 上的：要么把 SDP 塞进 Peer Map（协议变丑），要么跑一套 SIP/WHIP 式的外部信令。我们已经有 Control Plane 在给两端发 Peer Map，Candidate 直接跟着 Peer Map 走，零额外通道。
2. **两节点的场景用不上 ICE 的完整状态机。** ICE 的 checklist、优先级排序、role conflict、trickle 是为「多候选、多流、浏览器」设计的。我们的场景是 N 个 Node 两两配对，候选通常 2–4 个，一段 200 行的探测循环就够。
3. **Tailscale disco 不兼容也兼容不了。** 它是未文档化的私有协议，跟 Tailscale 的 node key、DERP 鉴权、控制协议耦合。想复用它就得实现整个 TS 协议栈——那就是 headscale 的活。

## 做法要点

同一个 UDP socket 同时承载 WireGuard 与探测包，按包头魔数分流：探测包走自己的 Ping/Pong（带发送方公钥与 tx id），WireGuard 包原样交给 `device`。打通后把 `device` 的该 peer endpoint 指向打通的地址。两端同时向对方全部 Candidate 发包，谁先收到 Pong 用谁。

## 代价

- NAT 类型探测、端口预测、保活全要自己写，还要自己处理「打洞成功后公网映射变了」的漂移。
- 对称 NAT / CGNAT / 移动网络下打洞大概率失败，只能走 Relay。这是物理限制，不是实现缺陷；Control Plane 要如实把「当前是 Relayed Path」暴露给 Client，而不是假装在打洞。
