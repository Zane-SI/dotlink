# Dotlink

自托管的 overlay 网络：把分散在不同网络里的设备放进同一个虚拟网段，让它们像在同一个局域网里一样互相访问。没有账号，没有第三方托管，控制面由使用者自己部署。

## Language

### 网络与设备

**Overlay**：
叠加在真实网络之上的一层虚拟网络。Node 之间用 Overlay IP 互访，真实网络只负责承载。
_Avoid_：内网、VPN 网络

**Network**：
一个 Control Plane 所管理的全部 Node 的集合。v1 里一个 Control Plane 只有一个 Network，Network 内所有 Node 默认互通。
_Avoid_：tailnet、虚拟局域网、集群

**Node**：
加入了 Network 的一台设备。一个 Node 有且只有一对密钥和一个 Overlay IP。
_Avoid_：设备、peer、成员

**Gateway**：
在 Network 里同时承担 Subnet Router 角色的 Node，通常是一台常年开机的机器。
_Avoid_：服务端、server、主节点、中心

**Subnet Router**：
把一个真实局域网（例如家里的 `192.168.1.0/24`）通告进 Network 的 Node。其他 Node 访问该网段时，流量经它转发。
_Avoid_：路由器、bridge

**Exit Node**：
接管全部出网流量的 Node。v1 不做。
_Avoid_：全局代理

**Overlay IP**：
Control Plane 分配给 Node 的虚拟地址。v1 同时分配一个 `100.64.0.0/10` 内的 IPv4 和一个 `fd00::/8` 内的 IPv6。
_Avoid_：虚拟 IP、内网 IP、tunnel IP

### 路径

**Direct Path**：
两个 Node 之间不经第三方转发的点对点路径。
_Avoid_：P2P、直连

**Relayed Path**：
流量经 Relay 转发的路径。
_Avoid_：中转、代理路径

**Hole Punching**：
让两个位于 NAT 之后的 Node 同时向对方发起连接，从而在各自的 NAT 上开出通路的过程。
_Avoid_：穿透、NAT 穿透

**Candidate**：
一个 Node 声称自己可能被访问到的地址（`IP:port`）。Candidate 分公网与局域网两类，由 Control Plane 下发给对端。
_Avoid_：地址列表、endpoint

**Endpoint**：
一对 Node 之间最终实际使用的那个 Candidate。Hole Punching 成功前，Endpoint 指向 Relay。
_Avoid_：候选、地址

**STUN**：
用来发现自己在 NAT 后面的公网映射地址的协议。Dotlink 自建 STUN 服务，不使用公共实例。
_Avoid_：—

**Relay**：
只转发加密报文、不持有密钥、读不懂内容的服务器。
_Avoid_：服务器、中继节点、proxy、跳板

**Backend**：
Relay 的一种具体实现。v1 有两个：自有 UDP Relay 与 DERP 兼容 Relay。
_Avoid_：协议、驱动

### 控制面

**Control Plane**：
签发 Invite、登记 Node、下发 Peer Map 的那部分服务。它不在数据路径上——Control Plane 挂掉后，已建立的 Direct Path 与 Relayed Path 仍然可用。
_Avoid_：服务端、后端、master

**Peer Map**：
Control Plane 下发给每个 Node 的全网视图：每个 Node 的公钥、Overlay IP、Candidate、在线状态，以及 Subnet Router 通告的网段。
_Avoid_：配置、路由表、节点列表

**Invite**：
一张一次性的入网凭证，编码成二维码，24 小时内有效，兑换一次即作废。Invite 里不含任何私钥。
_Avoid_：邀请码、token、key

**Enrollment**：
Node 用 Invite 换取自己身份的过程：生成密钥对、把公钥交给 Control Plane、领到 Overlay IP 与 Peer Map。
_Avoid_：注册、登录、绑定

**Revoke**：
让一个 Node 永久失去 Network 访问权。被 Revoke 的 Node 会从所有 Peer Map 里消失。
_Avoid_：删除、踢出

### 客户端

**Agent**：
跑在 Node 上的无界面后台进程，负责隧道、Hole Punching、与 Control Plane 通信。
_Avoid_：客户端、daemon、service

**Client**：
用户看得见的那层界面：菜单栏、托盘、iOS App。Client 通过本地 socket 指挥 Agent。
_Avoid_：App、UI

**MagicDNS**：
用名字而不是 Overlay IP 访问 Node 的能力。v1 使用 `.dotlink` 这个伪 TLD。
_Avoid_：内网 DNS、域名解析
