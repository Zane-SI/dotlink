# macOS 用 root launchd daemon，不用 Network Extension

macOS 客户端 = 一个 root 权限的 launchd daemon（打开 `utun`、跑 wireguard-go）+ 一个 MyGo 菜单栏 Client，两者通过本地 socket 通信。不申请 NetworkExtension、不做 system extension。

## 为什么

macOS 上自写 Network Extension 是全场最贵的一条路：`.appex` 只能通过 Mac App Store 分发，走 Developer ID 就必须打成 system extension，额外需要 `com.apple.developer.system-extension.install` entitlement、用户在系统设置里手动批准、以及公证。而 root daemon 打开 `utun` 完全不需要任何 entitlement —— `tailscaled`、`wg-quick`、Mullvad 都是这么干的。省下 3–4 周，换一个「安装时要输密码」。

## 代价

- 安装器必须请求 root（`osascript` 提权或 pkg installer），首次体验不如 NE 顺滑。
- daemon 的生命周期、崩溃重启、版本升级都要自己管（launchd 的 `KeepAlive` + 自更新时要协调重启）。
- 卸载要清理 `/Library/LaunchDaemons`，不能留下孤儿进程。

## 考虑过但没选

- **system extension**：体验最好，但 +3–4 周且要 Apple 侧 entitlement 审批。
- **用户态 TUN**：macOS 没有非 root 的 `utun` 替代，不成立。
