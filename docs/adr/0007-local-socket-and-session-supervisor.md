# 本地控制在 Unix socket 上，断开会话而不是停进程

Client 与 Agent 之间是 `/var/run/dotlink.sock`（`root:admin 0660`）上的四个 HTTP 端点：`GET /status`、`POST /invite`、`POST /disconnect`、`POST /connect`。Agent 进程被 launchd 的 `KeepAlive` 看着，但隧道是一个可以被独立停掉的**会话**。

## 为什么是 socket 而不是端口

对面那个进程能打开 `utun`、改写路由、把整台机器的流量搬走。把这种能力交给「本机任意进程」已经过宽，交给局域网更是灾难。Unix socket 的权限就是进程的权限：`0600` 给 root，`0660 root:admin` 给能装 launch daemon 的那个组。加一个 TCP 端口只会多一件要防的事。

## 为什么断开是停会话

如果「断开」直接让进程退出，`KeepAlive` 会在几秒内把它拉回来——按钮点了没效果，是比没有按钮更糟的谎话。反过来，如果会话崩溃不重启，一个 bug 就能让机器整晚离线。所以把两者分开：`Supervisor.Stop()` 取消会话并**等** TUN 与路由真正消失才返回；`Supervisor.Serve()` 只在会话「自己失败」时重启，用户主动断开的不碰。

## 代价

- 两个生命周期要同时想清楚：进程（launchd 管）与会话（Supervisor 管）。`status` 因此有两个失败模式要区分——进程不在，和进程在但隧道没起来。
- `disconnect` 会阻塞到清理完成（通常几百毫秒）。这是有意的：提前返回会让「已经没有 utun 了」这句话变成猜测。
- socket 文件会活过进程（崩溃、`SIGKILL`），所以启动时先删陈旧文件，否则永远 `address already in use`。
