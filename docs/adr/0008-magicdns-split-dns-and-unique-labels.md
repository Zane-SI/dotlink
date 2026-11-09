# 8. MagicDNS 用 split-DNS，名字来自 hostname 且必须唯一

## 背景

三端都要能用 `mac-mini.dotlink` 而不是 `100.64.0.1`。可选做法：改全局 DNS（`/etc/resolv.conf`、Windows 网卡 DNS）、在每个端口上拦截、或者让系统把某个后缀交给指定解析器。

## 决定

1. **只接管一个后缀**：macOS 写 `/etc/resolver/dotlink`，Windows 用 NRPT，iOS 用 `NEDNSSettings`。查询发往 Agent 自己 Overlay IP 上的 `:53`。
2. **解析器监听在本机 Overlay IP 上**，因此查询不进 TUN、不经过任何 peer，也不会漏给系统 DNS。
3. **名字由 hostname 推出**（转小写、截到第一个点、非法字符折成 `-`），Peer Map 同时下发 `hostname` 与派生出的 `dns_name`。
4. **重名在 Enrollment 时直接拒绝**（409），不自动加后缀；被 Revoke 的 Node 释放名字。

## 理由

- 全局改 DNS 会在隧道断掉时把整台机器的解析一起带走。只接管一个后缀，隧道挂了最多是 `.dotlink` 不通，`example.com` 照常。
- 让名字可推导意味着不需要「给设备起名」这一步，也不会有两块真值（hostname 与 DNS 名）互相漂移。
- 拒绝重名而不是加后缀：`mac-mini-2` 不会告诉用户哪台是刚扫码的那台，而他们正是要靠这个名字区分两台同名机器。Revoke 释放名字则保证重装不必改名。
- 不存在的名字回 NXDOMAIN：这是「立刻失败」与「等 30 秒超时」的区别，也是 §7.4 验收里「立即」的含义。区域外回 REFUSED，因为我们没有资格对别人的域名下结论。

## 代价

- 每个平台各一套规则；Windows 与 iOS 的规则还没有代码（各自票里做）。
- 重名在家庭网络里很常见（两台 `MacBook-Pro`），用户会遇到一次 409 并需要显式 `--hostname`。这是有意的：静默改名更难查。
- `dotlink` 不是 ICANN 的 TLD，将来真注册了会冲突。v1 接受这个风险，名字里带 `.local` 之类的后缀同样有主。
