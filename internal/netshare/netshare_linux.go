//go:build linux

package netshare

import (
	"context"
	"fmt"

	"github.com/Zane-SI/dotlink/internal/netcfg"
)

const linuxComment = "dotlink-subnet-router"

// rule is one iptables/ip6tables rule. The comment makes the rule ours even
// after a crash: the next start recognises it, and cleanup removes it instead
// of leaving a NAT rule behind forever.
type rule struct {
	cmd    string
	table  string
	chain  string
	insert bool // FORWARD must go before a default DROP policy; NAT appends.
	match  []string
}

func (ru rule) checkArgs() []string {
	args := []string{"-w"}
	if ru.table != "" {
		args = append(args, "-t", ru.table)
	}
	args = append(args, "-C", ru.chain)
	return append(args, ru.match...)
}

func (ru rule) addArgs() []string {
	args := []string{"-w"}
	if ru.table != "" {
		args = append(args, "-t", ru.table)
	}
	if ru.insert {
		args = append(args, "-I", ru.chain, "1")
	} else {
		args = append(args, "-A", ru.chain)
	}
	return append(args, ru.match...)
}

func (ru rule) delArgs() []string {
	args := []string{"-w"}
	if ru.table != "" {
		args = append(args, "-t", ru.table)
	}
	args = append(args, "-D", ru.chain)
	return append(args, ru.match...)
}

// Enable turns a Linux Agent into a Gateway with iproute2 and iptables. It is
// deliberately conservative: if iptables is missing or a rule cannot be
// installed, it rolls back every rule it added and returns the error instead
// of advertising a LAN that would black-hole peer traffic.
func Enable(ctx context.Context, r netcfg.Runner, c Config) (func(), error) {
	if len(c.Routes) == 0 {
		return func() {}, nil
	}
	if c.TUN == "" {
		return nil, fmt.Errorf("subnet router needs a TUN interface")
	}
	ifaces := make([]string, 0, len(c.Routes))
	for _, pr := range c.Routes {
		if pr.Bits() == 0 {
			return nil, fmt.Errorf("%s is a default route; exit nodes are not in v1", pr)
		}
		iface, err := netcfg.RouteInterface(ctx, r, pr)
		if err != nil {
			return nil, err
		}
		if iface == "" {
			return nil, fmt.Errorf("no route to %s from this machine; run the Gateway on that LAN or add a static route first", pr)
		}
		if iface == c.TUN {
			return nil, fmt.Errorf("%s already routes into %s; forwarding it back into the tunnel would loop", pr, c.TUN)
		}
		ifaces = append(ifaces, iface)
	}
	ifaces = uniq(ifaces)

	sources := c.Sources
	if sources == nil {
		sources = DefaultSources()
	}
	v4, v6 := splitByFamily(sources)

	if len(v4) > 0 {
		if err := r.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return nil, fmt.Errorf("enable IPv4 forwarding: %w", err)
		}
	}
	if len(v6) > 0 {
		if err := r.Run(ctx, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
			return nil, fmt.Errorf("enable IPv6 forwarding: %w", err)
		}
	}

	var installed []rule
	rollback := func() {
		for i := len(installed) - 1; i >= 0; i-- {
			_ = r.Run(context.Background(), installed[i].cmd, installed[i].delArgs()...)
		}
	}
	add := func(ru rule) error {
		installed = append(installed, ru)
		if err := r.Run(ctx, ru.cmd, ru.checkArgs()...); err == nil {
			// Already present, normally from a previous run that crashed.
			// Keep it in installed so cleanup still removes our rule.
			return nil
		}
		if err := r.Run(ctx, ru.cmd, ru.addArgs()...); err != nil {
			return fmt.Errorf("install %s rule: %w", ru.cmd, err)
		}
		return nil
	}

	for _, iface := range ifaces {
		for _, src := range v4 {
			rules := []rule{
				{cmd: "iptables", table: "nat", chain: "POSTROUTING", match: []string{
					"-s", src.String(), "-o", iface, "-m", "comment", "--comment", linuxComment, "-j", "MASQUERADE"}},
				{cmd: "iptables", chain: "FORWARD", insert: true, match: []string{
					"-i", c.TUN, "-o", iface, "-m", "comment", "--comment", linuxComment, "-j", "ACCEPT"}},
				{cmd: "iptables", chain: "FORWARD", insert: true, match: []string{
					"-i", iface, "-o", c.TUN, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", linuxComment, "-j", "ACCEPT"}},
			}
			for _, ru := range rules {
				if err := add(ru); err != nil {
					rollback()
					return nil, err
				}
			}
		}
		for _, src := range v6 {
			rules := []rule{
				{cmd: "ip6tables", table: "nat", chain: "POSTROUTING", match: []string{
					"-s", src.String(), "-o", iface, "-m", "comment", "--comment", linuxComment, "-j", "MASQUERADE"}},
				{cmd: "ip6tables", chain: "FORWARD", insert: true, match: []string{
					"-i", c.TUN, "-o", iface, "-m", "comment", "--comment", linuxComment, "-j", "ACCEPT"}},
				{cmd: "ip6tables", chain: "FORWARD", insert: true, match: []string{
					"-i", iface, "-o", c.TUN, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", linuxComment, "-j", "ACCEPT"}},
			}
			for _, ru := range rules {
				if err := add(ru); err != nil {
					rollback()
					return nil, err
				}
			}
		}
	}

	return func() {
		for i := len(installed) - 1; i >= 0; i-- {
			_ = r.Run(context.Background(), installed[i].cmd, installed[i].delArgs()...)
		}
	}, nil
}
