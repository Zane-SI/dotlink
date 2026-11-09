// Command dotlink-bar is the macOS Client: a menu bar icon that shows the
// tunnel's state and can sign a QR code for a new device.
//
// It owns no network state of its own. Everything it draws comes from the
// Agent over /var/run/dotlink.sock, which is root:admin 0660 — the same
// group that can already install a launch daemon. Keeping the Client dumb is
// what makes "disconnect" honest: the interface really is gone, not just
// hidden from a menu.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/Zane-SI/dotlink/internal/ipc"
)

type bar struct {
	client *ipc.Client

	mu     sync.Mutex
	st     ipc.Status
	invite *ipc.Invite
	qr     ui.ImageSource
	halted string // why the last action failed, shown in the panel

	tray *mygo.Tray
	win  *mygo.Window
	last *inviteView
}

type inviteView struct {
	url     string
	expires time.Time
}

func main() {
	socket := flag.String("socket", ipc.DefaultSocket, "Unix socket the Agent listens on")
	flag.Parse()

	b := &bar{client: ipc.NewClient(*socket)}

	mygo.App.SetName("Dotlink")
	// Accessory: no Dock icon, no app menu. This is a menu bar resident.
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
	// Closing the panel must not quit: the tunnel is the point, the window
	// is only a view of it.
	mygo.App.OnWindowAllClosed(func() {})
	mygo.App.OnWillQuit(func(*mygo.QuitEvent) {
		if b.tray != nil {
			b.tray.Destroy()
		}
	})
	mygo.App.WhenReady(b.ready)
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

func (b *bar) ready() {
	tray, err := mygo.NewTray(mygo.TrayOptions{
		Icon:           trayIcon(),
		IconIsTemplate: true,
		ToolTip:        "Dotlink",
	})
	if err != nil {
		log.Fatal("tray: ", err)
	}
	b.tray = tray
	tray.SetMenu(b.menu())
	tray.OnClick(func() { b.togglePanel() })

	go b.poll()
}

// poll keeps the panel and the menu honest. Two seconds is short enough that
// a scan feels immediate and long enough not to wake the machine for nothing.
func (b *bar) poll() {
	ctx := context.Background()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	b.refresh(ctx)
	for range tick.C {
		b.refresh(ctx)
		b.tickCountdown()
	}
}

func (b *bar) refresh(ctx context.Context) {
	st, err := b.client.Status(ctx)
	mygo.RunOnMain(func() {
		b.mu.Lock()
		st.Peers = append(st.Peers[:0:0], st.Peers...)
		b.mu.Unlock()
		if err != nil {
			// The daemon is down or the socket is unreadable. Say so rather
			// than showing a stale "connected" that the user cannot act on.
			b.applyProblem(err.Error())
			return
		}
		b.apply(st)
	})
}

func (b *bar) applyProblem(msg string) {
	b.mu.Lock()
	b.st.Running = false
	b.halted = msg
	b.mu.Unlock()
	if b.tray != nil {
		b.tray.SetMenu(b.menu())
	}
	b.redraw()
}

func (b *bar) apply(st ipc.Status) {
	b.mu.Lock()
	b.st = st
	b.halted = st.Error
	if b.invite != nil && !st.Running {
		b.invite, b.qr = nil, nil
	}
	b.mu.Unlock()
	if b.tray != nil {
		b.tray.SetMenu(b.menu())
	}
	b.redraw()
}

func (b *bar) redraw() {
	if b.win != nil {
		b.win.Update(func() {})
	}
}

// tickCountdown redraws once a second so the expiry actually counts down
// instead of jumping when the next status poll lands. An expired invite stays
// on screen as "已过期" rather than vanishing: a QR that disappears leaves
// the user wondering whether the scan worked.
func (b *bar) tickCountdown() {
	b.mu.Lock()
	has := b.invite != nil
	b.mu.Unlock()
	if has {
		b.redraw()
	}
}

func (b *bar) menu() *mygo.Menu {
	b.mu.Lock()
	st := b.st
	b.mu.Unlock()

	header := "Dotlink · 未连接"
	switch {
	case st.Running && st.IPv4 != "":
		header = "Dotlink · " + st.IPv4
	case st.Running:
		header = "Dotlink · 正在连接"
	}

	items := []*mygo.MenuItem{
		{Label: header, Disabled: true},
		mygo.Separator(),
	}
	if len(st.Peers) == 0 {
		items = append(items, &mygo.MenuItem{Label: "还没有别的设备", Disabled: true})
	}
	for _, p := range st.Peers {
		items = append(items, &mygo.MenuItem{Label: describePeer(p), Disabled: true})
	}
	items = append(items, mygo.Separator())

	inviteLabel := "生成邀请二维码…"
	if !st.CanInvite {
		inviteLabel = "生成邀请二维码（本机不是 Gateway）"
	}
	items = append(items, &mygo.MenuItem{
		Label:    inviteLabel,
		Disabled: !st.CanInvite || !st.Running,
		Click:    func(*mygo.MenuItem, *mygo.Window) { b.createInvite() },
	})
	if st.Running {
		items = append(items, &mygo.MenuItem{
			Label: "断开",
			Click: func(*mygo.MenuItem, *mygo.Window) { b.call("断开", b.client.Disconnect) },
		})
	} else {
		items = append(items, &mygo.MenuItem{
			Label:    "连接",
			Disabled: st.CanInvite == false && st.IPv4 == "",
			Click:    func(*mygo.MenuItem, *mygo.Window) { b.call("连接", b.client.Connect) },
		})
	}
	items = append(items,
		&mygo.MenuItem{Label: "显示面板…", Click: func(*mygo.MenuItem, *mygo.Window) { b.togglePanel() }},
		mygo.Separator(),
		&mygo.MenuItem{Role: mygo.RoleQuit},
	)
	return mygo.NewMenu(items)
}

func describePeer(p ipc.Peer) string {
	path := "中继"
	if p.Path == "Direct" {
		path = "直连"
	}
	label := fmt.Sprintf("%s · %s", p.Hostname, path)
	if p.RTTms > 0 && p.Path == "Direct" {
		label += fmt.Sprintf(" · %d ms", p.RTTms)
	}
	return label
}

func (b *bar) togglePanel() {
	if b.win != nil {
		b.win.Close()
		return
	}
	b.win = mygo.NewWindow(mygo.WindowOptions{
		Title:  "Dotlink",
		Width:  380,
		Height: 620,
		Hidden: true,
		Content: ui.View(func(c *ui.Context) {
			b.view(c)
		}),
	})
	b.win.OnClosed(func() { b.win = nil })
	b.win.Show()
	b.win.Focus()
}

func (b *bar) createInvite() {
	b.mu.Lock()
	b.halted = ""
	b.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		inv, err := b.client.CreateInvite(ctx)
		var src ui.ImageSource
		if err == nil {
			png, qerr := qrcode.Encode(inv.URL, qrcode.Medium, 512)
			if qerr != nil {
				err = qerr
			} else {
				src, err = ui.DecodeImage(png)
			}
		}
		mygo.RunOnMain(func() {
			b.mu.Lock()
			if err != nil {
				b.halted = err.Error()
			} else {
				b.invite = &inv
				b.qr = src
			}
			b.mu.Unlock()
			if b.tray != nil {
				b.tray.SetMenu(b.menu())
			}
			if b.win == nil && err == nil {
				b.togglePanel()
			}
			b.redraw()
		})
	}()
}

// call runs one control action and reports its failure in the panel instead
// of a dialog: a menu bar app should not steal focus to say "no".
func (b *bar) call(what string, fn func(context.Context) error) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := fn(ctx)
		mygo.RunOnMain(func() {
			b.mu.Lock()
			if err != nil {
				b.halted = what + "失败：" + err.Error()
			} else {
				b.halted = ""
				if what == "断开" {
					b.invite, b.qr = nil, nil
				}
			}
			b.mu.Unlock()
			if b.tray != nil {
				b.tray.SetMenu(b.menu())
			}
			b.redraw()
		})
		b.refresh(context.Background())
	}()
}

func (b *bar) view(c *ui.Context) {
	t := c.Theme()
	b.mu.Lock()
	st := b.st
	inv := b.invite
	src := b.qr
	halted := b.halted
	b.mu.Unlock()

	root := ui.Column(c).Fill().Background(t.Surface).Padding(20).Gap(14)
	root.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Text(c, "Dotlink").FontSize(20).Bold()
			ui.Spacer(c)
			ui.Text(c, statusLabel(st)).FontSize(12).TextColor(t.TextMuted)
		})

		ui.Column(c).Gap(2).Padding(12).Radius(10).Border(1, t.Border).Children(func() {
			ui.Text(c, "本机").FontSize(11).TextColor(t.TextMuted)
			addr := st.IPv4
			if addr == "" {
				addr = "未分配"
			}
			ui.Text(c, addr).FontSize(26)
			if st.IPv6 != "" {
				ui.Text(c, st.IPv6).FontSize(11).TextColor(t.TextMuted)
			}
			if st.Network != "" {
				ui.Text(c, "网络 "+st.Network+" · MagicDNS .dotlink").FontSize(11).TextColor(t.TextMuted)
			}
		})

		ui.Text(c, "其他设备").FontSize(11).TextColor(t.TextMuted)
		if len(st.Peers) == 0 {
			ui.Text(c, "还没有设备加入。生成邀请二维码让对方扫一下。").FontSize(12).TextColor(t.TextMuted)
		}
		for _, p := range st.Peers {
			peer := p
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Column(c).Gap(1).Grow(1).Children(func() {
					ui.Text(c, peer.Hostname).FontSize(13)
					ui.Text(c, peer.IPv4).FontSize(11).TextColor(t.TextMuted)
				})
				ui.Text(c, describePeer(peer)).FontSize(11).TextColor(t.TextMuted)
			})
		}

		ui.Spacer(c)

		if inv != nil && src != nil && time.Now().Before(inv.ExpiresAt) {
			ui.Column(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Image(c, src).Width(240).Height(240)
				ui.Text(c, "用 iPhone 相机扫描").FontSize(12)
				ui.Text(c, "有效期还剩 "+shortRemaining(inv.ExpiresAt)).FontSize(11).TextColor(t.TextMuted)
			})
		} else if inv != nil {
			ui.Column(c).AlignItems(ui.Center).Gap(4).Children(func() {
				ui.Text(c, "二维码已过期").FontSize(13)
				ui.Text(c, "重新生成一张，旧的邀请在服务端也已经作废。").FontSize(11).TextColor(t.TextMuted)
			})
		}

		if halted != "" {
			ui.Text(c, halted).FontSize(11).TextColor(t.Warning)
		}

		ui.Row(c).Gap(10).Children(func() {
			ui.Button(c, "生成邀请").Disabled(!st.CanInvite).OnClick(b.createInvite)
			if st.Running {
				ui.Button(c, "断开").OnClick(func() { b.call("断开", b.client.Disconnect) })
			} else {
				ui.Button(c, "连接").OnClick(func() { b.call("连接", b.client.Connect) })
			}
		})
	})
}

func statusLabel(st ipc.Status) string {
	if !st.Running {
		return "已断开"
	}
	if st.Registered {
		return "已连接"
	}
	return "连接中…"
}

func shortRemaining(t time.Time) string {
	d := time.Until(t)
	if d <= 0 {
		return "已过期"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%d 小时 %d 分", h, m)
	}
	return fmt.Sprintf("%d 分", m+1)
}

// trayIcon draws a link: two overlapping rings, black on transparent so
// macOS tints it for light and dark menu bars.
func trayIcon() []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	ink := color.NRGBA{A: 255}
	ring := func(cx, cy, outer, inner float64) {
		for y := range 32 {
			for x := range 32 {
				dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
				d := dx*dx + dy*dy
				if d < outer*outer && d > inner*inner {
					img.Set(x, y, ink)
				}
			}
		}
	}
	ring(12, 16, 8, 5)
	ring(20, 16, 8, 5)
	// Clear the overlap so the two rings read as links, not a blob.
	for y := range 32 {
		for x := 15; x < 17; x++ {
			if img.NRGBAAt(x, y).A == 255 {
				img.Set(x, y, color.NRGBA{})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}
