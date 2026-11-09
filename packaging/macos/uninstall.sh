#!/bin/sh
# Removes everything this app installed. It does not touch ~/.dotlink: the
# Node's key pair and token are the user's identity, and re-enrolling would
# mint a new Node. Pass --purge to delete that too.
set -eu

sudo launchctl bootout system/com.dotlink.agent 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.dotlink.agent.plist
sudo rm -f /usr/local/libexec/dotlink-agent
sudo rm -rf /Applications/Dotlink.app
# The socket outlives the process by design (a reinstall should not inherit a
# dead endpoint), so remove it explicitly.
sudo rm -f /var/run/dotlink.sock
sudo rm -f /var/log/dotlink-agent.log

# Orphan utun interfaces go away with the process; say so rather than pretend
# to clean something that is already gone.
if ifconfig 2>/dev/null | grep -q '^utun'; then
	echo "note: utun interfaces exist; they belong to other VPN clients or the OS"
fi

for home in /Users/*; do
	[ -f "$home/.dotlink/node.json" ] || continue
	if [ "${1:-}" = "--purge" ]; then
		sudo rm -rf "$home/.dotlink"
		echo "purged $home/.dotlink"
	else
		echo "kept $home/.dotlink (enrollment kept; pass --purge to delete)"
	fi
done

echo "uninstalled"
