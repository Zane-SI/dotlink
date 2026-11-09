#!/bin/sh
# Installs Dotlink on this Mac: the Agent as a launch daemon, the menu bar app
# in /Applications. Needs sudo because both halves write outside the home.
set -eu

SRC=$(cd "$(dirname "$0")/../.." && pwd)
AGENT_BIN=${AGENT_BIN:-$SRC/bin/dotlink-agent}
BAR_APP=${BAR_APP:-$SRC/bin/Dotlink.app}
PLIST=$SRC/packaging/macos/com.dotlink.agent.plist

if [ ! -x "$AGENT_BIN" ]; then
	echo "missing $AGENT_BIN — run 'make build' first" >&2
	exit 1
fi
if [ ! -d "$BAR_APP" ]; then
	echo "missing $BAR_APP — run 'make build' first" >&2
	exit 1
fi

sudo install -d -m 0755 /usr/local/libexec
sudo install -m 0755 "$AGENT_BIN" /usr/local/libexec/dotlink-agent

sudo rm -rf /Applications/Dotlink.app
sudo cp -R "$BAR_APP" /Applications/Dotlink.app
sudo chown -R root:wheel /Applications/Dotlink.app

# The launchd job has no shell, so a Gateway is configured through this file
# instead of editing ProgramArguments. A flag on `dotlink-agent up` still wins.
if [ -n "${ADVERTISE_ROUTES:-}" ]; then
	sudo install -d -m 0755 /usr/local/etc/dotlink
	printf '%s\n' "$ADVERTISE_ROUTES" | sudo tee /usr/local/etc/dotlink/advertise-routes >/dev/null
	sudo chmod 0644 /usr/local/etc/dotlink/advertise-routes
	sudo chown root:wheel /usr/local/etc/dotlink/advertise-routes
	echo "gateway routes: $ADVERTISE_ROUTES"
fi

sudo install -m 0644 -o root -g wheel "$PLIST" /Library/LaunchDaemons/com.dotlink.agent.plist

# bootout fails when the daemon is not loaded yet; that is the normal first
# install, not an error.
sudo launchctl bootout system/com.dotlink.agent 2>/dev/null || true
sudo launchctl bootstrap system /Library/LaunchDaemons/com.dotlink.agent.plist
sudo launchctl enable system/com.dotlink.agent

echo "agent installed. enroll this Mac first:"
echo "  sudo dotlink-agent join 'dotlink://enroll?...'"
echo "then open /Applications/Dotlink.app"
