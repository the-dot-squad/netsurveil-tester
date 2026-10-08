#!/bin/sh
# Installs or upgrades the NetSurveil tester node as a systemd service, without Docker.
#
#   curl -fsSL https://github.com/the-dot-squad/netsurveil-tester/releases/latest/download/install.sh | sudo sh
#   sudo sh install.sh --uninstall [--purge]
#
# Environment (first install only, except VERSION):
#   VERSION    release tag to install, e.g. v0.1.0 (default: latest)
#   NODE_ID    node identifier (prompted for when unset)
#   FEED_URLS  comma-separated feed mirror URLs for pull mode (optional)
#   NODE_PORT  port for direct requests (default 8080)
#
# Settings live in /etc/netsurveil-tester/node.env; re-running upgrades the
# binary and keeps them.
set -eu

REPO=the-dot-squad/netsurveil-tester
SERVICE=netsurveil-tester
BIN=/usr/local/bin/nst-node
CONF_DIR=/etc/netsurveil-tester
ENV_FILE=$CONF_DIR/node.env
UNIT=/etc/systemd/system/$SERVICE.service
SVC_USER=nst-node

die() {
	echo "install.sh: $*" >&2
	exit 1
}

uninstall() {
	systemctl disable --now "$SERVICE" 2>/dev/null || true
	rm -f "$UNIT" "$BIN"
	systemctl daemon-reload
	if id "$SVC_USER" >/dev/null 2>&1; then
		userdel "$SVC_USER"
	fi
	if [ "${1:-}" = "--purge" ]; then
		rm -rf "$CONF_DIR"
	fi
	echo "$SERVICE removed"
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ "$(uname -s)" = Linux ] || die "Linux only"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

case "${1:-}" in
"") ;;
--uninstall)
	uninstall "${2:-}"
	exit 0
	;;
*) die "usage: install.sh [--uninstall [--purge]]" ;;
esac

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

for cmd in curl tar sha256sum; do
	command -v "$cmd" >/dev/null 2>&1 || die "$cmd is required"
done

if [ -z "${VERSION:-}" ]; then
	VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/##')
fi
case "$VERSION" in
v[0-9]*) ;;
*) die "cannot resolve the release to install (got '$VERSION'); set VERSION" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ASSET="nst-node_${VERSION}_linux_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
echo "downloading $ASSET"
curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"
curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
(cd "$TMP" && grep " $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "checksum verification failed"
tar -xzf "$TMP/$ASSET" -C "$TMP" nst-node
install -m 0755 "$TMP/nst-node" "$BIN"

if ! id "$SVC_USER" >/dev/null 2>&1; then
	useradd --system --no-create-home --shell "$(command -v nologin || echo /bin/false)" "$SVC_USER"
fi

NEW_SECRET=
if [ ! -f "$ENV_FILE" ]; then
	NODE_ID=${NODE_ID:-}
	if [ -z "$NODE_ID" ] && [ -r /dev/tty ]; then
		printf 'NODE_ID ([A-Za-z0-9._-], e.g. ir-tehran-1): ' >/dev/tty
		read -r NODE_ID </dev/tty
	fi
	[ -n "$NODE_ID" ] || die "set NODE_ID"
	NEW_SECRET=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
	mkdir -p "$CONF_DIR"
	(
		umask 077
		cat >"$ENV_FILE" <<EOF
NODE_ID=$NODE_ID
NODE_SECRET=$NEW_SECRET
LISTEN_ADDR=:${NODE_PORT:-8080}
HEALTH_ADDR=off
FEED_URLS=${FEED_URLS:-}
HTTP_PATH_PREFIX=
RATE_LIMIT_PER_MIN=30
ALLOW_PRIVATE_TARGETS=false
LOG_LEVEL=warn
EOF
	)
	chown root:"$SVC_USER" "$ENV_FILE"
	chmod 0640 "$ENV_FILE"
fi

cat >"$UNIT" <<EOF
[Unit]
Description=NetSurveil tester node
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ENV_FILE
ExecStart=$BIN
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=true
MemoryMax=128M
TasksMax=128

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"

echo "nst-node $VERSION installed; status: systemctl status $SERVICE, logs: journalctl -u $SERVICE"
echo "settings: $ENV_FILE (restart the service after editing)"
if [ -n "$NEW_SECRET" ]; then
	echo "NODE_SECRET=$NEW_SECRET"
	echo "register this secret with the node on the website; it is not shown again"
fi
