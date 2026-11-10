#!/usr/bin/env bash
# Builds dist/syslog5651_<version>_<arch>.deb for Ubuntu 22.04 / 24.04.
# Usage: scripts/build-deb.sh [version]   (default: from git describe)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo 0.0.0)}"
case "$VERSION" in [0-9]*) ;; *) VERSION="0.1.0~${VERSION}" ;; esac
ARCH="${GOARCH:-amd64}"
PKG="dist/pkg"
rm -rf "$PKG" && mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/lib/systemd/system" \
  "$PKG/usr/share/doc/syslog5651" "$PKG/etc/syslog5651"

CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X main.version=$VERSION" -o "$PKG/usr/bin/syslog5651" ./cmd/syslog5651

install -m 0644 deploy/syslog5651.service "$PKG/lib/systemd/system/syslog5651.service"
install -m 0640 deploy/config.example.yaml "$PKG/etc/syslog5651/config.yaml"
install -m 0644 deploy/config.example.yaml "$PKG/usr/share/doc/syslog5651/config.example.yaml"
install -m 0644 KURULUM.md README.md "$PKG/usr/share/doc/syslog5651/"

cat > "$PKG/DEBIAN/control" <<EOF
Package: syslog5651
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: xz-utils, openssl, adduser
Maintainer: syslog5651
Description: 5651 uyumlu syslog toplama servisi
 Firewall loglarını toplar, sütunlu formatta yüksek oranla sıkıştırır,
 saatlik mühürler, günlük manifesti RFC 3161 zaman damgasıyla imzalar
 ve müşteri bazında web arayüzü sunar.
EOF

echo "/etc/syslog5651/config.yaml" > "$PKG/DEBIAN/conffiles"

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  if ! getent passwd syslog5651 >/dev/null; then
    adduser --system --group --home /var/lib/syslog5651 --no-create-home --shell /usr/sbin/nologin syslog5651
  fi
  install -d -m 0700 -o syslog5651 -g syslog5651 /var/lib/syslog5651
  install -d -m 0750 -o root -g syslog5651 /etc/syslog5651 /etc/syslog5651/tls
  chown root:syslog5651 /etc/syslog5651/config.yaml
  chmod 0640 /etc/syslog5651/config.yaml
  # Self-signed certificate for the web UI and syslog TLS (replace with your own).
  if [ ! -f /etc/syslog5651/tls/server.key ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
      -subj "/CN=$(hostname -f 2>/dev/null || hostname)" \
      -addext "subjectAltName=DNS:$(hostname -f 2>/dev/null || hostname),DNS:localhost,IP:127.0.0.1" \
      -keyout /etc/syslog5651/tls/server.key -out /etc/syslog5651/tls/server.crt >/dev/null 2>&1
    chown root:syslog5651 /etc/syslog5651/tls/server.key /etc/syslog5651/tls/server.crt
    chmod 0640 /etc/syslog5651/tls/server.key
    chmod 0644 /etc/syslog5651/tls/server.crt
  fi
  if [ ! -f /etc/syslog5651/users.yaml ]; then
    echo "users: []" > /etc/syslog5651/users.yaml
  fi
  chown root:syslog5651 /etc/syslog5651/users.yaml
  chmod 0640 /etc/syslog5651/users.yaml
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable syslog5651 >/dev/null 2>&1 || true
  echo ""
  echo "syslog5651 kuruldu. Sonraki adımlar:"
  echo "  1) sudo nano /etc/syslog5651/config.yaml   (müşteriler ve zaman damgası)"
  echo "  2) sudo syslog5651 useradd -users /etc/syslog5651/users.yaml -name admin -role admin"
  echo "  3) sudo systemctl restart syslog5651 && sudo systemctl status syslog5651"
  echo "Rehber: /usr/share/doc/syslog5651/KURULUM.md"
fi
exit 0
EOF

cat > "$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
  systemctl stop syslog5651 >/dev/null 2>&1 || true
  systemctl disable syslog5651 >/dev/null 2>&1 || true
fi
exit 0
EOF

cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
# Log data (/var/lib/syslog5651) is legal evidence and is never deleted by the package.
systemctl daemon-reload >/dev/null 2>&1 || true
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"

mkdir -p dist
OUT="dist/syslog5651_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG" "$OUT" >/dev/null
rm -rf "$PKG"
echo "$OUT"
