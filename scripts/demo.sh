#!/bin/sh
# Yerel demo: örnek veriyle servisi ve web panelini başlatır (macOS veya Linux).
# Gereken: Go, openssl. Kullanım: scripts/demo.sh   Durdurmak: Ctrl+C
# Panel: https://localhost:8443  admin / demo-admin-5651, lojistik / demo-lojistik-5651
set -e
cd "$(dirname "$0")/.."
D="$(pwd)/demo"
mkdir -p "$D/tls"
go build -o "$D/syslog5651" ./cmd/syslog5651
if [ ! -d "$D/data" ]; then
  DEMO_DIR="$D/data" go test ./internal/store/ -run TestDemoData -count=1 >/dev/null
fi
chmod 0700 "$D/data"
if [ ! -f "$D/tls/server.key" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=localhost \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$D/tls/server.key" -out "$D/tls/server.crt" 2>/dev/null
  chmod 0600 "$D/tls/server.key"
fi
if [ ! -f "$D/users.yaml" ]; then
  echo demo-admin-5651 | "$D/syslog5651" useradd -users "$D/users.yaml" -name admin -role admin
  echo demo-lojistik-5651 | "$D/syslog5651" useradd -users "$D/users.yaml" -name lojistik -role tenant -tenants musteri-a
fi
cat > "$D/config.yaml" <<CFG
data_dir: $D/data
timezone: Europe/Istanbul
listen: {udp: "127.0.0.1:5514", tcp: "127.0.0.1:5514"}
compression: {codec: zstd}
timestamp: {mode: none}
web: {listen: "127.0.0.1:8443", tls_cert: $D/tls/server.crt, tls_key: $D/tls/server.key, users_file: $D/users.yaml}
tenants:
  - {id: musteri-a, name: "Örnek Lojistik A.Ş.", sources: [10.0.0.0/24, 127.0.0.1], license_until: "2027-09-30"}
  - {id: musteri-b, name: "Deniz Otel Ltd.", sources: [10.0.1.0/24], retention_days: 365, license_until: "2026-11-28"}
CFG
# Canlı log: birkaç saniyede bir örnek firewall satırı (musteri-a).
( sleep 2; i=0; while kill -0 $$ 2>/dev/null; do i=$((i+1))
  printf '<189>date=%s time=%s devname="FGT60F" type="traffic" subtype="forward" srcip=192.168.1.%d dstip=142.250.187.%d dstport=443 action="accept" policyid=3 service="HTTPS" sentbyte=%d rcvdbyte=%d\n' \
    "$(date +%F)" "$(date +%T)" $((i % 40 + 10)) $((i % 200)) $((i * 37 % 9000)) $((i * 91 % 90000)) |
    nc -u -w1 127.0.0.1 5514 >/dev/null 2>&1 || true
  sleep 3
done ) &
echo "Panel: https://localhost:8443  (admin / demo-admin-5651, lojistik / demo-lojistik-5651)"
exec "$D/syslog5651" run -config "$D/config.yaml"
