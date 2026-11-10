# 5651-custom-syslog

Firewall loglarını toplayıp 5651 sayılı kanuna uygun şekilde saklayan, çok müşterili (multi-tenant) bir syslog servisi. SIEM istemeyen müşteriler için tasarlandı: logu alır, kayıpsız ve yüksek oranla sıkıştırır, hash zinciriyle mühürler, her gün RFC 3161 (KamuSM) zaman damgası alır, saklama süresi dolunca denetim kaydıyla siler ve müşteri bazında bir web arayüzü sunar.

Kurulum için: [KURULUM.md](KURULUM.md)

![Müşteriler](docs/ekran/2-musteriler.png)

## Nasıl çalışır

1. **Alım:** UDP 514, TCP 514 (RFC 6587 çerçeveleme) ve TLS 6514 (RFC 5425). Kaynak IP müşteriye eşlenir; tanımsız kaynaklar reddedilir.
2. **Ham dosya:** Her kayıt değiştirilmeden, alınma zamanı (UTC, nanosaniye) ve kaynak IP ile saatlik dosyaya yazılır: `<müşteri>/<gün>/<cihaz>/<saat>.log`
3. **Saatlik mühür:** Biten saat sütunlu formatta sıkıştırılır (`.s5651`), açılıp ham dosyanın SHA-256'sıyla karşılaştırılır, `hours.jsonl` dosyasına hash zinciriyle eklenir, ardından ham dosya silinir.
4. **Günlük mühür:** Gün bitince müşteri başına bir `manifest.json` (tüm dosyaların hash'leri, önceki günün manifest hash'i) oluşturulur ve RFC 3161 zaman damgası alınır (`manifest.json.tsr`). Müşteri başına günde 1 damga harcanır.
5. **Saklama:** Varsayılan 730 gün, müşteri bazında değiştirilebilir. Silmeden önce denetim kaydı yazılır; mühürlenmemiş gün hiçbir zaman silinmez.

## Sıkıştırma

Firewall logları çoğunlukla `anahtar=değer` çiftlerinden oluşur. `colz` formatı her satırı bir şablona (anahtarların sırası) ve sütunlara (her anahtarın değerleri) ayırır, artan sayıları (zaman, eventtime) fark olarak saklar ve her sütunu ayrı sıkıştırır. Dönüşüm bayt bayt geri alınabilir; her mühürlemede bu kontrol edilir.

Aynı sentetik FortiGate verisi (150.000 satır, alanların çoğu rastgele, yani en kötü durum):

| Yöntem | Oran |
| --- | --- |
| xz -9e (düz dosya) | 11,4x |
| zstd, sütunlu | 13,5x |
| **xz -9e, sütunlu (varsayılan)** | **15,2x** |

Daha gerçekçi tekrarlı demo verisinde sütunlu zstd ile saatlik dosyalar 25x civarında sıkışıyor. Gerçek müşteri loguyla ölçmek için:

```bash
COLZ_BENCH=/yol/ham.log go test ./internal/colz/ -run TestBenchFile -v
```

## Güvenlik

- Servis root olmayan kullanıcıyla, kısıtlamalı systemd birimiyle çalışır (sadece `CAP_NET_BIND_SERVICE`; salt okunur sistem; seccomp filtresi).
- Veri klasörü `0700`, mühürlü dosyalar `0400`; web ve doğrulama tarafındaki dosya okumaları ile saklama silmeleri `os.Root` ile veri klasörüne hapsedilir.
- Web: sadece HTTPS (TLS 1.2+), HSTS, sıkı CSP (hiç JavaScript yok), `__Host-` çerezler (Secure, HttpOnly, SameSite=Strict), her POST'ta CSRF token, argon2id şifreler, IP ve kullanıcı bazında artan kilitleme, müşteri izolasyonu (başka müşterinin sayfası 404 döner), tüm giriş/arama/indirme işlemleri denetim kaydına yazılır.
- Sıkıştırılmış dosyaları okuyan kod fuzz testinden geçer; boyut sınırları decompression bomb'a karşı korur.
- CI'da `go vet`, testler (race dahil), `gosec` ve `govulncheck` çalışır.

## Geliştirme

```bash
go test ./...                 # tüm testler
go test -race ./...
scripts/build-deb.sh 0.1.0    # dist/syslog5651_0.1.0_amd64.deb
```

Paketler: `internal/ingest` (alım), `internal/store` (dosyalar, mühür, manifest, saklama, doğrulama), `internal/colz` (sütunlu sıkıştırma), `internal/tsa` (RFC 3161), `internal/web` (arayüz), `internal/config`.
