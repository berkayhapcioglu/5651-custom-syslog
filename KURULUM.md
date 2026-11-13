# Kurulum Rehberi

Bu rehber syslog5651 servisini bir Ubuntu sunucuya kurmayı, müşterileri tanımlamayı ve firewall'ları bağlamayı anlatır. Kurulum yaklaşık 15 dakika sürer.

## 1. Gereksinimler

| Konu | Öneri |
| --- | --- |
| İşletim sistemi | Ubuntu Server 22.04 veya 24.04 (64 bit) |
| CPU / RAM | Başlangıç için 2 çekirdek, 4 GB RAM (tahmini; log hacmine göre artırın) |
| Disk | Tahmini: ham log hacminin yaklaşık 1/15'i × saklama süresi (ör. günde 10 GB ham log, 2 yıl ≈ 500 GB). Gerçek oran ilk günlerden sonra panelde görünür. |
| Saat | NTP açık olmalı: `timedatectl` çıktısında `System clock synchronized: yes` |
| Zaman damgası | KamuSM zaman damgası sözleşmesi (kontör) ve erişim bilgileri |

Sunucuda şu portların açık olması gerekir:

| Port | Protokol | Ne için | Kime açılmalı |
| --- | --- | --- | --- |
| 514 | UDP ve TCP | Syslog | Sadece müşteri firewall'larının IP'lerine |
| 6514 | TCP (TLS) | Şifreli syslog | Sadece müşteri firewall'larının IP'lerine |
| 8443 | TCP (HTTPS) | Web arayüzü | Sadece ofis / VPN IP'lerine |

## 2. Paketi kurma

```bash
sudo apt update
sudo apt install ./syslog5651_0.1.0_amd64.deb
```

Paket şunları yapar:

- `syslog5651` adında, giriş yapamayan bir sistem kullanıcısı oluşturur. Servis root olarak çalışmaz.
- Programı `/usr/bin/syslog5651` olarak kurar.
- Ayar dosyasını `/etc/syslog5651/config.yaml` olarak koyar.
- Log klasörünü `/var/lib/syslog5651` olarak açar (sadece servis kullanıcısı okuyabilir).
- Web arayüzü ve TLS syslog için kendinden imzalı bir sertifika üretir (`/etc/syslog5651/tls/`).
- Kısıtlamalı bir systemd servisi kurar (sadece 514 portunu açma yetkisi, salt okunur sistem, sadece log klasörüne yazma).

Paket kaldırılsa bile `/var/lib/syslog5651` silinmez, çünkü içindekiler yasal delildir.

## 3. Müşterileri tanımlama

En kolay yol paneldir: yönetici olarak girip **Log kaynakları** sayfasında "Yeni müşteri" ile müşteriyi açın, ardından firewall'un IP'sini ekleyin. Değişiklik servisi yeniden başlatmadan hemen geçerli olur ve denetim kaydına yazılır. Panelden eklenenler `/var/lib/syslog5651/_panel/panel.json` dosyasında saklanır.

Aynı sayfada saklama süresi (365-3650 gün) ve lisans bitiş tarihi de girilir. Lisansı biten müşterinin logları **kabul edilmeye devam eder**; panel sadece uyarır (5651 gereği log kaybı olmaz). Uyarının kaç gün önce başlayacağı **Ayarlar** sayfasındadır. Ayrıca "Bilinmeyen kaynaklar" listesi, henüz hiçbir müşteriye bağlanmamış ama log gönderen IP'leri gösterir; tek tıkla bir müşteriye eklenebilir.

İsterseniz müşterileri `config.yaml` içinde de tanımlayabilirsiniz. Bunlar panelde "config.yaml" etiketiyle görünür; adları ve IP'leri sadece dosyadan değişir, saklama süresi ve lisans tarihi panelden de değiştirilebilir.

```bash
sudo nano /etc/syslog5651/config.yaml
```

Her müşteri `tenants` altında bir kayıttır:

```yaml
tenants:
  - id: lojistik-as            # kısa ad: küçük harf, rakam, - ve _
    name: "Örnek Lojistik A.Ş."
    sources:
      - 203.0.113.10           # firewall'un dış IP'si
      - 198.51.100.0/28        # veya bir ağ
  - id: deniz-otel
    name: "Deniz Otel Ltd."
    sources: [192.0.2.44]
    retention_days: 730        # isterseniz müşteriye özel saklama süresi
```

Kurallar:

- Servis, gelen logu kaynak IP'sine bakarak ilgili müşteriye yazar.
- Hiçbir müşteriye uymayan IP'lerden gelen loglar atılır ve panelde "Bilinmeyen kaynak" sayacında görünür.
- İki müşterinin IP aralıkları çakışırsa servis başlamaz ve hatayı söyler (panel ise çakışan kaynağı hiç kaydetmez).
- Panelden eklenen ağlar IPv4'te en az /16, IPv6'da en az /32 olmalıdır.
- Her müşterinin klasörü, günlük manifesti, zaman damgası ve saklama süresi ayrıdır.

Firewall'lar NAT arkasındaysa veya IP'leri değişiyorsa TLS (6514) ile istemci sertifikası kullanın: `listen.tls_client_ca` ayarını doldurun ve her firewall'a bu CA'dan imzalı bir sertifika verin.

## 4. Zaman damgasını ayarlama

5651 uyumu için bu adım zorunludur. `timestamp.mode: none` sadece denemek içindir.

**KamuSM istemcisiyle (önerilen):** KamuSM'in verdiği istemci programını sunucuya kurun ve `config.yaml` içine şunu yazın:

```yaml
timestamp:
  mode: exec
  command: ["/opt/kamusm/istemci", "<girdi parametresi>", "{data}", "<çıktı parametresi>", "{out}"]
  ca_file: /etc/syslog5651/kamusm-root.crt
```

Parametre adlarını KamuSM istemcisinin belgesinden alın. `{data}` yerine damgalanacak manifest dosyası, `{out}` yerine istemcinin yazacağı `.tsr` dosyası konur.

**Standart RFC 3161 sunucusuyla:**

```yaml
timestamp:
  mode: http
  url: "https://..."                          # TSA adresi
  username: "kullanici"                       # gerekiyorsa
  password_file: /etc/syslog5651/tsa-password
  ca_file: /etc/syslog5651/tsa-root.crt
```

Şifre dosyasını şu izinlerle oluşturun:

```bash
sudo sh -c 'printf "%s" "SIFRE" > /etc/syslog5651/tsa-password'
sudo chown root:syslog5651 /etc/syslog5651/tsa-password
sudo chmod 0640 /etc/syslog5651/tsa-password
```

Servis her gün, gün bittikten 10 dakika sonra her müşteri için **bir** zaman damgası alır (müşteri başına günde 1 kontör). Damga alınamazsa her dakika yeniden dener ve gün "Açık" olarak kalır.

## 5. Web kullanıcısı oluşturma

İlk yöneticiyi komut satırından oluşturun (tüm müşterileri görür):

```bash
sudo syslog5651 useradd -name admin -role admin
```

Sonraki kullanıcıları panelde **Kullanıcılar** sayfasından ekleyin. Müşteri kullanıcısı sadece seçilen müşterilerin loglarını görür. Komut satırından da eklenebilir:

```bash
sudo syslog5651 useradd -name lojistik -role tenant -tenants lojistik-as
```

**İki adımlı giriş:** Her kullanıcı **Hesabım** sayfasından açabilir. Ekrandaki QR kodu Google Authenticator, Microsoft Authenticator gibi bir uygulamayla okutulur; sonraki girişlerde şifreden sonra uygulamadaki 6 haneli kod istenir. Yöneticiler için açılması önerilir (Kullanıcılar sayfasında kimde açık olduğu görünür). Telefonunu kaybeden kullanıcı için yönetici **Kullanıcılar** sayfasında "İki adımlı girişi sıfırla"ya basar; son yönetici kendi telefonunu kaybettiyse sunucuda `sudo syslog5651 useradd -name admin -role admin -reset-2fa` çalıştırılır.

Şifre en az 12 karakter olmalıdır ve argon2id ile saklanır. Kullanıcılar `/var/lib/syslog5651/_panel/users.yaml` dosyasındadır; komut satırından yapılan değişiklikler birkaç saniye içinde servis yeniden başlatılmadan geçerli olur. Şifresi değişen ya da silinen kullanıcının açık oturumları hemen kapanır. Herkes kendi şifresini **Hesabım** sayfasından değiştirebilir. En az bir yönetici her zaman kalır.

## 6. Servisi başlatma

```bash
sudo systemctl restart syslog5651
sudo systemctl status syslog5651
sudo journalctl -u syslog5651 -f      # canlı servis kayıtları
```

Web arayüzü: `https://SUNUCU-IP:8443`

Kendinden imzalı sertifika olduğu için tarayıcı ilk girişte uyarı verir. Kalıcı çözüm için kendi sertifikanızı `/etc/syslog5651/tls/server.crt` ve `server.key` olarak koyun (`chown root:syslog5651`, anahtar için `chmod 0640`) ve servisi yeniden başlatın.

## 6a. E-posta uyarıları

Servis bir sorun olduğunda e-posta atar: bir müşteriden belirlenen süre (varsayılan 2 saat) log gelmemesi, bir günün mühürlenememesi (zaman damgası alınamıyor), veri diskinin %90 dolması, log dosyalarına yazılamaması, lisansın bitmesi ya da yaklaşması, web/TLS/zaman damgası sertifikalarının bitmesine 30 günden az kalması. Sorun başlayınca, sürerse günde bir (lisans ve sertifika için haftada bir) ve düzelince e-posta gelir.

1. Posta sunucusunu `config.yaml` içindeki `alerts` bölümüne yazın (örnek dosyada açıklamalı hali var) ve şifreyi ayrı bir dosyaya koyun:

```bash
sudo sh -c 'printf "%s" "SMTP-SIFRESI" > /etc/syslog5651/smtp-password'
sudo chown root:syslog5651 /etc/syslog5651/smtp-password
sudo chmod 0640 /etc/syslog5651/smtp-password
sudo systemctl restart syslog5651
```

2. Panelde **Ayarlar ve durum > E-posta uyarıları** bölümüne alıcıları yazın ve **Deneme e-postası gönder** ile kontrol edin. Aynı bölümde şu anki sorunlar ve son gönderilen bildirimler listelenir.

Uyarılar şifreli bağlantı olmadan gönderilmez (STARTTLS ya da TLS). Zabbix, Uptime Kuma gibi bir izleme aracınız varsa `https://SUNUCU:8443/healthz` adresini izletebilirsiniz: sorun yokken 200, hata düzeyinde bir sorun varken 503 döner (giriş gerektirmez, müşteri bilgisi içermez).

## 7. Sunucu firewall'u (ufw)

```bash
sudo ufw allow from 203.0.113.10 to any port 514 proto udp
sudo ufw allow from 203.0.113.10 to any port 514 proto tcp
sudo ufw allow from 203.0.113.10 to any port 6514 proto tcp
sudo ufw allow from OFIS-IP to any port 8443 proto tcp
sudo ufw allow OpenSSH
sudo ufw enable
```

Her müşteri firewall'u için ilk üç satırı tekrarlayın.

## 8. Firewall'lardan log gönderme

Menü adları cihazın yazılım sürümüne göre değişebilir; tablo genel bir yol göstericidir.

| Cihaz | Nereden | Ayar |
| --- | --- | --- |
| Sophos | System services > Log settings > Syslog servers > Add | Sunucu IP, port 514, Severity: Information. Gönderilecekler: Firewall rules, Invalid traffic, Web filter, Application filter, Admin events, Authentication events |
| FortiGate | Log & Report > Log Settings > Remote Logging | `config log syslogd setting` → `set status enable`, `set server SUNUCU-IP`, `set port 514`, `set format default` |
| pfSense / OPNsense | Status > System Logs > Settings > Remote Logging | Sunucu IP:514, "Firewall Events" ve "DHCP" seçili |
| MikroTik | System > Logging > Actions | `remote` action: sunucu IP, port 514; firewall kurallarında `log=yes` |

İç IP dağıtımı (DHCP) loglarını da göndermeyi unutmayın; 5651 kapsamında hangi iç IP'nin kime verildiği de sorulur.

Kurulumdan sonra panelde müşterinin "Son log" sütununun güncellendiğini kontrol edin.

## 9. Günlük işleyiş

- **Her saat başı** biten saatin dosyası sıkıştırılır, açılıp hash'i kontrol edilir, ardından ham dosya silinir.
- **Her gün 00:10'da** önceki gün için manifest oluşturulur, zaman damgası alınır ve gün "Mühürlü" olur. Manifest bir önceki günün manifestine hash ile bağlanır, böylece arada gün silinirse fark edilir.
- **Her saat** saklama süresi dolan mühürlü günler silinir ve silme kaydı `/var/lib/syslog5651/_audit/audit.jsonl` dosyasına yazılır.
- Panelde bir güne girip **Bütünlüğü doğrula** ile o günün bütün dosyaları kontrol edilir.
- Denetimde **Doğrulama paketini indir** ile o günün manifesti, zaman damgası ve sıkıştırılmış dosyaları tek zip olarak alınır.

- Her mühürlenen saat için küçük bir arama indeksi (`.idx`, sıkıştırılmış verinin yaklaşık %1-4'ü) yazılır. İndeks mühürün dışındadır: silinse ya da bozulsa bile mühür ve doğrulama etkilenmez, arama o saati baştan tarar ve indeksi yeniden oluşturur. Yönetici bir günün sayfasından **İndeksi yeniden oluştur** diyebilir.
- **Arama** sayfasında tarih aralığı, saat aralığı ve cihaz seçilir. "Tam kelime" modu (ör. kullanıcı adı, IP, alan adı) indeks sayesinde aranan kelimenin geçmediği saatleri açmadan atlar; "Metnin içinde" modu her satırı tarar. En fazla 500 sonuç gösterilir ve her arama denetim kaydına yazılır.
- Müşteri sayfasındaki **Aylık rapor**, seçilen ay için her günün kayıt sayısını, saklanan boyutu, mühür ve zaman damgası bilgisini gösterir. Tarayıcıda Yazdır > PDF olarak kaydet ile müşteriye gönderilebilir. Müşteri kullanıcıları kendi raporlarını alabilir.
- Arama sonuçları **CSV indir** ile Excel'de açılabilir (en çok 100.000 satır, Türkçe Excel için `;` ayraçlı).
- **Denetim kaydı** sayfası kim, ne zaman, hangi IP'den giriş yaptı, ne aradı, neyi değiştirdi gösterir.

Komut satırından doğrulama:

```bash
sudo -u syslog5651 syslog5651 verify -config /etc/syslog5651/config.yaml -tenant lojistik-as
```

Zaman damgasını servisten bağımsız olarak OpenSSL ile de kontrol edebilirsiniz:

```bash
openssl ts -verify -data manifest.json -in manifest.json.tsr -CAfile kamusm-root.crt
```

## 10. Yedekleme

`/var/lib/syslog5651` klasörünü düzenli olarak başka bir diske veya nesne depolamaya kopyalayın (ör. `rsync -a` ile gece). Mühürlü dosyalar değişmez, bu yüzden artımlı yedek çok küçük olur. Panelden yapılan müşteri, kaynak ve kullanıcı değişiklikleri bu klasörün `_panel` alt klasöründedir. Ayarlar için `/etc/syslog5651` klasörünü de yedekleyin.

## 11. Sorun giderme

| Belirti | Kontrol |
| --- | --- |
| Panelde "Son 1 saatte log gelmedi" | Firewall syslog ayarı, ufw kuralı, `config.yaml` içindeki IP doğru mu? |
| "Bilinmeyen kaynak" sayacı artıyor | Log gelen IP hiçbir müşteriye tanımlı değil. Panelde **Log kaynakları > Bilinmeyen kaynaklar** listesinden doğru müşteriye ekleyin. |
| Gün "Açık" kalıyor | Zaman damgası alınamıyor: `journalctl -u syslog5651 | grep "seal day"` |
| Servis başlamıyor | `journalctl -u syslog5651 -n 50`; hatalı ayar satırı mesajda yazar. |
