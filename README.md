# Safe4Me

**Linux CVE / güvenlik yaması & denetim script'i** — tek dosya, bağımsız, bash.
RHEL ailesi (AlmaLinux / CentOS / Rocky / RHEL) ve Debian ailesi (Ubuntu / Debian)
sunucularda son dönemde çıkan CVE'lerin düzeltmelerini **dağıtımın kendi güvenlik
akışı** üzerinden uygular; uygulama katmanını (PHP / Node.js / SQL) ve sunucu
sertleştirmesini denetler.

> _Developer & Distributor:_ **[cagritopuz.com](https://cagritopuz.com)** · _License:_ MIT

> **EN (short):** Single-file bash tool that patches recent CVEs via the
> distribution's own security feed (no hardcoded CVE list), reports EOL app
> versions (PHP/Node/SQL) live from endoflife.date, cross-checks CISA KEV, and
> runs an optional read-only hardening audit. **Report-only by default**, no
> telemetry, all network calls disablable with `--offline`.

---

## Neden "gömülü CVE listesi" yok?

Script içine sabit bir CVE listesi **kasıtlı olarak** gömülmez. Dağıtımın
`dnf/yum --security` ve `apt` güvenlik pocket'ı, son çıkan açıkların
backport'lanmış, doğru ve **her zaman güncel** düzeltmelerini zaten taşır. Elle
yazılan bir liste bir sonraki ay eskir ve yanıltır. Safe4Me bu nedenle
**düzeltme motoru olarak dağıtımın kendi akışını sürer**, üstüne görünürlük
(EOL + CISA KEV) ve denetim katmanları ekler.

## Güvenlik modeli

- **Varsayılan = SADECE RAPOR.** `--apply` verilmedikçe hiçbir şey değişmez.
- **Reboot için ayrı onay** (`--reboot`), aksi halde sadece bildirir.
- **Telemetri YOK.** Hiçbir yere veri gönderilmez.
- **Dışarı çıkan tek şey iki salt-okunur indirme** (aşağıya bak), `--offline` ile
  tamamen kapanır.
- `--apply` sırasında **geri alma (rollback)** bilgisi kaydedilir.

## Ağ erişimi (şeffaflık)

Safe4Me **yalnızca** şu iki herkese açık kaynağa bağlanır, ikisi de GET (indirme):

| Kaynak | Amaç |
|---|---|
| `cisa.gov/.../known_exploited_vulnerabilities.json` | Aktif sömürülen (KEV) CVE listesi |
| `endoflife.date/api/<ürün>.json` | PHP/Node/SQL EOL tarihleri |

`--audit-apps` ve `--wordpress` kullanılırsa `composer`/`npm`/`pip-audit`/`wp-cli`
kendi advisory kaynaklarına çıkar. **Tümü `--offline` ile atlanır.**

## Özellikler

- **OS yaması:** RHEL (`dnf/yum update --security`) + Debian (`apt` güvenlik pocket / `unattended-upgrade`)
- **Çekirdek:** KernelCare canlı yama desteği, reboot + `needrestart` tespiti
- **Uygulama sürümleri:** PHP (sistem + cPanel `ea-php` + LiteSpeed/ISPmanager `lsphp`), Node/npm, MySQL/MariaDB/PostgreSQL, nginx/Apache/LiteSpeed, Redis
- **EOL kontrolü:** endoflife.date'ten canlı — destek-dışı sürümleri işaretler
- **CVE görünürlük:** CISA KEV canlı rapor
- **Bağımlılık denetimi:** `composer audit` + `npm audit` + `pip-audit` (`--audit-apps`)
- **Güvenlik denetimi (`--security-audit`, salt-okunur):** SSH, firewall, fail2ban, dinlenen portlar, SUID, dünyaya-yazılabilir dosyalar, TLS sertifika son kullanma, malware/rootkit araç durumu, Lynis
- **WordPress (`--wordpress DIZIN`):** wp-cli ile core/plugin/theme güncellik
- **Rollback:** RHEL `dnf history undo`, Debian için eski sürüm kaydı
- **JSON çıktı (`--json`):** makine-okur özet (filoya toplamak için — gönderim YOK)

## Kurulum

```bash
curl -fsSLO https://raw.githubusercontent.com/cagritopuz/safe4me/main/safe4me.sh
chmod +x safe4me.sh
```

Önerilen bağımlılıklar (yoksa ilgili adım zarifçe atlanır): `curl`, `jq`,
`needrestart` / `yum-utils`(dnf-utils), ve denetim için `composer`, `npm`,
`pip-audit`, `wp-cli`, `lynis`.

## Kullanım

```bash
sudo ./safe4me.sh                     # SADECE RAPOR — hiçbir şey değişmez
sudo ./safe4me.sh --apply             # güvenlik güncellemelerini uygula
sudo ./safe4me.sh --apply --full      # sadece güvenlik değil TÜM güncellemeler
sudo ./safe4me.sh --apply --reboot    # gerekiyorsa uyguladıktan sonra reboot
sudo ./safe4me.sh --apply --yes       # soru sormadan (cron için)
sudo ./safe4me.sh --security-audit    # SSH/firewall/SUID/sertifika/rootkit denetimi
sudo ./safe4me.sh --audit-apps /home  # composer/npm/pip bağımlılık denetimi
sudo ./safe4me.sh --wordpress /home   # wp-cli ile WordPress güncellik denetimi
sudo ./safe4me.sh --json              # makine-okur özet (stdout'a)
sudo ./safe4me.sh --offline           # hiçbir dış bağlantı kurma
sudo ./safe4me.sh --log /yol/x.log    # özel log dosyası
```

### Bayraklar

| Bayrak | Açıklama |
|---|---|
| (yok) | Rapor modu — hiçbir değişiklik yapılmaz |
| `--apply` | Güvenlik güncellemelerini uygular |
| `--full` | `--apply` ile: sadece güvenlik değil tüm güncellemeler |
| `--reboot` | `--apply` ile: gerekirse yeniden başlatır |
| `--yes`, `-y` | Etkileşimli onayı atlar (cron) |
| `--security-audit` | Salt-okunur sertleştirme denetimi |
| `--audit-apps DIZIN` | composer/npm/pip bağımlılık denetimi |
| `--wordpress DIZIN` | wp-cli ile WordPress güncellik denetimi |
| `--json` | Makine-okur özet (stdout) |
| `--offline` | Tüm dış bağlantıları kapatır |
| `--log DOSYA` | Log dosyası yolu |
| `-h`, `--help` | Yardım |

### Çıkış kodları

| Kod | Anlam |
|---|---|
| 0 | Temiz / başarılı |
| 10 | Güncelleme uygulandı, **yeniden başlatma bekliyor** |
| 2 | Kullanım hatası |
| 3 | Desteklenmeyen dağıtım |
| 4 | root değil |

## Cron örneği (haftalık rapor)

```cron
# Her pazar 03:00 — sadece rapor, log dosyasına
0 3 * * 0 root /opt/safe4me/safe4me.sh --log /var/log/safe4me-weekly.log
```

## Sorumluluk reddi

Bu araç **root ile** çalışır ve paket kurar/günceller. Üretim sunucusunda
`--apply` kullanmadan önce script'i **okuyun** ve önce rapor modunda çalıştırın.
MIT lisansı gereği **garanti verilmez** — kendi sorumluluğunuzda kullanın.
Yedeğinizi almadan `--apply` çalıştırmayın.

## Lisans

MIT © 2026 [cagritopuz.com](https://cagritopuz.com) — bkz. [LICENSE](LICENSE)
