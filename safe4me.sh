#!/usr/bin/env bash
# ============================================================================
#  Safe4Me — Linux CVE / Güvenlik Yaması & Denetim Script'i  (safe4me.sh)
# ----------------------------------------------------------------------------
#  Geliştirici & Dağıtımcı : cagritopuz.com
#  Lisans                  : MIT (bkz. LICENSE)
#  Telemetri               : YOK — bkz. "AĞ ERİŞİMİ" bölümü
# ----------------------------------------------------------------------------
#  Ne yapar?
#    Dağıtımın KENDİ güvenlik akışını (security feed) sürerek son dönemde
#    çıkan CVE'lerin backport'lanmış düzeltmelerini uygular. Yani sabit bir
#    "CVE listesi" gömülü DEĞİLDİR — bu kasıtlı: dağıtım security repo'su her
#    zaman güncel ve doğru kaynaktır, elle yazılan CVE listesi eskir/yanıltır.
#
#    Desteklenen aileler:
#      * RHEL ailesi  (AlmaLinux / CentOS / Rocky / RHEL — cPanel sunucuları)
#          -> dnf/yum update --security
#      * Debian ailesi (Ubuntu / Debian — ISPmanager sunucuları)
#          -> apt security pocket (unattended-upgrade tercihli)
#
#    Ekstra:
#      * KernelCare varsa çekirdeği CANLI yamalar (reboot gerekmez)
#      * CISA KEV kataloğunu CANLI çekip aktif sömürülen Linux çekirdek
#        CVE'lerini raporlar (internet varsa) — gömülü/uydurma ID yok
#      * Yüksek profilli bileşenleri (kernel, sudo, openssl, glibc, openssh,
#        bash) kontrol eder, reboot/servis yeniden başlatma ihtiyacını bildirir
#
#    UYGULAMA KATMANI (NodeJS / PHP / SQL / web sunucuları):
#      * Kurulu sürümleri raporlar: PHP (sistem + cPanel ea-php + lsphp /opt),
#        Node/npm, MySQL/MariaDB, PostgreSQL, nginx/Apache/LiteSpeed, Redis
#      * endoflife.date API'sini CANLI çekip DESTEK DIŞI (EOL) sürümleri
#        işaretler — EOL = artık güvenlik yaması GELMEZ, en büyük risk budur
#      * --audit-apps DIZIN ile composer audit + npm audit çalıştırır
#        (müşteri uygulamalarının bağımlılık CVE'leri)
#      * lsphp (LiteSpeed/ISPmanager) ve cPanel'e özel güncelleme hook'ları
#
#    GÜVENLİK DENETİMİ (--security-audit, salt-okunur):
#      * SSH sertleştirme (root login / parola auth / port)
#      * Güvenlik duvarı (firewalld/ufw/csf/nftables) + fail2ban durumu
#      * Dinlenen portlar, SUID & dünyaya-yazılabilir dosya taraması
#      * TLS sertifikası son kullanma (certbot/openssl)
#      * Malware/rootkit araç durumu (Imunify/ClamAV/rkhunter/chkrootkit)
#      * Lynis sertleştirme skoru (varsa)
#
#    WORDPRESS (--wordpress DIZIN): wp-cli ile core/plugin/theme güncel mi
#    ROLLBACK: --apply sırasında işlem kaydı tutulur, geri alma komutu basılır
#    JSON: --json ile makine-okur özet (dış filoya toplamak için — gönderim YOK)
#
#  AĞ ERİŞİMİ (şeffaflık — bu script SADECE şu iki herkese açık kaynağa bağlanır):
#    * https://www.cisa.gov/.../known_exploited_vulnerabilities.json  (CISA KEV)
#    * https://endoflife.date/api/<ürün>.json                         (EOL tarihleri)
#    Başka HİÇBİR yere veri GÖNDERMEZ, telemetri yoktur. Tümünü kapatmak için
#    --offline kullan (airgap/kapalı sunucularda).
#
#  Kullanım:
#    sudo ./safe4me.sh                     # SADECE RAPOR — hiçbir şey değişmez
#    sudo ./safe4me.sh --apply             # güvenlik güncellemelerini uygula
#    sudo ./safe4me.sh --apply --full      # SADECE güvenlik değil TÜM güncellemeler
#    sudo ./safe4me.sh --apply --reboot    # gerekiyorsa uyguladıktan sonra reboot
#    sudo ./safe4me.sh --apply --yes       # soru sormadan (cron için)
#    sudo ./safe4me.sh --security-audit    # SSH/firewall/SUID/sertifika/rootkit denetimi
#    sudo ./safe4me.sh --audit-apps /home  # composer/npm/pip bağımlılık denetimi
#    sudo ./safe4me.sh --wordpress /home   # wp-cli ile WordPress güncellik denetimi
#    sudo ./safe4me.sh --json              # makine-okur özet (stdout'a)
#    sudo ./safe4me.sh --offline           # hiçbir dış bağlantı kurma
#    sudo ./safe4me.sh --log /yol/x.log
#
#  Çıkış kodları: 0=temiz/başarılı  10=güncelleme uygulandı, reboot bekliyor
#                 2=kullanım hatası  3=desteklenmeyen dağıtım  4=root değil
# ============================================================================
set -euo pipefail

# ---- Varsayılan ayarlar ----------------------------------------------------
APPLY=0            # --apply verilmedikçe rapor modu (güvenli varsayılan)
FULL=0             # --full : güvenlik dışı tüm güncellemeleri de al
DO_REBOOT=0        # --reboot : gerekirse yeniden başlat
ASSUME_YES=0       # --yes : etkileşimli onayı atla
OFFLINE=0          # --offline : hiçbir dış bağlantı kurma (KEV + endoflife.date kapalı)
AUDIT_DIR=""       # --audit-apps DIZIN : composer/npm/pip bağımlılık denetimi (read-only)
SEC_AUDIT=0        # --security-audit : SSH/firewall/SUID/sertifika/rootkit denetimi
WP_DIR=""          # --wordpress DIZIN : wp-cli ile WordPress güncellik denetimi
JSON=0             # --json : makine-okur özet (stdout'a; hiçbir yere GÖNDERİLMEZ)
LOG="/var/log/safe4me-$(date +%Y%m%d-%H%M%S).log"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ---- JSON/özet sayaçları (global) ------------------------------------------
EOL_WARN=0         # EOL (destek dışı) bulgu sayısı
SEC_FINDINGS=0     # güvenlik denetimi uyarı sayısı
ROLLBACK_HINT=""   # --apply sonrası geri alma komutu

# ---- Argüman ayrıştırma ----------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --apply)  APPLY=1 ;;
    --full)   FULL=1 ;;
    --reboot) DO_REBOOT=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --offline) OFFLINE=1 ;;
    --security-audit) SEC_AUDIT=1 ;;
    --audit-apps) shift; AUDIT_DIR="${1:?--audit-apps sonrası dizin gerekli (ör: /home)}" ;;
    --wordpress)  shift; WP_DIR="${1:?--wordpress sonrası dizin gerekli (ör: /home)}" ;;
    --json)   JSON=1 ;;
    --log)    shift; LOG="${1:?--log sonrası dosya yolu gerekli}" ;;
    -h|--help)
      sed -n '2,70p' "$0"; exit 0 ;;
    *) echo "Bilinmeyen argüman: $1  (yardım: --help)" >&2; exit 2 ;;
  esac
  shift
done

# ---- Log altyapısı ---------------------------------------------------------
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
# --json modunda insan çıktısı SADECE log dosyasına gider; stdout'a yalnız JSON.
if [ "$JSON" -eq 1 ]; then exec 3>&1 1>/dev/null; fi
log()  { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
hr()   { printf -- '--------------------------------------------------------------\n' | tee -a "$LOG"; }
die()  { printf 'HATA: %s\n' "$*" | tee -a "$LOG" >&2; exit "${2:-1}"; }

# ---- root kontrolü ---------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "root gerekli — 'sudo $0 ...' ile çalıştır." 4

# JSON modunda etkileşimli onay gösterilemez — --apply için --yes zorunlu
if [ "$JSON" -eq 1 ] && [ "$APPLY" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
  die "JSON modunda --apply için --yes zorunlu (etkileşimli onay gösterilemez)." 2
fi

# JSON özet üretici (sadece --json; stdout'a yazar, hiçbir yere GÖNDERMEZ)
emit_json() {
  [ "$JSON" -eq 1 ] || return 0
  printf '{"tool":"safe4me","developer":"cagritopuz.com","host":"%s","os":"%s %s","kernel":"%s","mode":"%s","offline":%s,"reboot_needed":%s,"eol_warnings":%d,"security_findings":%d,"rollback":"%s","log":"%s"}\n' \
    "$(hostname -f 2>/dev/null || hostname)" "${OS_NAME:-?}" "${OS_VER:-?}" "$(uname -r)" \
    "$([ "$APPLY" -eq 1 ] && echo applied || echo report)" \
    "$([ "$OFFLINE" -eq 1 ] && echo true || echo false)" \
    "$([ "${REBOOT_NEEDED:-0}" -eq 1 ] && echo true || echo false)" \
    "${EOL_WARN:-0}" "${SEC_FINDINGS:-0}" "${ROLLBACK_HINT:-}" "$LOG" >&3
}

hr
log "Safe4Me — Linux güvenlik yaması & denetim  (cagritopuz.com)"
log "Sunucu: $(hostname -f 2>/dev/null || hostname)"
log "Mod: $([ "$APPLY" -eq 1 ] && echo UYGULA || echo 'SADECE RAPOR')  Full:$FULL  Reboot:$DO_REBOOT  Log:$LOG"
hr

# ---- Dağıtım tespiti --------------------------------------------------------
FAMILY=""; OS_NAME="?"; OS_VER="?"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_NAME="${NAME:-?}"; OS_VER="${VERSION_ID:-?}"
  case " ${ID:-} ${ID_LIKE:-} " in
    *" rhel "*|*" fedora "*|*" centos "*|*" almalinux "*|*" rocky "*) FAMILY="rhel" ;;
    *" debian "*|*" ubuntu "*) FAMILY="debian" ;;
  esac
fi
[ -n "$FAMILY" ] || die "Desteklenmeyen/anlaşılamayan dağıtım: $OS_NAME $OS_VER" 3
log "Dağıtım: $OS_NAME $OS_VER  (aile: $FAMILY)"
log "Çalışan çekirdek: $(uname -r)"

# ---- Disk ön kontrolü (/var ve / için en az ~500MB) -------------------------
check_disk() {
  local path="$1" need_mb=500 avail_mb
  avail_mb=$(df -Pm "$path" 2>/dev/null | awk 'NR==2{print $4}')
  [ -n "${avail_mb:-}" ] || return 0
  if [ "$avail_mb" -lt "$need_mb" ]; then
    log "UYARI: $path üzerinde sadece ${avail_mb}MB boş (<${need_mb}MB). Güncelleme başarısız olabilir."
  fi
}
check_disk /; check_disk /var

# ---- KernelCare (canlı çekirdek yaması) tespiti -----------------------------
KCARE=0
if command -v kcarectl >/dev/null 2>&1; then
  KCARE=1
  log "KernelCare tespit edildi — çekirdek canlı yamalanacak, reboot gerekmeyebilir."
fi

# ---- CISA KEV: aktif sömürülen Linux çekirdek CVE'leri (CANLI) --------------
kev_report() {
  [ "$OFFLINE" -eq 1 ] && { log "KEV kontrolü atlandı (--offline)."; return 0; }
  command -v curl >/dev/null 2>&1 || { log "KEV kontrolü atlandı (curl yok)."; return 0; }
  local tmp; tmp="$(mktemp)"
  if ! curl -fsSL --max-time 20 "$KEV_URL" -o "$tmp" 2>/dev/null; then
    log "KEV kontrolü atlandı (CISA kataloğuna erişilemedi — offline sunucu olabilir)."
    rm -f "$tmp"; return 0
  fi
  log "CISA KEV — 'Linux' satıcılı (aktif sömürülen) açıklar:"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.vulnerabilities[]
           | select((.vendorProject|ascii_downcase)=="linux")
           | "   \(.cveID)  \(.vulnerabilityName)  (son tarih: \(.dueDate))"' "$tmp" \
      | tee -a "$LOG" || log "   (KEV ayrıştırılamadı)"
  else
    # jq yoksa kaba grep — sadece Linux bloğundaki cveID'leri yakala
    grep -oE '"cveID":"CVE-[0-9]{4}-[0-9]+"' "$tmp" | sed 's/.*"\(CVE[^"]*\)"/   \1/' \
      | sort -u | tail -40 | tee -a "$LOG" || true
    log "   (jq kurulu değil — tam filtreleme için 'jq' kur; yukarısı ham liste)"
  fi
  log "   NOT: Yukarıdaki CVE'leri dağıtımınızın advisory'si ile DOĞRULAYIN; bu script"
  log "        bunları otomatik yamalamaz, çekirdek güncellemesi + reboot gerekebilir."
  rm -f "$tmp"
}

# ---- Yüksek profilli bileşen sürümleri -------------------------------------
report_components() {
  log "Kritik bileşen sürümleri:"
  local p
  if [ "$FAMILY" = "rhel" ]; then
    for p in kernel sudo openssl glibc openssh-server bash; do
      rpm -q "$p" 2>/dev/null | sed 's/^/   /' | tee -a "$LOG" || log "   $p: kurulu değil"
    done
  else
    for p in sudo openssl libc6 openssh-server bash; do
      dpkg-query -W -f='   ${Package} ${Version}\n' "$p" 2>/dev/null | tee -a "$LOG" || log "   $p: kurulu değil"
    done
    log "   kernel: $(uname -r)"
  fi
}

# ============================================================================
#  UYGULAMA KATMANI — NodeJS / PHP / SQL / web sunucuları
# ============================================================================

# Bir sürüm dizesinden ilk X.Y'yi çıkar (ör: "10.11.6-MariaDB" -> "10.11")
ver_xy() { grep -oE '[0-9]+\.[0-9]+' <<<"$1" | head -1; }

# Kurulu uygulama bileşeni sürümlerini raporla
app_layer_report() {
  log "Uygulama katmanı sürümleri:"
  # PHP — sistem CLI
  if command -v php >/dev/null 2>&1; then
    log "   php (CLI): $(php -r 'echo PHP_VERSION;' 2>/dev/null)"
  fi
  # PHP — cPanel EasyApache (ea-php70..84)
  local b
  for b in /opt/cpanel/ea-php*/root/usr/bin/php; do
    [ -x "$b" ] || continue
    log "   $b: $("$b" -r 'echo PHP_VERSION;' 2>/dev/null)"
  done
  # PHP — LiteSpeed / ISPmanager lsphp (/opt/phpXX, /usr/local/lsws/lsphp*)
  for b in /opt/php*/bin/php /usr/local/lsws/lsphp*/bin/php; do
    [ -x "$b" ] || continue
    log "   $b: $("$b" -r 'echo PHP_VERSION;' 2>/dev/null)"
  done
  # Node / npm
  if command -v node >/dev/null 2>&1; then log "   node: $(node -v 2>/dev/null)"; fi
  if command -v npm  >/dev/null 2>&1; then log "   npm:  $(npm -v 2>/dev/null)"; fi
  # Veritabanları
  if command -v mariadb >/dev/null 2>&1; then
    log "   mariadb: $(mariadb --version 2>/dev/null)"
  elif command -v mysql >/dev/null 2>&1; then
    log "   mysql/mariadb: $(mysql --version 2>/dev/null)"
  fi
  if command -v psql >/dev/null 2>&1; then log "   postgresql: $(psql --version 2>/dev/null)"; fi
  # Web sunucuları
  if command -v nginx   >/dev/null 2>&1; then log "   nginx: $(nginx -v 2>&1)"; fi
  if command -v httpd   >/dev/null 2>&1; then log "   apache(httpd): $(httpd -v 2>/dev/null | head -1)"; fi
  if command -v apache2 >/dev/null 2>&1; then log "   apache2: $(apache2 -v 2>/dev/null | head -1)"; fi
  if [ -x /usr/local/lsws/bin/lshttpd ]; then log "   litespeed: $(/usr/local/lsws/bin/lshttpd -v 2>/dev/null | head -1)"; fi
  # Önbellek
  if command -v redis-server >/dev/null 2>&1; then log "   redis: $(redis-server --version 2>/dev/null)"; fi
}

# endoflife.date'ten TEK ürün+sürüm için EOL durumu (CANLI). Sabit tarih gömülü değil.
eol_fetch() {  # $1=ürün (php|nodejs|mysql|mariadb|postgresql)  $2=sürüm (X.Y)
  [ "$OFFLINE" -eq 1 ] && return 0
  command -v curl >/dev/null 2>&1 || return 0
  command -v jq   >/dev/null 2>&1 || { log "   ($1 $2: EOL kontrolü için 'jq' gerekli)"; return 0; }
  local prod="$1" ver="$2" tmp eol maj today
  [ -n "$ver" ] || return 0
  tmp="$(mktemp)"
  if ! curl -fsSL --max-time 15 "https://endoflife.date/api/${prod}.json" -o "$tmp" 2>/dev/null; then
    rm -f "$tmp"; log "   ($prod: endoflife.date'e erişilemedi)"; return 0
  fi
  # Önce X.Y cycle'ı, yoksa major prefix ile eşleştir
  eol="$(jq -r --arg v "$ver" '[.[] | select((.cycle|tostring)==$v)][0].eol // empty' "$tmp" 2>/dev/null)"
  if [ -z "$eol" ]; then
    maj="${ver%%.*}"
    eol="$(jq -r --arg v "$maj" '[.[] | select((.cycle|tostring|startswith($v)))][0].eol // empty' "$tmp" 2>/dev/null)"
  fi
  rm -f "$tmp"
  [ -n "$eol" ] || { log "   $prod $ver: EOL verisi bulunamadı"; return 0; }
  today="$(date +%F)"
  case "$eol" in
    true)  log "   ⚠ $prod $ver: DESTEK DIŞI (EOL) — güvenlik yaması GELMİYOR, SÜRÜM YÜKSELT!"; EOL_WARN=$((EOL_WARN+1)) ;;
    false) log "   ✓ $prod $ver: destekleniyor" ;;
    *)     if [[ "$eol" < "$today" ]]; then
             log "   ⚠ $prod $ver: $eol tarihinde EOL oldu — güvenlik yaması GELMİYOR, YÜKSELT!"; EOL_WARN=$((EOL_WARN+1))
           else
             log "   ✓ $prod $ver: destekleniyor (EOL: $eol)"
           fi ;;
  esac
}

# Tespit edilen tüm uygulama sürümleri için EOL kontrolü
eol_check() {
  [ "$OFFLINE" -eq 1 ] && { log "EOL kontrolü atlandı (--offline)."; return 0; }
  log "Uygulama sürümü yaşam-sonu (EOL) kontrolü — endoflife.date (CANLI):"
  local b v
  # PHP sürümlerinin tümü (sistem + ea-php + lsphp) — tekrarları ele
  # NOT: 'while read' process substitution ile çağrılır ki EOL_WARN sayacı
  #      ana kabukta artsın (pipeline subshell'i sayacı yutar).
  while read -r v; do eol_fetch php "$v"; done < <(
    { command -v php >/dev/null 2>&1 && php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null; echo
      for b in /opt/cpanel/ea-php*/root/usr/bin/php /opt/php*/bin/php /usr/local/lsws/lsphp*/bin/php; do
        [ -x "$b" ] && { "$b" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null; echo; }
      done; } | grep -E '^[0-9]+\.[0-9]+$' | sort -u )
  # Node
  if command -v node >/dev/null 2>&1; then eol_fetch nodejs "$(ver_xy "$(node -v 2>/dev/null)")"; fi
  # DB
  if command -v mariadb >/dev/null 2>&1; then
    eol_fetch mariadb "$(ver_xy "$(mariadb --version 2>/dev/null)")"
  elif command -v mysql >/dev/null 2>&1; then
    v="$(mysql --version 2>/dev/null)"
    if grep -qi mariadb <<<"$v"; then eol_fetch mariadb "$(ver_xy "$v")"; else eol_fetch mysql "$(ver_xy "$v")"; fi
  fi
  if command -v psql >/dev/null 2>&1; then eol_fetch postgresql "$(ver_xy "$(psql --version 2>/dev/null)")"; fi
}

# composer audit + npm audit — müşteri uygulamalarının bağımlılık CVE'leri (read-only)
app_audit() {
  local dir="$1" max=25 n proj lock pl req
  if [ "$OFFLINE" -eq 1 ]; then
    log "Uygulama bağımlılık denetimi atlandı (--offline) — composer/npm/pip-audit internet gerektirir."
    return 0
  fi
  log "Uygulama bağımlılık denetimi: $dir  (en çok $max proje/tür)"
  # PHP / composer
  if command -v composer >/dev/null 2>&1; then
    n=0
    while IFS= read -r lock; do
      [ -n "$lock" ] || continue
      [ "$n" -ge "$max" ] && { log "   ... composer: $max sınırına ulaşıldı, kalanı atlandı"; break; }
      proj="$(dirname "$lock")"; n=$((n+1))
      log "   composer audit → $proj"
      ( cd "$proj" && composer audit --no-interaction --format=plain 2>&1 | sed 's/^/      /' ) | tee -a "$LOG" || true
    done < <(find "$dir" -maxdepth 5 -name composer.lock -not -path '*/vendor/*' 2>/dev/null)
    [ "$n" -eq 0 ] && log "   (composer.lock bulunamadı)"
  else
    log "   composer yok — PHP bağımlılık denetimi atlandı."
  fi
  # Node / npm
  if command -v npm >/dev/null 2>&1; then
    n=0
    while IFS= read -r pl; do
      [ -n "$pl" ] || continue
      [ "$n" -ge "$max" ] && { log "   ... npm: $max sınırına ulaşıldı, kalanı atlandı"; break; }
      proj="$(dirname "$pl")"; n=$((n+1))
      log "   npm audit → $proj"
      ( cd "$proj" && npm audit --omit=dev 2>&1 | sed 's/^/      /' ) | tee -a "$LOG" || true
    done < <(find "$dir" -maxdepth 5 -name package-lock.json -not -path '*/node_modules/*' 2>/dev/null)
    [ "$n" -eq 0 ] && log "   (package-lock.json bulunamadı)"
  else
    log "   npm yok — Node bağımlılık denetimi atlandı."
  fi
  log "   NOT: nvm ile kurulu Node sürümleri sistem paket yöneticisiyle güncellenmez;"
  log "        kullanıcı kendi 'nvm install <sürüm>' ile yükseltmeli."
  # Python / pip-audit (PyPA — OSV/PyPI advisory DB'sine canlı sorar)
  if command -v pip-audit >/dev/null 2>&1; then
    # Önce aktif/sistem ortamı
    log "   pip-audit → sistem/aktif Python ortamı"
    pip-audit 2>&1 | sed 's/^/      /' | tee -a "$LOG" || true
    # Sonra bulunan requirements dosyaları (sınırlı)
    n=0
    while IFS= read -r req; do
      [ -n "$req" ] || continue
      [ "$n" -ge "$max" ] && { log "   ... pip-audit: $max sınırına ulaşıldı, kalanı atlandı"; break; }
      n=$((n+1))
      log "   pip-audit → $req"
      pip-audit -r "$req" 2>&1 | sed 's/^/      /' | tee -a "$LOG" || true
    done < <(find "$dir" -maxdepth 5 -name 'requirements*.txt' -not -path '*/site-packages/*' 2>/dev/null)
  else
    log "   pip-audit yok — Python bağımlılık denetimi atlandı ('pip install pip-audit' ile kurulur)."
  fi
}

# --apply sonrası platforma özel servis yenileme / notlar
post_apply_hooks() {
  [ "$APPLY" -eq 1 ] || return 0
  if [ -d /usr/local/lsws ]; then
    log "LiteSpeed tespit edildi — graceful restart (lswsctrl)..."
    [ -x /usr/local/lsws/bin/lswsctrl ] && { /usr/local/lsws/bin/lswsctrl restart >>"$LOG" 2>&1 || log "   lswsctrl restart başarısız."; }
    log "   NOT: lsphp'de ini/OPcache düzeyi değişiklikler RUNTIME'da etkisiz kalabilir;"
    log "        gerekirse 'killall lsphp' ile worker'ları zorla yenile."
  fi
  if [ -d /usr/local/cpanel ]; then
    log "cPanel tespit edildi — ea-php/sistem paketleri yum security ile güncellendi."
    log "   cPanel çekirdeği için elle: '/usr/local/cpanel/scripts/upcp --log-timestamps'."
  fi
}

# ============================================================================
#  GÜVENLİK DENETİMİ (salt-okunur) — --security-audit
#  Hiçbir ayarı DEĞİŞTİRMEZ; sadece durum raporlar ve bulgu sayar.
# ============================================================================
security_audit() {
  log "GÜVENLİK DENETİMİ (salt-okunur — hiçbir ayar değiştirilmez):"

  # 1) SSH sertleştirme
  log " [SSH] etkin yapılandırma:"
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -iE '^(permitrootlogin|passwordauthentication|port|permitemptypasswords|x11forwarding) ' | sed 's/^/    /' | tee -a "$LOG" || true
    if sshd -T 2>/dev/null | grep -qiE '^permitrootlogin[[:space:]]+yes'; then
      log "    ⚠ PermitRootLogin yes — root ile doğrudan SSH açık."; SEC_FINDINGS=$((SEC_FINDINGS+1)); fi
    if sshd -T 2>/dev/null | grep -qiE '^passwordauthentication[[:space:]]+yes'; then
      log "    ⚠ PasswordAuthentication yes — brute-force riski, anahtar tabanlıya geç."; SEC_FINDINGS=$((SEC_FINDINGS+1)); fi
  else
    grep -hiE '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|Port)\b' \
      /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sed 's/^/    /' | tee -a "$LOG" || log "    (sshd yapılandırması okunamadı)"
  fi

  # 2) Güvenlik duvarı
  local fw="yok"
  if   command -v csf >/dev/null 2>&1; then fw="CSF kurulu"
  elif systemctl is-active --quiet firewalld 2>/dev/null; then fw="firewalld (aktif)"
  elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then fw="ufw (aktif)"
  elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then fw="nftables (kural var)"
  elif command -v iptables >/dev/null 2>&1 && [ "$(iptables -S 2>/dev/null | wc -l)" -gt 3 ]; then fw="iptables (kural var)"
  fi
  if [ "$fw" = "yok" ]; then log " [Firewall] ⚠ Aktif güvenlik duvarı tespit edilemedi."; SEC_FINDINGS=$((SEC_FINDINGS+1));
  else log " [Firewall] $fw"; fi

  # 3) fail2ban
  if command -v fail2ban-client >/dev/null 2>&1; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      log " [fail2ban] aktif — jail'ler:$(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/{print $2}')"
    else
      log " [fail2ban] kurulu ama ÇALIŞMIYOR."; SEC_FINDINGS=$((SEC_FINDINGS+1))
    fi
  else
    log " [fail2ban] kurulu değil (brute-force koruması için önerilir)."
  fi

  # 4) Dinlenen portlar
  if command -v ss >/dev/null 2>&1; then
    log " [Dinlenen portlar]:"
    ss -tulpnH 2>/dev/null | awk '{print $1, $5}' | sort -u | sed 's/^/    /' | tee -a "$LOG" || true
  fi

  # 5) SUID dosyalar (gözle incele — beklenmeyen olan var mı)
  log " [SUID dosyalar] (ilk 50):"
  find / -xdev -perm -4000 -type f 2>/dev/null | head -50 | sed 's/^/    /' | tee -a "$LOG" || true

  # 6) Dünyaya-yazılabilir dosyalar (hassas dizinlerde)
  log " [Dünyaya-yazılabilir dosyalar] /etc /usr/bin /usr/sbin /usr/local (ilk 30):"
  find /etc /usr/bin /usr/sbin /usr/local -xdev -type f -perm -0002 2>/dev/null | head -30 | sed 's/^/    /' | tee -a "$LOG" || true

  # 7) TLS sertifikası son kullanma (Let's Encrypt live — <30 gün uyar)
  log " [TLS sertifikaları] (Let's Encrypt):"
  local c end e2 days
  for c in /etc/letsencrypt/live/*/fullchain.pem; do
    [ -f "$c" ] || continue
    end="$(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)"
    [ -n "$end" ] || continue
    e2="$(date -d "$end" +%s 2>/dev/null)" || e2=""
    [ -n "$e2" ] || continue
    days=$(( (e2 - $(date +%s)) / 86400 ))
    if [ "$days" -lt 30 ]; then
      log "    ⚠ $c: $days gün kaldı — yenile!"; SEC_FINDINGS=$((SEC_FINDINGS+1))
    else
      log "    ✓ $c: $days gün var"
    fi
  done

  # 8) Malware / rootkit araç durumu
  log " [Malware/rootkit araçları]:"
  if command -v imunify360-agent >/dev/null 2>&1; then
    log "    Imunify360: $(imunify360-agent version 2>/dev/null | head -1)"
  elif command -v imunify-antivirus >/dev/null 2>&1; then
    log "    ImunifyAV kurulu."
  fi
  command -v clamscan   >/dev/null 2>&1 && log "    ClamAV kurulu (tarama: clamscan -ri /home)."
  command -v rkhunter   >/dev/null 2>&1 && log "    rkhunter kurulu (tarama: rkhunter --check --sk)."
  command -v chkrootkit >/dev/null 2>&1 && log "    chkrootkit kurulu (tarama: chkrootkit)."
  if ! command -v imunify360-agent >/dev/null 2>&1 && ! command -v imunify-antivirus >/dev/null 2>&1 \
     && ! command -v clamscan >/dev/null 2>&1 && ! command -v rkhunter >/dev/null 2>&1 \
     && ! command -v chkrootkit >/dev/null 2>&1; then
    log "    ⚠ Hiçbir malware/rootkit aracı kurulu değil."; SEC_FINDINGS=$((SEC_FINDINGS+1))
  fi

  # 9) Lynis (varsa) — bu script çalıştırmaz, sadece bildirir
  if command -v lynis >/dev/null 2>&1; then
    log " [Lynis] kurulu — tam denetim: 'lynis audit system'."
    [ -f /var/log/lynis.log ] && grep -i 'Hardening index' /var/log/lynis.log 2>/dev/null | tail -1 | sed 's/^/    /' | tee -a "$LOG" || true
  else
    log " [Lynis] kurulu değil (derin sertleştirme denetimi için önerilir)."
  fi

  log " Güvenlik denetimi bulgu sayısı: $SEC_FINDINGS"
}

# ============================================================================
#  WORDPRESS — wp-cli ile güncellik denetimi (--wordpress DIZIN)
# ============================================================================
wordpress_scan() {
  local dir="$1" max=50 n=0 wpcfg docroot owner
  [ "$OFFLINE" -eq 1 ] && { log "WordPress denetimi atlandı (--offline — wp.org API gerekir)."; return 0; }
  if ! command -v wp >/dev/null 2>&1; then
    log "WordPress denetimi atlandı — wp-cli ('wp') kurulu değil."
    return 0
  fi
  log "WordPress denetimi: $dir  (en çok $max kurulum)"
  while IFS= read -r wpcfg; do
    [ -n "$wpcfg" ] || continue
    [ "$n" -ge "$max" ] && { log "   ... $max sınırına ulaşıldı, kalanı atlandı"; break; }
    docroot="$(dirname "$wpcfg")"; owner="$(stat -c '%U' "$docroot" 2>/dev/null)"; n=$((n+1))
    log "   WP → $docroot (sahip: ${owner:-?})"
    # wp-cli root ile çalışmayı reddeder; kurulum sahibinin kullanıcısı ile çalıştır
    local runas=(wp)
    [ -n "$owner" ] && [ "$owner" != root ] && runas=(sudo -u "$owner" -- wp)
    "${runas[@]}" --path="$docroot" core version 2>/dev/null | sed 's/^/      core: /' | tee -a "$LOG" || true
    "${runas[@]}" --path="$docroot" core check-update --format=csv 2>/dev/null | sed 's/^/      core-güncelleme: /' | tee -a "$LOG" || true
    "${runas[@]}" --path="$docroot" plugin list --update=available --fields=name,version,update_version --format=csv 2>/dev/null | sed 's/^/      eklenti-güncel: /' | tee -a "$LOG" || true
    "${runas[@]}" --path="$docroot" theme list --update=available --fields=name,version,update_version --format=csv 2>/dev/null | sed 's/^/      tema-güncel: /' | tee -a "$LOG" || true
  done < <(find "$dir" -maxdepth 4 -name wp-config.php 2>/dev/null)
  [ "$n" -eq 0 ] && log "   (wp-config.php bulunamadı)"
}

# ============================================================================
#  RHEL ailesi
# ============================================================================
run_rhel() {
  local PM
  if command -v dnf >/dev/null 2>&1; then PM="dnf"; else PM="yum"; fi
  log "Paket yöneticisi: $PM"

  # security plugin'ini garanti altına al
  if [ "$PM" = "yum" ]; then
    rpm -q yum-plugin-security >/dev/null 2>&1 || { log "yum-plugin-security kuruluyor..."; [ "$APPLY" -eq 1 ] && yum -y install yum-plugin-security >>"$LOG" 2>&1 || true; }
  fi

  log "Metadata yenileniyor..."
  $PM -q makecache >>"$LOG" 2>&1 || true

  log "Bekleyen GÜVENLİK güncellemeleri / CVE'ler:"
  # updateinfo bazı dağıtımlarda boşsa nonzero dönebilir -> guard
  $PM updateinfo list security 2>/dev/null | sed 's/^/   /' | tee -a "$LOG" || log "   (güvenlik bülteni listesi boş ya da updateinfo yok)"

  if [ "$APPLY" -eq 0 ]; then
    log "RAPOR MODU — 'dnf update --security' simülasyonu (kurulacaklar):"
    $PM -q check-update --security 2>/dev/null | sed 's/^/   /' | tee -a "$LOG" || true
    return 0
  fi

  if [ "$FULL" -eq 1 ]; then
    log "TÜM güncellemeler uygulanıyor ($PM update)..."
    $PM -y update >>"$LOG" 2>&1
  else
    log "GÜVENLİK güncellemeleri uygulanıyor ($PM update --security)..."
    # --security bazı minimal sistemlerde bulgu yoksa 'Error' dönebilir; fallback
    if ! $PM -y update --security >>"$LOG" 2>&1; then
      log "   --security başarısız/boş; --nobest ile tekrar deneniyor..."
      $PM -y --nobest update --security >>"$LOG" 2>&1 || log "   güvenlik güncellemesi uygulanamadı (bülten olmayabilir)."
    fi
  fi

  # Rollback ipucu — son dnf/yum işlemi geri alınabilir
  local txid
  txid="$($PM history 2>/dev/null | awk 'NF>=2 && $1 ~ /^[0-9]+$/ {print $1; exit}')"
  if [ -n "${txid:-}" ]; then
    ROLLBACK_HINT="$PM history undo $txid"
    log "Geri alma: bu güncelleme '$ROLLBACK_HINT' ile geri alınabilir (işlem #$txid)."
  fi

  if [ "$KCARE" -eq 1 ]; then
    log "KernelCare canlı yama uygulanıyor..."
    kcarectl --update >>"$LOG" 2>&1 || log "   kcarectl --update başarısız."
  fi
}

# ============================================================================
#  Debian ailesi
# ============================================================================
run_debian() {
  export DEBIAN_FRONTEND=noninteractive
  log "Paket listeleri güncelleniyor (apt-get update)..."
  apt-get update >>"$LOG" 2>&1 || log "   apt-get update uyarı verdi (devam)."

  log "Yükseltilebilir paketler (güvenlik işaretli):"
  apt list --upgradable 2>/dev/null | grep -iE 'security' | sed 's/^/   /' | tee -a "$LOG" \
    || log "   (bekleyen güvenlik güncellemesi görünmüyor)"

  if [ "$APPLY" -eq 0 ]; then
    log "RAPOR MODU — kurulum simülasyonu (apt-get -s upgrade | güvenlik):"
    apt-get -s upgrade 2>/dev/null | awk '/^Inst/ && /[Ss]ecurity/ {print "   "$0}' | tee -a "$LOG" || true
    return 0
  fi

  # Rollback anlık görüntüsü — apt'ta yerel geri alma yok; yükseltilecek
  # paketlerin ESKİ sürümlerini kaydet ki gerekirse elle downgrade edilebilsin.
  local rbfile="${LOG%.log}-rollback.list"
  apt-get -s upgrade 2>/dev/null | awk '/^Inst/ {gsub(/[][]/,""); print $2"="$3}' > "$rbfile" 2>/dev/null || true
  if [ -s "$rbfile" ]; then
    ROLLBACK_HINT="apt-get install -V \$(xargs < $rbfile)"
    log "Geri alma: $(wc -l < "$rbfile") paketin eski sürümü kaydedildi → $rbfile"
    log "   Gerekirse downgrade: $ROLLBACK_HINT"
  fi

  if [ "$FULL" -eq 1 ]; then
    log "TÜM güncellemeler uygulanıyor (apt-get upgrade)..."
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade >>"$LOG" 2>&1
  else
    # Tercih 1: unattended-upgrade — SADECE yapılandırılmış güvenlik origin'lerini uygular
    if command -v unattended-upgrade >/dev/null 2>&1; then
      log "GÜVENLİK güncellemeleri uygulanıyor (unattended-upgrade)..."
      unattended-upgrade -v >>"$LOG" 2>&1 || log "   unattended-upgrade uyarı/hata verdi, log'a bak."
    else
      # Tercih 2: güvenlik pocket'ından paketleri hedefli yükselt
      log "unattended-upgrades yok — güvenlik paketleri hedefli yükseltiliyor..."
      local secpkgs
      secpkgs="$(apt-get -s upgrade 2>/dev/null | awk '/^Inst/ && /[Ss]ecurity/ {print $2}' | tr '\n' ' ')"
      if [ -n "${secpkgs// /}" ]; then
        log "   Yükseltilecek: $secpkgs"
        # shellcheck disable=SC2086
        apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install $secpkgs >>"$LOG" 2>&1
      else
        log "   Güvenlik işaretli bekleyen paket yok."
      fi
    fi
  fi
}

# ---- Reboot / servis yeniden başlatma ihtiyacı ------------------------------
REBOOT_NEEDED=0
check_reboot() {
  if [ "$FAMILY" = "rhel" ]; then
    if command -v needs-restarting >/dev/null 2>&1; then
      if ! needs-restarting -r >>"$LOG" 2>&1; then REBOOT_NEEDED=1; fi
    fi
  else
    [ -f /var/run/reboot-required ] && REBOOT_NEEDED=1
  fi
  # KernelCare çekirdeği canlı yamaladıysa, çekirdek kaynaklı reboot'u say ma
  if [ "$REBOOT_NEEDED" -eq 1 ] && [ "$KCARE" -eq 1 ]; then
    log "Reboot işareti var ama KernelCare aktif — çekirdek canlı yamalı; yalnızca"
    log "glibc/openssl gibi çekirdek dışı bileşenler için servis restart yeterli olabilir."
  fi

  # Servis bazında needrestart (varsa) — hangi servisler eski kütüphane kullanıyor
  if command -v needrestart >/dev/null 2>&1; then
    log "Yeniden başlatılması gereken servisler (needrestart):"
    needrestart -b 2>/dev/null | grep -E 'NEEDRESTART-(SVC|KSTA)' | sed 's/^/   /' | tee -a "$LOG" || true
  fi
}

# ============================================================================
#  AKIŞ
# ============================================================================
report_components
hr
app_layer_report
hr
eol_check
hr
kev_report
hr
if [ -n "$AUDIT_DIR" ]; then
  app_audit "$AUDIT_DIR"
  hr
fi
if [ "$SEC_AUDIT" -eq 1 ]; then
  security_audit
  hr
fi
if [ -n "$WP_DIR" ]; then
  wordpress_scan "$WP_DIR"
  hr
fi

# Uygulama modunda ve etkileşimliyse onay al
if [ "$APPLY" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
  printf 'Güvenlik güncellemeleri UYGULANACAK (%s). Devam? [e/H] ' "$([ "$FULL" -eq 1 ] && echo 'TÜM güncellemeler' || echo 'sadece güvenlik')"
  read -r ans || ans=""
  case "$ans" in e|E|evet|Evet|y|Y) ;; *) die "Kullanıcı iptal etti." 0 ;; esac
fi

case "$FAMILY" in
  rhel)   run_rhel ;;
  debian) run_debian ;;
esac

hr
post_apply_hooks
hr
check_reboot
hr

# ---- Özet -------------------------------------------------------------------
log "ÖZET"
if [ "$APPLY" -eq 0 ]; then
  log "  Mod: RAPOR — hiçbir değişiklik yapılmadı. Uygulamak için: $0 --apply"
else
  log "  Güvenlik güncellemeleri uygulandı. Detay: $LOG"
  [ -n "$ROLLBACK_HINT" ] && log "  Geri almak için: $ROLLBACK_HINT"
fi
[ "$EOL_WARN" -gt 0 ]     && log "  ⚠ $EOL_WARN adet DESTEK DIŞI (EOL) sürüm bulundu — yükseltme gerekiyor."
[ "$SEC_FINDINGS" -gt 0 ] && log "  ⚠ $SEC_FINDINGS adet güvenlik denetimi bulgusu var (yukarıda)."

if [ "$REBOOT_NEEDED" -eq 1 ]; then
  log "  ⚠ YENİDEN BAŞLATMA GEREKİYOR (yeni çekirdek/kütüphane aktifleşsin diye)."
  if [ "$APPLY" -eq 1 ] && [ "$DO_REBOOT" -eq 1 ]; then
    if [ "$ASSUME_YES" -eq 0 ]; then
      printf '  Şimdi reboot edilsin mi? [e/H] '; read -r rb || rb=""
    else rb="e"; fi
    case "$rb" in e|E|evet|Evet|y|Y) log "  Reboot ediliyor..."; sleep 2; systemctl reboot || reboot ;;
                  *) log "  Reboot atlandı — elle: 'systemctl reboot'." ;; esac
  else
    log "  Elle yeniden başlat: 'systemctl reboot'  (veya --reboot ile çalıştır)."
  fi
  emit_json
  exit 10
fi

log "  Reboot gerekmiyor. Tamamlandı."
hr
emit_json
exit 0
