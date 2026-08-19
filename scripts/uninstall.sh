#!/usr/bin/env bash
# ==============================================================================
# cli-panel: Linux Host Uninstaller & System Cleanup
# Supports: Ubuntu 20.04+, Ubuntu 22.04+, Ubuntu 24.04+, Debian 11+, Debian 12+
# Features: 2 Purge Levels (Panel Core Only vs Full Purge), Fail-Safe Confirmation
# ==============================================================================

# Handle --help before root check
for arg in "$@"; do
    if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
        echo "Usage: sudo bash scripts/uninstall.sh [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --core-only, -1     Remove panel engine, WAF, and launcher (keeps /www/wwwroot and databases)"
        echo "  --full-purge, -2    Purge all panel data, vhosts, and entire /www directory"
        echo "  -y, --yes           Non-interactive mode (proceed without prompting)"
        echo "  -h, --help          Show this help message"
        exit 0
    fi
done

# 1. Root privilege verification
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[!] Error: This uninstaller must be executed as root (sudo)." >&2
    exit 1
fi

echo "========================================================"
echo "⚠️  cli-panel: Linux Environment Uninstaller"
echo "========================================================"
echo ""

# Helper to check commands
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# 2. Argument Parsing & Non-Interactive Detection
# ------------------------------------------------------------------------------
UNINSTALL_MODE=0
AUTO_YES=0

for arg in "$@"; do
    case "$arg" in
        --core-only|-1)
            UNINSTALL_MODE=1
            ;;
        --full-purge|-2)
            UNINSTALL_MODE=2
            ;;
        -y|--yes|--non-interactive)
            AUTO_YES=1
            ;;
        --help|-h)
            echo "Usage: sudo bash scripts/uninstall.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --core-only, -1     Remove panel engine, WAF, and launcher (keeps /www/wwwroot and databases)"
            echo "  --full-purge, -2    Purge all panel data, vhosts, and entire /www directory"
            echo "  -y, --yes           Non-interactive mode (proceed without prompting)"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
    esac
done

if [ "${UNINSTALL_MODE}" -eq 0 ]; then
    if [ ! -t 0 ] && [ "${AUTO_YES}" -eq 1 ]; then
        UNINSTALL_MODE=1
    else
        echo "Pilih Tingkat Pembersihan (Uninstall Level):"
        echo "  [1] Panel Core Only (Rekomendasi Aman)"
        echo "      -> Menghapus engine panel, CLI launcher 'mypanel', WAF, & konfigurasi panel."
        echo "      -> DATA AMAN: Tetap menyimpan /www/wwwroot, Database, & /www/backup."
        echo ""
        echo "  [2] Full Purge (Hapus Total Tanpa Sisa)"
        echo "      -> Menghapus seluruh folder /www/, semua situs, vhost panel, & backup."
        echo "      -> Server kembali bersih tanpa sisa konfigurasi panel."
        echo ""
        echo "  [3] Batalkan (Exit / Cancel)"
        echo "--------------------------------------------------------"
        read -r -p "Pilih mode uninstall [1-3] (Default: 3 - Batal): " MODE_INPUT </dev/tty || MODE_INPUT="3"
        case "${MODE_INPUT}" in
            1) UNINSTALL_MODE=1 ;;
            2) UNINSTALL_MODE=2 ;;
            *)
                echo "[*] Proses uninstall dibatalkan. Tidak ada perubahan yang dilakukan."
                exit 0
                ;;
        esac
        echo ""
    fi
fi

# ------------------------------------------------------------------------------
# 3. Mode 2 Pre-Confirmation & Emergency Backup
# ------------------------------------------------------------------------------
if [ "${UNINSTALL_MODE}" -eq 2 ]; then
    if [ "${AUTO_YES}" -eq 0 ]; then
        echo "========================================================"
        echo "🚨 PERINGATAN: MODE FULL PURGE AKAN MENGHAPUS SEMUA DATA"
        echo "   - Seluruh direktori /www/ (termasuk /www/wwwroot & website)"
        echo "   - Seluruh berkas backup panel di /www/backup"
        echo "   - Seluruh virtual host Nginx yang dibuat oleh panel"
        echo "========================================================"
        read -r -p "Ketik 'DELETE' untuk konfirmasi penghapusan total: " CONFIRM_INPUT </dev/tty || CONFIRM_INPUT=""
        if [ "${CONFIRM_INPUT}" != "DELETE" ]; then
            echo "[!] Konfirmasi gagal. Proses uninstall dibatalkan."
            exit 1
        fi
        echo ""

        if [ -d "/www/wwwroot" ] && [ "$(ls -A /www/wwwroot 2>/dev/null)" ]; then
            read -r -p "Ingin membuat arsip backup darurat ke /root/ sebelum dihapus? [Y/n]: " BACKUP_ANS </dev/tty || BACKUP_ANS="Y"
            if [ "${BACKUP_ANS:-Y}" != "n" ] && [ "${BACKUP_ANS:-Y}" != "N" ]; then
                BACKUP_TAR="/root/clipanel_emergency_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                echo "[*] Membuat arsip darurat ke ${BACKUP_TAR}..."
                tar -czf "${BACKUP_TAR}" -C /www wwwroot backup 2>/dev/null || tar -czf "${BACKUP_TAR}" -C /www wwwroot 2>/dev/null || true
                echo "    -> Backup darurat berhasil disimpan di: ${BACKUP_TAR}"
                echo ""
            fi
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 4. Execute Core Uninstallation (Common to Mode 1 & 2)
# ------------------------------------------------------------------------------
echo "[*] Step 1: Menghapus executable launcher /usr/local/bin/mypanel..."
rm -f /usr/local/bin/mypanel 2>/dev/null || true

echo "[*] Step 2: Menghapus Web GUI Adminer (jika terpasang)..."
rm -rf /www/server/adminer 2>/dev/null || true
rm -f /etc/nginx/sites-available/00_adminer.conf 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/00_adminer.conf 2>/dev/null || true

echo "[*] Step 3: Menghapus konfigurasi WAF & Default Catch-All Block Nginx..."
rm -rf /etc/nginx/waf 2>/dev/null || true
rm -f /etc/nginx/conf.d/00_default_block.conf 2>/dev/null || true
rm -f /etc/nginx/conf.d/00_global_security.conf 2>/dev/null || true

echo "[*] Step 4: Membersihkan jadwal cron panel..."
if has_cmd crontab; then
    crontab -l 2>/dev/null | grep -v 'mypanel' | grep -v '/www/server/panel' | crontab - 2>/dev/null || true
fi

echo "[*] Step 5: Menghapus direktori inti panel (/www/server/panel)..."
rm -rf /www/server/panel 2>/dev/null || true

# ------------------------------------------------------------------------------
# 5. Execute Full Purge Actions (Mode 2 Only)
# ------------------------------------------------------------------------------
if [ "${UNINSTALL_MODE}" -eq 2 ]; then
    echo "[*] Step 6: Menghapus virtual host situs web Nginx panel..."
    # Hapus semua conf situs kecuali default jika ada
    find /etc/nginx/sites-available/ -type f -name "*.conf" ! -name "default" -exec rm -f {} + 2>/dev/null || true
    find /etc/nginx/sites-enabled/ -type l ! -name "default" -exec rm -f {} + 2>/dev/null || true

    echo "[*] Step 7: Menghapus seluruh direktori /www..."
    rm -rf /www 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 6. Reload Nginx Service
# ------------------------------------------------------------------------------
if has_cmd nginx; then
    echo "[*] Menguji dan memuat ulang konfigurasi Nginx..."
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || true
    else
        echo "[!] Peringatan: Konfigurasi Nginx memiliki peringatan sintaks. Silakan periksa dengan 'sudo nginx -t'."
    fi
fi

# ------------------------------------------------------------------------------
# 7. Summary & Completion Notice
# ------------------------------------------------------------------------------
echo ""
echo "========================================================"
if [ "${UNINSTALL_MODE}" -eq 1 ]; then
    echo "✓ cli-panel berhasil di-uninstall (Mode: Core Only)!"
    echo "  - Panel Engine, Launcher, & WAF telah dibersihkan."
    echo "  - Berkas website (/www/wwwroot) & Database MariaDB TETAP AMAN."
else
    echo "✓ cli-panel berhasil di-uninstall total (Mode: Full Purge)!"
    echo "  - Seluruh direktori /www & konfigurasi vhost panel telah dihapus."
    echo "  - Server telah bersih dari sisa instalasi panel."
fi
echo "========================================================"
