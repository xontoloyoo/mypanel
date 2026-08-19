#!/usr/bin/env bash
# ==============================================================================
# cli-panel: Linux Host Dependency & Environment Installer
# Supports: Ubuntu 20.04+, Ubuntu 22.04+, Ubuntu 24.04+, Debian 11+, Debian 12+
# Features: Interactive Mode Selection, Missing-Only Install, Modular WAF & Venv
# ==============================================================================

set -euo pipefail

# 1. Root privilege verification
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[!] Error: This installer must be executed as root (sudo)." >&2
    exit 1
fi

echo "========================================================"
echo "⚡ cli-panel: Linux Environment Installation"
echo "========================================================"
echo ""

# Helper to check commands
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# 2. Interactive Installation Mode Selection
# ------------------------------------------------------------------------------
NON_INTERACTIVE=0
for arg in "$@"; do
    if [ "$arg" = "-y" ] || [ "$arg" = "--yes" ] || [ "$arg" = "--non-interactive" ]; then
        NON_INTERACTIVE=1
    fi
done

if [ ! -t 0 ]; then
    NON_INTERACTIVE=1
fi

INSTALL_MODE=1

if [ "${NON_INTERACTIVE}" -eq 0 ]; then
    echo "Pilih Mode Instalasi:"
    echo "  [1] Express Auto-Install (Rekomendasi: Otomatis pasang semua dependensi yang belum ada)"
    echo "  [2] Custom / Interactive (Tanya satu per satu komponen yang ingin dipasang/di-skip)"
    echo "  [3] Panel Core Only      (Hanya siapkan direktori /www/, venv, WAF, & launcher - software diinstall manual)"
    echo "--------------------------------------------------------"
    read -r -p "Pilih mode [1-3] (Default: 1): " MODE_INPUT </dev/tty || MODE_INPUT="1"
    case "${MODE_INPUT}" in
        2) INSTALL_MODE=2 ;;
        3) INSTALL_MODE=3 ;;
        *) INSTALL_MODE=1 ;;
    esac
    echo ""
fi

# ------------------------------------------------------------------------------
# 3. Pre-Flight System Inspection
# ------------------------------------------------------------------------------
echo "========================================================"
echo "       PRE-FLIGHT SYSTEM INSPECTION (cli-panel)         "
echo "========================================================"

DEFAULT_PHP="8.2"
TARGET_PHP="${DEFAULT_PHP}"
PACKAGES_TO_INSTALL=()
NEED_PHP_REPO=0

# [A] Nginx Inspection
if has_cmd nginx; then
    NGINX_VER=$(nginx -v 2>&1 | awk -F'/' '{print $2}' | awk '{print $1}')
    echo "[+] Nginx           : INSTALLED (v${NGINX_VER}) -> Skip reinstall"
else
    echo "[-] Nginx           : NOT FOUND"
    if [ "${INSTALL_MODE}" -eq 1 ]; then
        PACKAGES_TO_INSTALL+=("nginx")
    elif [ "${INSTALL_MODE}" -eq 2 ]; then
        read -r -p "    [?] Nginx belum ada. Install Nginx via apt repository? [Y/n]: " ANS </dev/tty || ANS="Y"
        if [ "${ANS:-Y}" != "n" ] && [ "${ANS:-Y}" != "N" ]; then
            PACKAGES_TO_INSTALL+=("nginx")
        else
            echo "        -> Nginx dilewati (akan diinstall manual oleh Anda)"
        fi
    fi
fi

# [B] MariaDB / MySQL Inspection
if has_cmd mariadb; then
    MARIA_VER=$(mariadb --version 2>&1 | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+/) print $i}' | head -n1)
    echo "[+] MariaDB/MySQL   : INSTALLED (v${MARIA_VER:-detected}) -> Skip reinstall"
elif has_cmd mysql; then
    MYSQL_VER=$(mysql --version 2>&1 | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+/) print $i}' | head -n1)
    echo "[+] MariaDB/MySQL   : INSTALLED (v${MYSQL_VER:-detected}) -> Skip reinstall"
else
    echo "[-] MariaDB/MySQL   : NOT FOUND"
    if [ "${INSTALL_MODE}" -eq 1 ]; then
        PACKAGES_TO_INSTALL+=("mariadb-server")
    elif [ "${INSTALL_MODE}" -eq 2 ]; then
        read -r -p "    [?] MariaDB/MySQL belum ada. Install MariaDB via apt repository? [Y/n]: " ANS </dev/tty || ANS="Y"
        if [ "${ANS:-Y}" != "n" ] && [ "${ANS:-Y}" != "N" ]; then
            PACKAGES_TO_INSTALL+=("mariadb-server")
        else
            echo "        -> MariaDB dilewati (akan diinstall manual oleh Anda)"
        fi
    fi
fi

# [C] PHP & Target Version Detection
if has_cmd php; then
    PHP_FULL_VER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || php -v 2>&1 | awk 'NR==1{print $2}')
    PHP_MM_VER=$(echo "${PHP_FULL_VER}" | cut -d'.' -f1,2)
    TARGET_PHP="${PHP_MM_VER}"
    echo "[+] PHP CLI         : INSTALLED (v${PHP_FULL_VER}) -> Use existing PHP ${TARGET_PHP}"
else
    echo "[-] PHP CLI         : NOT FOUND"
    if [ "${INSTALL_MODE}" -eq 1 ]; then
        TARGET_PHP="${DEFAULT_PHP}"
        NEED_PHP_REPO=1
        PACKAGES_TO_INSTALL+=(
            "php${TARGET_PHP}-fpm"
            "php${TARGET_PHP}-mysql"
            "php${TARGET_PHP}-curl"
            "php${TARGET_PHP}-gd"
            "php${TARGET_PHP}-mbstring"
            "php${TARGET_PHP}-xml"
            "php${TARGET_PHP}-zip"
            "php${TARGET_PHP}-opcache"
            "php${TARGET_PHP}-cli"
        )
    elif [ "${INSTALL_MODE}" -eq 2 ]; then
        read -r -p "    [?] PHP belum ada. Install PHP & PHP-FPM via repository PPA? [Y/n]: " ANS </dev/tty || ANS="Y"
        if [ "${ANS:-Y}" != "n" ] && [ "${ANS:-Y}" != "N" ]; then
            read -r -p "        Pilih versi PHP (misal: 8.1, 8.2, 8.3, 8.4) [Default: ${DEFAULT_PHP}]: " VER_INPUT </dev/tty || VER_INPUT="${DEFAULT_PHP}"
            TARGET_PHP="${VER_INPUT:-$DEFAULT_PHP}"
            NEED_PHP_REPO=1
            PACKAGES_TO_INSTALL+=(
                "php${TARGET_PHP}-fpm"
                "php${TARGET_PHP}-mysql"
                "php${TARGET_PHP}-curl"
                "php${TARGET_PHP}-gd"
                "php${TARGET_PHP}-mbstring"
                "php${TARGET_PHP}-xml"
                "php${TARGET_PHP}-zip"
                "php${TARGET_PHP}-opcache"
                "php${TARGET_PHP}-cli"
            )
        else
            TARGET_PHP=""
            echo "        -> PHP dilewati (akan diinstall manual oleh Anda)"
        fi
    else
        TARGET_PHP=""
    fi
fi

# [D] Python3 Inspection (Mandatory for CLI Panel engine)
if has_cmd python3; then
    PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    echo "[+] Python3         : INSTALLED (v${PY_VER}) -> Ready"
    if ! python3 -m venv --help >/dev/null 2>&1; then
        PACKAGES_TO_INSTALL+=("python3-venv")
    fi
    if ! has_cmd pip3 && ! python3 -m pip --version >/dev/null 2>&1; then
        PACKAGES_TO_INSTALL+=("python3-pip")
    fi
else
    echo "[-] Python3         : NOT FOUND           -> Will install"
    PACKAGES_TO_INSTALL+=("python3" "python3-venv" "python3-pip")
fi

# [E] Certbot & SSL
if has_cmd certbot; then
    CERTBOT_VER=$(certbot --version 2>&1 | awk '{print $2}')
    echo "[+] Certbot         : INSTALLED (v${CERTBOT_VER:-detected}) -> Ready"
else
    echo "[-] Certbot         : NOT FOUND"
    if [ "${INSTALL_MODE}" -eq 1 ]; then
        PACKAGES_TO_INSTALL+=("certbot" "python3-certbot-nginx")
    elif [ "${INSTALL_MODE}" -eq 2 ]; then
        read -r -p "    [?] Certbot belum ada. Install Certbot (Let's Encrypt)? [Y/n]: " ANS </dev/tty || ANS="Y"
        if [ "${ANS:-Y}" != "n" ] && [ "${ANS:-Y}" != "N" ]; then
            PACKAGES_TO_INSTALL+=("certbot" "python3-certbot-nginx")
        else
            echo "        -> Certbot dilewati"
        fi
    fi
fi

# [F] Firewall (UFW)
if has_cmd ufw; then
    echo "[+] UFW             : INSTALLED           -> Ready"
else
    echo "[-] UFW             : NOT FOUND"
    if [ "${INSTALL_MODE}" -eq 1 ]; then
        PACKAGES_TO_INSTALL+=("ufw")
    elif [ "${INSTALL_MODE}" -eq 2 ]; then
        read -r -p "    [?] UFW Firewall belum ada. Install UFW? [Y/n]: " ANS </dev/tty || ANS="Y"
        if [ "${ANS:-Y}" != "n" ] && [ "${ANS:-Y}" != "N" ]; then
            PACKAGES_TO_INSTALL+=("ufw")
        else
            echo "        -> UFW dilewati"
        fi
    fi
fi

# [G] Base Utilities (Required Core Tools)
for util in cron tar gzip sqlite3 curl git; do
    if has_cmd "$util"; then
        echo "[+] Util (${util})    : INSTALLED           -> Ready"
    else
        echo "[-] Util (${util})    : NOT FOUND           -> Will install"
        if [ "$util" = "cron" ]; then
            PACKAGES_TO_INSTALL+=("cron")
        elif [ "$util" = "sqlite3" ]; then
            PACKAGES_TO_INSTALL+=("sqlite3")
        else
            PACKAGES_TO_INSTALL+=("$util")
        fi
    fi
done

echo "========================================================"
echo ""

# ------------------------------------------------------------------------------
# 4. Conditional Package Installation (Install Missing Only)
# ------------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive

if [ ${#PACKAGES_TO_INSTALL[@]} -gt 0 ]; then
    echo "[*] Step 1/5: Installing selected system packages: ${PACKAGES_TO_INSTALL[*]}"

    if has_cmd apt-get; then
        # Setup Ondrej Surý PPA for single PHP if PHP repository is needed
        if [ "${NEED_PHP_REPO}" -eq 1 ]; then
            echo "[*] Adding PHP repository for PHP ${TARGET_PHP}..."
            apt-get update -y
            apt-get install -y software-properties-common ca-certificates lsb-release apt-transport-https

            if has_cmd add-apt-repository; then
                add-apt-repository -y ppa:ondrej/php || true
            else
                # Debian fallback for Ondrej Surý repo
                if [ -f /etc/debian_version ]; then
                    curl -sSLo /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg || true
                    echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list || true
                fi
            fi
        fi

        apt-get update -y
        apt-get install -y "${PACKAGES_TO_INSTALL[@]}"
    elif has_cmd dnf; then
        dnf update -y
        dnf install -y "${PACKAGES_TO_INSTALL[@]}"
    else
        echo "[!] Unsupported package manager. Please install packages manually: ${PACKAGES_TO_INSTALL[*]}"
        exit 1
    fi
else
    echo "[*] Step 1/5: No additional packages to install. Continuing with panel configuration."
fi

# ------------------------------------------------------------------------------
# 5. Create Standard aaPanel-compatible Directory Scaffold & WAF Snippet
# ------------------------------------------------------------------------------
echo "[*] Step 2/5: Creating standard directory layout & Nginx WAF (/www/ & /etc/nginx/waf)..."
mkdir -p /www/wwwroot
mkdir -p /www/wwwlogs
mkdir -p /www/server/panel/templates/errors
mkdir -p /www/backup/site
mkdir -p /www/backup/database
mkdir -p /www/backup/migration
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled
mkdir -p /etc/nginx/conf.d
mkdir -p /etc/nginx/waf
mkdir -p /etc/letsencrypt/live

# Set permissions
chmod 755 /www /www/wwwroot /www/wwwlogs /www/backup /www/backup/site /www/backup/database /www/backup/migration

# Clean up any legacy conflicting global security file in conf.d
rm -f /etc/nginx/conf.d/00_global_security.conf 2>/dev/null || true

# 2. Write default Modular WAF rules
if [ ! -f /etc/nginx/waf/waf_default.conf ]; then
    cat << 'EOF' > /etc/nginx/waf/waf_default.conf
# ==============================================================================
# CLI-PANEL MODULAR WAF & SCANNER PROTECTION
# ==============================================================================

# 1. Sensitive Files & Executable Protection (JSON & XML dikecualikan untuk API/Sitemap)
location ~* \.(env|git|svn|htaccess|user\.ini|yaml|yml|sql|bak|log|sh|conf|jar|aspx|cgi)$ {
    return 444;
}

# 2. Path Traversal, Null Byte & RCE Exploitation
if ($request_uri ~* "(/\.|%2e%2e|%2fetc%2fpasswd|/etc/passwd|/bin/sh|%00)") {
    return 444;
}

# 3. Scanner Drop (Framework, Backdoor, & CMS Bot Hunter)
if ($request_uri ~* "^/(wp-admin|wp-login|actuator|owa|ecp|cgi-bin|v2/_catalog|geoserver|\+CSCOE\+|\+CSCOL\+)") {
    return 444;
}

# 4. SQLi, XSS, PHP Injections, & Debugger in Query String
if ($query_string ~* "(union.*select|select.*from|cmd=|pearcmd|invokefunction|call_user_func|proc_open|shell_exec|XDEBUG_SESSION)") {
    return 444;
}
EOF
    chmod 644 /etc/nginx/waf/waf_default.conf
fi

# 3. Write default catch-all drop block for direct IP / wild domains
if [ ! -f /etc/nginx/conf.d/00_default_block.conf ]; then
    cat << 'EOF' > /etc/nginx/conf.d/00_default_block.conf
# Blok penangkap semua trafik liar/IP langsung
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
EOF
    chmod 644 /etc/nginx/conf.d/00_default_block.conf
fi

# ------------------------------------------------------------------------------
# 6. Copy / Link Project to /www/server/panel
# ------------------------------------------------------------------------------
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PANEL_DIR="/www/server/panel"

echo "[*] Step 3/5: Synchronizing panel source code to ${PANEL_DIR}..."
if [ "${CURRENT_DIR}" != "${PANEL_DIR}" ]; then
    cp -ru "${CURRENT_DIR}/"* "${PANEL_DIR}/" || true
fi

# Ensure web templates directory is readable by Nginx daemon (www-data)
if [ -d "${PANEL_DIR}/templates" ]; then
    chmod -R 755 "${PANEL_DIR}/templates" 2>/dev/null || true
    chmod -R 644 "${PANEL_DIR}/templates/errors/"*.html 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 7. Virtual Environment & Python Dependencies
# ------------------------------------------------------------------------------
echo "[*] Step 4/5: Initializing Python virtual environment (.venv)..."
cd "${PANEL_DIR}"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

# Activate and install requirements
.venv/bin/pip install --upgrade pip --quiet
.venv/bin/pip install -r requirements.txt --quiet

# ------------------------------------------------------------------------------
# 8. Global Command Launcher (mypanel)
# ------------------------------------------------------------------------------
echo "[*] Step 5/5: Configuring global CLI executable '/usr/local/bin/mypanel'..."
cat << 'EOF' > /usr/local/bin/mypanel
#!/usr/bin/env bash
PANEL_DIR="/www/server/panel"
if [ ! -d "${PANEL_DIR}" ]; then
    echo "[!] Error: Panel directory ${PANEL_DIR} not found." >&2
    exit 1
fi
cd "${PANEL_DIR}"
exec "${PANEL_DIR}/.venv/bin/python" "${PANEL_DIR}/app/main.py" "$@"
EOF

chmod +x /usr/local/bin/mypanel

# ------------------------------------------------------------------------------
# 9. Start & Enable Core Services
# ------------------------------------------------------------------------------
echo "[*] Ensuring background daemons are active..."
if has_cmd nginx; then
    systemctl enable nginx 2>/dev/null || true
    systemctl start nginx 2>/dev/null || true
fi

if has_cmd mariadb; then
    systemctl enable mariadb 2>/dev/null || true
    systemctl start mariadb 2>/dev/null || true
elif has_cmd mysql; then
    systemctl enable mysql 2>/dev/null || true
    systemctl start mysql 2>/dev/null || true
fi

if has_cmd cron; then
    systemctl enable cron 2>/dev/null || true
    systemctl start cron 2>/dev/null || true
elif has_cmd crond; then
    systemctl enable crond 2>/dev/null || true
    systemctl start crond 2>/dev/null || true
fi

# Enable and start single target PHP-FPM service if configured
if [ -n "${TARGET_PHP}" ]; then
    systemctl enable "php${TARGET_PHP}-fpm" 2>/dev/null || systemctl enable php-fpm 2>/dev/null || true
    systemctl start "php${TARGET_PHP}-fpm" 2>/dev/null || systemctl start php-fpm 2>/dev/null || true
fi

echo ""
echo "========================================================"
echo "✓ cli-panel installation completed successfully!"
if [ -n "${TARGET_PHP}" ]; then
    echo "  - Active PHP Version : PHP ${TARGET_PHP}"
else
    echo "  - Active PHP Version : (Manual installation chosen)"
fi
echo "  - Panel Directory    : ${PANEL_DIR}"
echo "  - Modular WAF Rules  : /etc/nginx/waf/waf_default.conf"
echo "  - Default Block Rule : /etc/nginx/conf.d/00_default_block.conf"
echo ""
echo "You can now run your server panel anytime by typing:"
echo "    sudo mypanel"
echo "========================================================"
