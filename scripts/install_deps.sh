#!/usr/bin/env bash
# ==============================================================================
# cli-panel: Linux Host Dependency & Environment Installer
# Supports: Ubuntu 20.04+, Ubuntu 22.04+, Ubuntu 24.04+, Debian 11+, Debian 12+
# Features: Pre-Flight System Inspection, Single PHP Version & Missing-Only Install
# ==============================================================================

set -euo pipefail

# 1. Root privilege verification
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[!] Error: This installer must be executed as root (sudo)." >&2
    exit 1
fi

echo "========================================================"
echo "⚡ cli-panel: Initializing Linux Environment Installation"
echo "========================================================"
echo ""

# ------------------------------------------------------------------------------
# 2. Pre-Flight System Inspection
# ------------------------------------------------------------------------------
echo "========================================================"
echo "       PRE-FLIGHT SYSTEM INSPECTION (cli-panel)         "
echo "========================================================"

DEFAULT_PHP="8.2"
TARGET_PHP="${DEFAULT_PHP}"
PACKAGES_TO_INSTALL=()
NEED_PHP_REPO=0

# Helper to check commands
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# [A] Nginx & Security Headers Filter Module
if has_cmd nginx; then
    NGINX_VER=$(nginx -v 2>&1 | awk -F'/' '{print $2}' | awk '{print $1}')
    echo "[+] Nginx           : INSTALLED (v${NGINX_VER}) -> Skip reinstall"
else
    echo "[-] Nginx           : NOT FOUND           -> Will install"
    PACKAGES_TO_INSTALL+=("nginx")
fi
if [ ! -f /etc/nginx/modules-enabled/50-mod-http-headers-more-filter.conf ]; then
    PACKAGES_TO_INSTALL+=("libnginx-mod-http-headers-more-filter")
fi

# [B] MariaDB / MySQL
if has_cmd mariadb; then
    MARIA_VER=$(mariadb --version 2>&1 | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+/) print $i}' | head -n1)
    echo "[+] MariaDB/MySQL   : INSTALLED (v${MARIA_VER:-detected}) -> Skip reinstall"
elif has_cmd mysql; then
    MYSQL_VER=$(mysql --version 2>&1 | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+/) print $i}' | head -n1)
    echo "[+] MariaDB/MySQL   : INSTALLED (v${MYSQL_VER:-detected}) -> Skip reinstall"
else
    echo "[-] MariaDB/MySQL   : NOT FOUND           -> Will install"
    PACKAGES_TO_INSTALL+=("mariadb-server")
fi

# [C] PHP & Target Version Detection
if has_cmd php; then
    PHP_FULL_VER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || php -v 2>&1 | awk 'NR==1{print $2}')
    PHP_MM_VER=$(echo "${PHP_FULL_VER}" | cut -d'.' -f1,2)
    TARGET_PHP="${PHP_MM_VER}"
    echo "[+] PHP CLI         : INSTALLED (v${PHP_FULL_VER}) -> Use existing PHP ${TARGET_PHP}"
else
    echo "[-] PHP CLI         : NOT FOUND           -> Will install single version PHP ${DEFAULT_PHP}"
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
fi

# [D] Python3
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
    echo "[-] Certbot         : NOT FOUND           -> Will install"
    PACKAGES_TO_INSTALL+=("certbot" "python3-certbot-nginx")
fi

# [F] Firewall (UFW)
if has_cmd ufw; then
    echo "[+] UFW             : INSTALLED           -> Ready"
else
    echo "[-] UFW             : NOT FOUND           -> Will install"
    PACKAGES_TO_INSTALL+=("ufw")
fi

# [G] Base Utilities
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
# 3. Conditional Package Installation (Install Missing Only)
# ------------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive

if [ ${#PACKAGES_TO_INSTALL[@]} -gt 0 ]; then
    echo "[*] Step 1/5: Installing missing system packages: ${PACKAGES_TO_INSTALL[*]}"

    if has_cmd apt-get; then
        # Setup Ondrej Surý PPA for single PHP if PHP repository is needed
        if [ "${NEED_PHP_REPO}" -eq 1 ]; then
            echo "[*] Adding PHP repository for single-version PHP ${TARGET_PHP}..."
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
    echo "[*] Step 1/5: All core software dependencies are already present. Skipping package installation."
fi

# ------------------------------------------------------------------------------
# 4. Create Standard aaPanel-compatible Directory Scaffold & WAF Snippet
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

# 1. Write Update-Proof Global Nginx Security Configuration (conf.d)
if [ ! -f /etc/nginx/conf.d/00_global_security.conf ]; then
    cat << 'EOF' > /etc/nginx/conf.d/00_global_security.conf
# ==============================================================================
# CLI-PANEL GLOBAL NGINX SECURITY & PERFORMANCE HARDENING
# Persistently loaded in http context across all current & future Nginx versions
# ==============================================================================

server_tokens off;
client_body_timeout 10s;
client_header_timeout 10s;
send_timeout 10s;

# Global Custom Error Page Definitions
error_page 403 /403.html;
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;
EOF
    chmod 644 /etc/nginx/conf.d/00_global_security.conf
fi

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

# ------------------------------------------------------------------------------
# 5. Copy / Link Project to /www/server/panel
# ------------------------------------------------------------------------------
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PANEL_DIR="/www/server/panel"

echo "[*] Step 3/5: Synchronizing panel source code to ${PANEL_DIR}..."
if [ "${CURRENT_DIR}" != "${PANEL_DIR}" ]; then
    cp -ru "${CURRENT_DIR}/"* "${PANEL_DIR}/" || true
fi

# ------------------------------------------------------------------------------
# 6. Virtual Environment & Python Dependencies
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
# 7. Global Command Launcher (mypanel)
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
# 8. Start & Enable Core Services
# ------------------------------------------------------------------------------
echo "[*] Ensuring background daemons are active..."
systemctl enable nginx 2>/dev/null || true
systemctl start nginx 2>/dev/null || true
systemctl enable mariadb 2>/dev/null || systemctl enable mysql 2>/dev/null || true
systemctl start mariadb 2>/dev/null || systemctl start mysql 2>/dev/null || true
systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null || true
systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null || true

# Enable and start single target PHP-FPM service
if [ -n "${TARGET_PHP}" ]; then
    systemctl enable "php${TARGET_PHP}-fpm" 2>/dev/null || systemctl enable php-fpm 2>/dev/null || true
    systemctl start "php${TARGET_PHP}-fpm" 2>/dev/null || systemctl start php-fpm 2>/dev/null || true
fi

echo ""
echo "========================================================"
echo "✓ cli-panel installation completed successfully!"
echo "  - Active PHP Version : PHP ${TARGET_PHP}"
echo "  - Panel Directory    : ${PANEL_DIR}"
echo "  - Modular WAF Rules  : /etc/nginx/waf/waf_default.conf"
echo ""
echo "You can now run your server panel anytime by typing:"
echo "    sudo mypanel"
echo "========================================================"
