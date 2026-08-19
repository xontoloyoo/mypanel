"""Site management module for Nginx and web server virtual hosts."""

import base64
from collections import deque
import hashlib
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

from app.core.database import Database, generate_short_id, get_db
from app.core.executor import run_cmd
from app.core.logger import BASE_DIR, get_logger

logger = get_logger("site")

# Domain validation regex: matches standard FQDNs and subdomains, plus localhost/dev domains
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$|^localhost$"
)

# Standard Modular WAF & Scanner Protection Snippet
WAF_DEFAULT_CONFIG = """# ==============================================================================
# CLI-PANEL MODULAR WAF & SCANNER PROTECTION
# ==============================================================================

# 1. Sensitive Files & Executable Protection (JSON & XML dikecualikan untuk API/Sitemap)
location ~* \\.(env|git|svn|htaccess|user\\.ini|yaml|yml|sql|bak|log|sh|conf|jar|aspx|cgi)$ {
    return 444;
}

# 2. Path Traversal, Null Byte & RCE Exploitation
if ($request_uri ~* "(/\\.|%2e%2e|%2fetc%2fpasswd|/etc/passwd|/bin/sh|%00)") {
    return 444;
}

# 3. Scanner Drop (Framework, Backdoor, & CMS Bot Hunter)
if ($request_uri ~* "^/(wp-admin|wp-login|actuator|owa|ecp|cgi-bin|v2/_catalog|geoserver|\\+CSCOE\\+|\\+CSCOL\\+)") {
    return 444;
}

# 4. SQLi, XSS, PHP Injections, & Debugger in Query String
if ($query_string ~* "(union.*select|select.*from|cmd=|pearcmd|invokefunction|call_user_func|proc_open|shell_exec|XDEBUG_SESSION)") {
    return 444;
}
"""

DEFAULT_BLOCK_CONFIG = """# Blok penangkap semua trafik liar/IP langsung
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
"""


def ensure_waf_snippet(waf_path: Optional[Path] = None) -> Path:
    """Ensure the centralized WAF snippet file exists on the host.

    Args:
        waf_path: Target path for the WAF file (optional).

    Returns:
        Path: Resolved Path to the WAF snippet file.
    """
    if waf_path:
        target = waf_path
    else:
        primary = Path("/etc/nginx/waf/waf_default.conf")
        fallback = BASE_DIR / "data" / "mock_config" / "waf_default.conf"
        target = primary if (primary.parent.exists() or os.name != "nt") else fallback

    try:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(WAF_DEFAULT_CONFIG, encoding="utf-8")
            logger.info("Created WAF default snippet at %s", target)
    except Exception as exc:
        logger.warning("Could not create default WAF snippet at '%s': %s", target, exc)

    return target


def ensure_default_block_config(conf_d_dir: Optional[Path] = None) -> Path:
    """Ensure the centralized 00_default_block.conf file exists in conf.d.

    Args:
        conf_d_dir: Target directory for conf.d (optional).

    Returns:
        Path: Resolved Path to 00_default_block.conf.
    """
    if conf_d_dir:
        target = conf_d_dir / "00_default_block.conf" if conf_d_dir.is_dir() else conf_d_dir
    else:
        primary = Path("/etc/nginx/conf.d/00_default_block.conf")
        fallback = BASE_DIR / "data" / "mock_config" / "00_default_block.conf"
        target = primary if (primary.parent.exists() or os.name != "nt") else fallback

    try:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(DEFAULT_BLOCK_CONFIG, encoding="utf-8")
            logger.info("Created Nginx default block config at %s", target)
    except Exception as exc:
        logger.warning("Could not create default block config at '%s': %s", target, exc)

    return target


class SiteManager:
    """Manager for Nginx web server virtual hosts and database synchronization."""

    def __init__(
        self,
        webroot_base: str = "/www/wwwroot",
        nginx_available: str = "/etc/nginx/sites-available",
        nginx_enabled: str = "/etc/nginx/sites-enabled",
        db: Optional[Database] = None,
    ) -> None:
        """Initialize SiteManager with configurable paths for flexibility and testing.

        Args:
            webroot_base: Base directory for website roots.
            nginx_available: Nginx sites-available directory.
            nginx_enabled: Nginx sites-enabled directory.
            db: Database instance (optional).
        """
        self.webroot_base = webroot_base
        self.nginx_available = nginx_available
        self.nginx_enabled = nginx_enabled
        self.db = db or get_db()
        # Ensure default WAF rule file and default catch-all block are prepared
        ensure_waf_snippet()
        ensure_default_block_config()

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate format of a given domain name.

        Args:
            domain: Domain name string.

        Returns:
            bool: True if domain format is valid, False otherwise.
        """
        if not domain or len(domain) > 253:
            return False
        return bool(DOMAIN_REGEX.match(domain.strip().lower()))

    def _generate_nginx_config(
        self,
        domain: str,
        root_path: str,
        php_version: str = "none",
    ) -> str:
        """Generate virtual host Nginx configuration string.

        Args:
            domain: Website domain name.
            root_path: Absolute directory root path.
            php_version: PHP version to attach, or 'none' for static HTML.

        Returns:
            str: Generated Nginx server block configuration.
        """
        clean_domain = domain.strip().lower()

        php_block = ""
        is_php = bool(php_version and php_version.lower() != "none")
        if is_php:
            php_sock = f"/run/php/php{php_version}-fpm.sock"
            php_block = f"""
    # PHP-FPM FastCGI Configuration
    location ~ \\.php$ {{
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\\.php)(/.+)$;
        fastcgi_pass unix:{php_sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        include fastcgi_params;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_intercept_errors on;
    }}"""

        routing_block = """    # Standard Application Routing (Framework & Permalinks Friendly)
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }""" if is_php else """    # Standard Application Routing (Static HTML)
    location / {
        try_files $uri $uri/ =404;
    }"""

        config = f"""server {{
    listen 80;
    listen [::]:80;

    server_name {clean_domain};
    root {root_path};
    index index.php index.html index.htm;
    charset utf-8;
    ssi on;

    # Include Modular WAF Protection
    include /etc/nginx/waf/waf_default.conf;

    # Server Identity Cloaking & Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # ACME Challenge Directory Verification for Let's Encrypt SSL
    location ~ /\\.well-known {{
        allow all;
    }}
    if ($uri ~ "^/\\.well-known/.*\\.(php|jsp|py|js|css|lua|ts|go|zip|tar\\.gz|rar|7z|sql|bak)$") {{
        return 403;
    }}

    # Static Assets Browser Caching & Log Suppression
    location ~* \\.(gif|jpg|jpeg|png|bmp|swf|ico|webp|svg|woff|woff2|ttf|eot)$ {{
        expires 30d;
        access_log off;
    }}

    location ~* \\.(js|css)$ {{
        expires 12h;
        access_log off;
    }}

    # =========================================================================
    # [CUSTOM USER RULES & ROUTING SECTION]
    # Anda dapat menambahkan rule kustom di bawah ini (misal: reverse proxy,
    # redirect khusus, atau sub-location) tanpa khawatir bentrok dengan sistem.
    # Contoh Reverse Proxy:
    # location /api/ {{
    #     proxy_pass http://127.0.0.1:3000;
    #     proxy_set_header Host $host;
    # }}
    # =========================================================================

{routing_block}
{php_block}

    # Unified Custom Error Pages via SSI
    error_page 403 404 500 502 503 504 /error.html;

    location = /error.html {{
        internal;
        root /www/server/panel/templates/errors;
    }}

    location ~ /\\.ht {{
        deny all;
    }}

    access_log /var/log/nginx/{domain}_access.log;
    error_log /var/log/nginx/{domain}_error.log;
}}
"""
        return config

    def _create_placeholder_index(self, root_path: str, domain: str, php_version: str) -> None:
        """Create a styled HTML placeholder page if no index file exists.

        Args:
            root_path: Website root directory.
            domain: Domain name.
            php_version: Assigned PHP version.
        """
        index_html = Path(root_path) / "index.html"
        index_php = Path(root_path) / "index.php"

        if not index_html.exists() and not index_php.exists():
            php_info = f"PHP {php_version}" if php_version and php_version.lower() != "none" else "Static HTML"
            content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to {domain}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #0f172a;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1.5rem;
        }}
        .card {{
            background: #1e293b;
            padding: 3rem 2.5rem;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            text-align: center;
            max-width: 520px;
            width: 100%;
            border: 1px solid #334155;
        }}
        .logo {{
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.75rem;
        }}
        p {{
            color: #94a3b8;
            font-size: 1rem;
            line-height: 1.6;
            margin-bottom: 1.5rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.35rem 0.9rem;
            background: #0369a1;
            color: #e0f2fe;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .footer {{
            margin-top: 2rem;
            font-size: 0.8rem;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">{domain}</div>
        <p>Your new site has been successfully initialized and configured with <strong>cli-panel</strong>.</p>
        <span class="badge">{php_info}</span>
        <div class="footer">Managed by cli-panel Engine</div>
    </div>
</body>
</html>
"""
            try:
                index_html.write_text(content, encoding="utf-8")
                logger.debug("Created placeholder index.html at %s", index_html)
            except Exception as exc:
                logger.warning("Could not write placeholder index.html: %s", exc)

    def _reload_nginx(self) -> Tuple[bool, str]:
        """Test syntax and reload Nginx daemon."""
        test_res = run_cmd("nginx -t")
        if not test_res.success:
            # Check if nginx binary simply doesn't exist (e.g. non-Linux / test environment)
            if "not found" in test_res.stderr.lower() or "not recognized" in test_res.stderr.lower():
                logger.debug("Nginx not installed in current environment. Skipping reload.")
                return True, "Nginx binary not found (skipped reload)"
            logger.error("Nginx configuration test failed: %s", test_res.stderr)
            return False, f"Nginx test failed: {test_res.stderr}"

        reload_res = run_cmd("systemctl reload nginx")
        if not reload_res.success:
            logger.warning("Failed to reload Nginx via systemctl: %s", reload_res.stderr)
            return False, f"Failed to reload Nginx: {reload_res.stderr}"

        return True, "Nginx reloaded successfully"

    def create_site(
        self,
        domain: str,
        root_path: Optional[str] = None,
        php_version: str = "none",
    ) -> Tuple[bool, str]:
        """Create a new website virtual host, directory structure, and database record.

        Args:
            domain: Website domain name.
            root_path: Custom webroot path. Defaults to /www/wwwroot/<domain>.
            php_version: PHP version to link with fastcgi (default: 'none').

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        domain = domain.strip().lower()

        # 1. Domain format validation
        if not self.validate_domain(domain):
            return False, f"Invalid domain name format: '{domain}'"

        # 2. Check duplicate domain in DB
        existing = self.get_site(domain)
        if existing:
            return False, f"Domain '{domain}' already exists in database."

        # 3. Determine web root (always enforce absolute path under webroot_base if relative)
        if root_path and os.path.isabs(root_path):
            target_root = os.path.abspath(root_path)
        elif root_path:
            target_root = os.path.abspath(os.path.join(self.webroot_base, root_path))
        else:
            target_root = os.path.abspath(os.path.join(self.webroot_base, domain))

        try:
            # 4. Create root directory & placeholder
            os.makedirs(target_root, exist_ok=True)
            self._create_placeholder_index(target_root, domain, php_version)

            # 5. Generate and write Nginx vhost config
            vhost_content = self._generate_nginx_config(domain, target_root, php_version)
            avail_dir = Path(self.nginx_available)
            enabled_dir = Path(self.nginx_enabled)

            # Ensure nginx config directories exist if writable/local
            if avail_dir.parent.exists() or os.name == "nt":
                avail_dir.mkdir(parents=True, exist_ok=True)
                vhost_file = avail_dir / f"{domain}.conf"
                vhost_file.write_text(vhost_content, encoding="utf-8")

                # 6. Create symlink in sites-enabled
                enabled_dir.mkdir(parents=True, exist_ok=True)
                symlink_file = enabled_dir / f"{domain}.conf"
                if symlink_file.exists() or symlink_file.is_symlink():
                    symlink_file.unlink()

                try:
                    if hasattr(os, "symlink"):
                        os.symlink(str(vhost_file), str(symlink_file))
                except Exception as sym_exc:
                    logger.debug("Symlink creation skipped or unsupported: %s", sym_exc)

            # 7. Reload Nginx
            reload_ok, reload_msg = self._reload_nginx()
            if not reload_ok:
                logger.warning("Nginx reload returned warning: %s", reload_msg)

            # 8. Insert record into database
            site_id = generate_short_id()
            with self.db:
                self.db.execute(
                    """
                    INSERT INTO sites (id, domain, root_path, php_version, ssl_status)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (site_id, domain, target_root, php_version, 0),
                )

            logger.info("Site '%s' successfully created with root '%s'", domain, target_root)
            return True, f"Site '{domain}' successfully created."

        except Exception as exc:
            err_msg = f"Failed to create site '{domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def delete_site(self, domain: str, delete_root: bool = False) -> Tuple[bool, str]:
        """Delete an existing website virtual host, configuration, and database record.

        Args:
            domain: Domain name to delete.
            delete_root: Whether to delete the web document root folder from disk.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        domain = domain.strip().lower()
        site = self.get_site(domain)
        if not site:
            return False, f"Site '{domain}' not found in database."

        try:
            # 1. Remove Nginx enabled symlink and available vhost
            enabled_file = Path(self.nginx_enabled) / f"{domain}.conf"
            available_file = Path(self.nginx_available) / f"{domain}.conf"

            if enabled_file.exists() or enabled_file.is_symlink():
                enabled_file.unlink()

            if available_file.exists():
                available_file.unlink()

            # 2. Reload Nginx
            self._reload_nginx()

            # 3. Delete root folder if requested
            if delete_root and site.get("root_path"):
                root_dir = Path(site["root_path"])
                if root_dir.exists() and root_dir.is_dir():
                    shutil.rmtree(root_dir)
                    logger.info("Deleted root directory for site '%s': %s", domain, root_dir)

            # 4. Remove database record
            with self.db:
                self.db.execute("DELETE FROM sites WHERE domain = ?;", (domain,))

            logger.info("Site '%s' successfully deleted.", domain)
            return True, f"Site '{domain}' successfully deleted."

        except Exception as exc:
            err_msg = f"Failed to delete site '{domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def sync_existing_sites(self) -> Tuple[int, List[str]]:
        """Scan Nginx virtual hosts and webroots on disk to synchronize missing sites into SQLite database.

        Returns:
            Tuple[int, List[str]]: (Count of newly synced sites, List of synced domain names).
        """
        synced: List[str] = []
        known_domains = {s["domain"].lower() for s in self.list_sites(auto_sync=False)}

        candidate_dirs = [
            Path(self.nginx_available),
            Path("/etc/nginx/sites-available"),
            Path("/etc/nginx/conf.d"),
        ]

        for c_dir in candidate_dirs:
            if not c_dir.exists() or not c_dir.is_dir():
                continue

            for conf_file in c_dir.glob("*.conf"):
                stem = conf_file.stem.lower()
                if stem in ("default", "000-default", "waf_default", "mock_config"):
                    continue

                domain = stem
                if not self.validate_domain(domain):
                    try:
                        content = conf_file.read_text(encoding="utf-8")
                        m = re.search(r"server_name\s+([^;]+);", content)
                        if m:
                            extracted = m.group(1).strip().split()[0].lower()
                            if self.validate_domain(extracted):
                                domain = extracted
                    except Exception:
                        pass

                if not self.validate_domain(domain) or domain in known_domains:
                    continue

                root_path = os.path.join(self.webroot_base, domain)
                php_ver = "none"
                ssl_status = 0

                try:
                    content = conf_file.read_text(encoding="utf-8")
                    root_m = re.search(r"root\s+([^;]+);", content)
                    if root_m:
                        parsed_root = root_m.group(1).strip()
                        if parsed_root:
                            root_path = parsed_root

                    php_m = re.search(r"php(\d+\.\d+)-fpm\.sock", content)
                    if php_m:
                        php_ver = php_m.group(1)

                    if "listen 443" in content or "ssl_certificate" in content:
                        ssl_status = 1
                except Exception as exc:
                    logger.debug("Could not parse vhost file '%s': %s", conf_file, exc)

                try:
                    with self.db:
                        self.db.execute(
                            """
                            INSERT OR IGNORE INTO sites (domain, root_path, php_version, ssl_status)
                            VALUES (?, ?, ?, ?);
                            """,
                            (domain, root_path, php_ver, ssl_status),
                        )
                    known_domains.add(domain)
                    synced.append(domain)
                    logger.info("Auto-synced existing site from Nginx vhost: %s (%s)", domain, root_path)
                except Exception as exc:
                    logger.warning("Failed to insert synced site '%s': %s", domain, exc)

        # Also inspect webroot directory for folders matching domain format
        webroot_p = Path(self.webroot_base)
        if webroot_p.exists() and webroot_p.is_dir():
            try:
                for entry in webroot_p.iterdir():
                    if entry.is_dir() and self.validate_domain(entry.name):
                        dom = entry.name.lower()
                        if dom not in known_domains:
                            try:
                                with self.db:
                                    self.db.execute(
                                        """
                                        INSERT OR IGNORE INTO sites (domain, root_path, php_version, ssl_status)
                                        VALUES (?, ?, ?, ?);
                                        """,
                                        (dom, str(entry), "none", 0),
                                    )
                                known_domains.add(dom)
                                synced.append(dom)
                                logger.info("Auto-synced existing site from webroot folder: %s", dom)
                            except Exception as exc:
                                logger.warning("Failed to insert synced webroot '%s': %s", dom, exc)
            except Exception as exc:
                logger.debug("Could not inspect webroot directory: %s", exc)

        return len(synced), synced

    def list_sites(self, auto_sync: bool = True) -> List[Dict[str, Any]]:
        """Retrieve all registered websites from database.

        Args:
            auto_sync: Whether to auto-discover and synchronize unindexed Nginx vhosts/webroots.

        Returns:
            List[Dict[str, Any]]: List of website dictionaries.
        """
        if auto_sync:
            try:
                self.sync_existing_sites()
            except Exception as exc:
                logger.debug("Auto-sync skipped or failed: %s", exc)

        try:
            with self.db:
                records = self.db.fetch_all(
                    """
                    SELECT id, domain, root_path, php_version, ssl_status, created_at
                    FROM sites
                    ORDER BY id DESC;
                    """
                )
                return records
        except Exception as exc:
            logger.error("Failed to fetch sites list: %s", exc)
            return []

    def get_site(self, domain: str) -> Optional[Dict[str, Any]]:
        """Retrieve details of a single website by domain.

        Args:
            domain: Domain name string.

        Returns:
            Optional[Dict[str, Any]]: Website dictionary or None if not found.
        """
        try:
            with self.db:
                record = self.db.fetch_one(
                    """
                    SELECT id, domain, root_path, php_version, ssl_status, created_at
                    FROM sites
                    WHERE domain = ?;
                    """,
                    (domain.strip().lower(),),
                )
                return record
        except Exception as exc:
            logger.error("Failed to get site '%s': %s", domain, exc)
            return None

    def get_vhost_path(self, domain: str) -> str:
        """Get absolute path to Nginx virtual host configuration file.

        Args:
            domain: Website domain name.

        Returns:
            str: Path to vhost .conf file.
        """
        domain = domain.strip().lower()
        avail_file = Path(self.nginx_available) / f"{domain}.conf"
        if avail_file.exists():
            return str(avail_file)

        std_avail = Path(f"/etc/nginx/sites-available/{domain}.conf")
        if std_avail.exists():
            return str(std_avail)

        conf_d = Path(f"/etc/nginx/conf.d/{domain}.conf")
        if conf_d.exists():
            return str(conf_d)

        return str(avail_file)

    def read_vhost_config(self, domain: str) -> Tuple[bool, str]:
        """Read content of Nginx virtual host configuration file.

        Args:
            domain: Website domain name.

        Returns:
            Tuple[bool, str]: (Success boolean, Content string or error message).
        """
        domain = domain.strip().lower()
        vhost_path = self.get_vhost_path(domain)
        p = Path(vhost_path)

        if not p.exists():
            return False, f"Virtual host configuration file not found at '{vhost_path}'."

        try:
            content = p.read_text(encoding="utf-8")
            return True, content
        except Exception as exc:
            err_msg = f"Failed to read vhost file '{vhost_path}': {exc}"
            logger.error(err_msg)
            return False, err_msg

    def edit_vhost_config_interactive(self, domain: str) -> Tuple[bool, str]:
        """Open Nginx vhost in CLI editor with auto-backup, syntax check, and rollback.

        Args:
            domain: Website domain name.

        Returns:
            Tuple[bool, str]: (Success boolean, Status or error message).
        """
        domain = domain.strip().lower()
        vhost_path = self.get_vhost_path(domain)
        p = Path(vhost_path)

        if not p.exists():
            return False, f"Virtual host file '{vhost_path}' does not exist."

        bak_path = Path(f"{vhost_path}.bak")

        try:
            # 1. Create temporary backup
            shutil.copy2(str(p), str(bak_path))
            logger.debug("Created vhost backup before edit: %s", bak_path)

            # 2. Select system editor
            editor = os.environ.get("EDITOR")
            if not editor:
                if shutil.which("nano"):
                    editor = "nano"
                elif shutil.which("vim"):
                    editor = "vim"
                elif shutil.which("vi"):
                    editor = "vi"
                elif os.name == "nt":
                    editor = "notepad"
                else:
                    editor = "nano"

            # 3. Launch interactive editor
            os.system(f"{editor} \"{vhost_path}\"")

            # 4. Test Nginx configuration syntax
            test_res = run_cmd("nginx -t")
            if test_res.success or "not found" in test_res.stderr.lower() or "not recognized" in test_res.stderr.lower():
                if bak_path.exists():
                    bak_path.unlink()
                self._reload_nginx()
                logger.info("Nginx vhost for '%s' updated and reloaded successfully.", domain)
                return True, "Nginx vhost updated and reloaded successfully."
            else:
                # Syntax error - auto-rollback from backup
                err_msg = test_res.stderr.strip() if test_res.stderr else "Nginx syntax check failed."
                if bak_path.exists():
                    shutil.copy2(str(bak_path), str(p))
                    bak_path.unlink()
                logger.warning("Nginx vhost syntax error for '%s', rolled back: %s", domain, err_msg)
                return False, f"Syntax error detected. Changes rolled back:\n{err_msg}"

        except Exception as exc:
            if bak_path.exists():
                try:
                    shutil.copy2(str(bak_path), str(p))
                    bak_path.unlink()
                except Exception:
                    pass
            err_msg = f"Failed to edit vhost for '{domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def reset_vhost_config(self, domain: str) -> Tuple[bool, str]:
        """Regenerate Nginx vhost config back to panel default template (including WAF & security headers).

        Args:
            domain: Website domain name.

        Returns:
            Tuple[bool, str]: (Success boolean, Status or error message).
        """
        domain = domain.strip().lower()
        site = self.get_site(domain)
        if not site:
            return False, f"Site '{domain}' not found in database."

        root_path = site.get("root_path") or os.path.join(self.webroot_base, domain)
        php_version = site.get("php_version", "none")
        ssl_status = site.get("ssl_status", 0)

        try:
            ensure_waf_snippet()

            vhost_path = Path(self.get_vhost_path(domain))
            vhost_path.parent.mkdir(parents=True, exist_ok=True)

            cert_dir = Path(f"/etc/letsencrypt/live/{domain}")
            cert_file = cert_dir / "fullchain.pem"
            key_file = cert_dir / "privkey.pem"

            is_ssl_active = (ssl_status == 1 or str(ssl_status).lower() == "enabled") and cert_file.exists() and key_file.exists()

            if is_ssl_active:
                from app.modules.ssl import SSLManager
                ssl_mgr = SSLManager(
                    nginx_available=self.nginx_available,
                    nginx_enabled=self.nginx_enabled,
                    db=self.db,
                )
                vhost_content = ssl_mgr._generate_ssl_nginx_config(
                    domain=domain,
                    root_path=root_path,
                    php_version=php_version,
                    cert_file=str(cert_file),
                    key_file=str(key_file),
                )
            else:
                vhost_content = self._generate_nginx_config(
                    domain=domain,
                    root_path=root_path,
                    php_version=php_version,
                )

            vhost_path.write_text(vhost_content, encoding="utf-8")

            # Symlink in sites-enabled
            enabled_dir = Path(self.nginx_enabled)
            if enabled_dir.parent.exists() or os.name == "nt":
                enabled_dir.mkdir(parents=True, exist_ok=True)
                symlink_file = enabled_dir / f"{domain}.conf"
                if symlink_file.exists() or symlink_file.is_symlink():
                    symlink_file.unlink()
                try:
                    if hasattr(os, "symlink"):
                        os.symlink(str(vhost_path), str(symlink_file))
                except Exception as sym_exc:
                    logger.debug("Symlink creation skipped: %s", sym_exc)

            # Reload Nginx
            reload_ok, reload_msg = self._reload_nginx()
            if not reload_ok:
                logger.warning("Nginx reload warning on reset: %s", reload_msg)

            logger.info("Nginx vhost for '%s' reset to default template.", domain)
            return True, f"Nginx configuration for '{domain}' has been reset to default and reloaded."

        except Exception as exc:
            err_msg = f"Failed to reset vhost for '{domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def rename_site(
        self,
        old_domain: str,
        new_domain: str,
        rename_root: bool = False,
    ) -> Tuple[bool, str]:
        """Rename an existing website domain name and optionally rename its document root folder.

        Args:
            old_domain: Current domain name.
            new_domain: New desired domain name.
            rename_root: Whether to also rename the document root folder.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        old_domain = old_domain.strip().lower()
        new_domain = new_domain.strip().lower()

        if old_domain == new_domain:
            return False, "New domain name is identical to current domain name."

        if not self.validate_domain(new_domain):
            return False, f"Invalid new domain name '{new_domain}'. Must be a valid FQDN."

        site = self.get_site(old_domain)
        if not site:
            return False, f"Site '{old_domain}' not found in database."

        if self.get_site(new_domain):
            return False, f"A website with domain '{new_domain}' already exists in the database."

        old_avail = Path(self.nginx_available) / f"{old_domain}.conf"
        old_enabled = Path(self.nginx_enabled) / f"{old_domain}.conf"
        new_avail = Path(self.nginx_available) / f"{new_domain}.conf"
        new_enabled = Path(self.nginx_enabled) / f"{new_domain}.conf"

        if new_avail.exists():
            return False, f"Configuration file for '{new_domain}' already exists at '{new_avail}'."

        old_root = Path(site.get("root_path") or os.path.join(self.webroot_base, old_domain))
        new_root_str = str(old_root)
        root_was_moved = False

        # 1. Optionally rename root directory
        if rename_root and old_root.exists() and old_root.is_dir():
            target_root = old_root.parent / new_domain
            if target_root.exists():
                return False, f"Target directory '{target_root}' already exists on disk."
            try:
                shutil.move(str(old_root), str(target_root))
                new_root_str = str(target_root)
                root_was_moved = True
            except Exception as exc:
                return False, f"Failed to rename document root: {exc}"

        # 2. Prepare new Nginx configuration
        try:
            if old_avail.exists():
                old_conf = old_avail.read_text(encoding="utf-8")
                new_conf = re.sub(
                    rf"\bserver_name\s+{re.escape(old_domain)}\b",
                    f"server_name {new_domain}",
                    old_conf,
                )
                new_conf = new_conf.replace(f"{old_domain}_access.log", f"{new_domain}_access.log")
                new_conf = new_conf.replace(f"{old_domain}_error.log", f"{new_domain}_error.log")
                new_conf = new_conf.replace(f"{old_domain}_ssl_access.log", f"{new_domain}_ssl_access.log")
                new_conf = new_conf.replace(f"{old_domain}_ssl_error.log", f"{new_domain}_ssl_error.log")
                new_conf = new_conf.replace(f"{old_domain}.pass", f"{new_domain}.pass")
                if root_was_moved:
                    new_conf = new_conf.replace(str(old_root), new_root_str)
            else:
                new_conf = self._generate_nginx_config(
                    domain=new_domain,
                    root_path=new_root_str,
                    php_version=site.get("php_version", "none"),
                )

            new_avail.parent.mkdir(parents=True, exist_ok=True)
            new_avail.write_text(new_conf, encoding="utf-8")

            # Update symlink
            if new_enabled.parent.exists() or os.name == "nt":
                new_enabled.parent.mkdir(parents=True, exist_ok=True)
                if new_enabled.exists() or new_enabled.is_symlink():
                    new_enabled.unlink()
                try:
                    if hasattr(os, "symlink"):
                        os.symlink(str(new_avail), str(new_enabled))
                except Exception as sym_exc:
                    logger.debug("Symlink error on rename: %s", sym_exc)

            # Unlink old files
            if old_enabled.exists() or old_enabled.is_symlink():
                old_enabled.unlink()
            if old_avail.exists():
                old_avail.unlink()

            # 3. Update Database
            with self.db:
                self.db.execute(
                    "UPDATE sites SET domain = ?, root_path = ? WHERE domain = ?;",
                    (new_domain, new_root_str, old_domain),
                )

            # 4. Test & Reload Nginx
            reload_ok, reload_msg = self._reload_nginx()
            if not reload_ok:
                logger.warning("Nginx reload warning on rename: %s", reload_msg)

            # 5. Update open_basedir .user.ini if present
            if root_was_moved:
                user_ini = Path(new_root_str) / ".user.ini"
                if user_ini.exists():
                    try:
                        run_cmd(f"chattr -i '{user_ini}'")
                        user_ini.write_text(f"open_basedir={new_root_str}/:/tmp/:/proc/\n", encoding="utf-8")
                        run_cmd(f"chattr +i '{user_ini}'")
                    except Exception:
                        pass

            logger.info("Successfully renamed site '%s' to '%s'.", old_domain, new_domain)
            return True, f"Website '{old_domain}' successfully renamed to '{new_domain}'."

        except Exception as exc:
            err_msg = f"Failed to rename site '{old_domain}' to '{new_domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def get_site_log_paths(self, domain: str) -> Dict[str, Path]:
        """Resolve access and error log paths for a website domain.

        Args:
            domain: Target domain name.

        Returns:
            Dict[str, Path]: Dict containing 'access' and 'error' Path objects.
        """
        clean_domain = domain.strip().lower()
        log_dir = Path("/var/log/nginx")
        fallback_dir = BASE_DIR / "logs"

        target_dir = log_dir if (log_dir.exists() or os.name != "nt") else fallback_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        return {
            "access": target_dir / f"{clean_domain}_access.log",
            "error": target_dir / f"{clean_domain}_error.log",
        }

    def read_site_log(
        self,
        domain: str,
        log_type: str = "access",
        lines: int = 50,
    ) -> Tuple[bool, List[str], str]:
        """Read the last N lines from a specific site's access or error log.

        Args:
            domain: Domain name.
            log_type: 'access' or 'error'.
            lines: Number of lines to retrieve.

        Returns:
            Tuple[bool, List[str], str]: (Success boolean, List of log lines, Path string).
        """
        paths = self.get_site_log_paths(domain)
        target_path = paths.get(log_type, paths["access"])

        if not target_path.exists():
            return True, [f"[INFO] Log file '{target_path.name}' does not exist on disk yet (no traffic recorded)."], str(target_path)

        try:
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                trailing_lines = list(deque(f, maxlen=lines))
                return True, [l.rstrip("\r\n") for l in trailing_lines], str(target_path)
        except Exception as exc:
            return False, [f"[ERROR] Could not read log file: {exc}"], str(target_path)

    def clear_site_log(
        self,
        domain: str,
        log_type: str = "all",
    ) -> Tuple[bool, str]:
        """Truncate and clear access log, error log, or both for a specific website.

        Args:
            domain: Domain name.
            log_type: 'access', 'error', or 'all'.

        Returns:
            Tuple[bool, str]: (Success boolean, Status message).
        """
        paths = self.get_site_log_paths(domain)
        targets: List[Path] = []
        if log_type in ("access", "all"):
            targets.append(paths["access"])
        if log_type in ("error", "all"):
            targets.append(paths["error"])

        cleared = []
        for p in targets:
            if p.exists():
                try:
                    with open(p, "w", encoding="utf-8") as f:
                        f.truncate(0)
                    cleared.append(p.name)
                except Exception as exc:
                    return False, f"Failed to clear log '{p.name}': {exc}"

        if not cleared:
            return True, f"Log files for '{domain}' are already empty or do not exist on disk."
        return True, f"Successfully cleared log(s) for '{domain}': {', '.join(cleared)}"

    def toggle_open_basedir(self, domain: str, enable: bool) -> Tuple[bool, str]:
        """Enable or disable PHP open_basedir directory isolation via .user.ini.

        Args:
            domain: Domain name.
            enable: True to enable, False to disable.

        Returns:
            Tuple[bool, str]: (Success boolean, Status message).
        """
        site = self.get_site(domain)
        if not site:
            return False, f"Site '{domain}' not found."

        root_path = site.get("root_path") or os.path.join(self.webroot_base, domain)
        user_ini = Path(root_path) / ".user.ini"

        try:
            if enable:
                user_ini.parent.mkdir(parents=True, exist_ok=True)
                run_cmd(f"chattr -i '{user_ini}'")
                user_ini.write_text(f"open_basedir={root_path}/:/tmp/:/proc/\n", encoding="utf-8")
                run_cmd(f"chattr +i '{user_ini}'")
                logger.info("Enabled open_basedir for '%s'", domain)
                return True, f"Open_basedir (.user.ini) isolation successfully ENABLED for '{domain}'."
            else:
                run_cmd(f"chattr -i '{user_ini}'")
                if user_ini.exists():
                    user_ini.unlink()
                logger.info("Disabled open_basedir for '%s'", domain)
                return True, f"Open_basedir (.user.ini) isolation DISABLED for '{domain}'."
        except Exception as exc:
            err_msg = f"Failed to update open_basedir for '{domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def get_open_basedir_status(self, domain: str) -> bool:
        """Check if open_basedir protection is active for a site."""
        site = self.get_site(domain)
        if not site:
            return False
        root_path = site.get("root_path") or os.path.join(self.webroot_base, domain)
        user_ini = Path(root_path) / ".user.ini"
        if not user_ini.exists():
            return False
        try:
            content = user_ini.read_text(encoding="utf-8", errors="replace")
            return "open_basedir" in content
        except Exception:
            return False

    def set_password_protection(
        self,
        domain: str,
        username: str,
        password: str,
    ) -> Tuple[bool, str]:
        """Set HTTP Basic Auth password protection on a website.

        Args:
            domain: Domain name.
            username: Authorized username.
            password: Plaintext password to hash.

        Returns:
            Tuple[bool, str]: (Success boolean, Status message).
        """
        clean_domain = domain.strip().lower()
        clean_user = username.strip()
        if not clean_user or not password:
            return False, "Username and password cannot be empty."

        site = self.get_site(clean_domain)
        if not site:
            return False, f"Site '{clean_domain}' not found."

        vhost_path = Path(self.get_vhost_path(clean_domain))
        if not vhost_path.exists():
            return False, f"Virtual host configuration for '{clean_domain}' not found."

        passwords_dir = Path("/etc/nginx/passwords")
        if not passwords_dir.exists() and os.name == "nt":
            passwords_dir = BASE_DIR / "data" / "passwords"

        try:
            passwords_dir.mkdir(parents=True, exist_ok=True)
            pass_file = passwords_dir / f"{clean_domain}.pass"

            # Generate SHA-1 encoded htpasswd entry
            sha1_hash = hashlib.sha1(password.encode("utf-8")).digest()
            b64_hash = base64.b64encode(sha1_hash).decode("ascii")
            pass_file.write_text(f"{clean_user}:{{SHA}}{b64_hash}\n", encoding="utf-8")

            pass_posix = pass_file.as_posix()

            # Update Nginx vhost with auth_basic directives
            vhost_content = vhost_path.read_text(encoding="utf-8")
            if "auth_basic" not in vhost_content:
                auth_snippet = f"""    # Password Access Protection
    auth_basic "Restricted Access";
    auth_basic_user_file {pass_posix};
"""
                # Inject right below server_name safely without regex escape bugs
                vhost_content = re.sub(
                    r"(server_name\s+[^;]+;\n)",
                    lambda m: m.group(1) + auth_snippet,
                    vhost_content,
                    count=1,
                )
                vhost_path.write_text(vhost_content, encoding="utf-8")

            self._reload_nginx()
            logger.info("Password protection enabled for site '%s' (user: %s)", clean_domain, clean_user)
            return True, f"Password protection successfully enabled for '{clean_domain}' (Username: {clean_user})."

        except Exception as exc:
            err_msg = f"Failed to enable password protection for '{clean_domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def disable_password_protection(self, domain: str) -> Tuple[bool, str]:
        """Disable HTTP Basic Auth password protection on a website.

        Args:
            domain: Domain name.

        Returns:
            Tuple[bool, str]: (Success boolean, Status message).
        """
        clean_domain = domain.strip().lower()
        vhost_path = Path(self.get_vhost_path(clean_domain))
        if not vhost_path.exists():
            return False, f"Virtual host configuration for '{clean_domain}' not found."

        try:
            vhost_content = vhost_path.read_text(encoding="utf-8")
            vhost_clean = re.sub(r"^[ \t]*auth_basic\s+.*$\n?", "", vhost_content, flags=re.MULTILINE)
            vhost_clean = re.sub(r"^[ \t]*auth_basic_user_file\s+.*$\n?", "", vhost_clean, flags=re.MULTILINE)
            vhost_path.write_text(vhost_clean, encoding="utf-8")

            passwords_dir = Path("/etc/nginx/passwords")
            if not passwords_dir.exists() and os.name == "nt":
                passwords_dir = BASE_DIR / "data" / "passwords"
            pass_file = passwords_dir / f"{clean_domain}.pass"
            if pass_file.exists():
                pass_file.unlink()

            self._reload_nginx()
            logger.info("Password protection disabled for site '%s'", clean_domain)
            return True, f"Password protection disabled for '{clean_domain}'."

        except Exception as exc:
            err_msg = f"Failed to disable password protection for '{clean_domain}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def get_password_protection_status(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Check if password protection is active and return associated username."""
        clean_domain = domain.strip().lower()
        vhost_path = Path(self.get_vhost_path(clean_domain))
        if not vhost_path.exists():
            return False, None
        try:
            vhost_content = vhost_path.read_text(encoding="utf-8", errors="replace")
            if "auth_basic" in vhost_content:
                passwords_dir = Path("/etc/nginx/passwords")
                if not passwords_dir.exists() and os.name == "nt":
                    passwords_dir = BASE_DIR / "data" / "passwords"
                pass_file = passwords_dir / f"{clean_domain}.pass"
                if pass_file.exists():
                    first_line = pass_file.read_text(encoding="utf-8").splitlines()
                    if first_line:
                        return True, first_line[0].split(":")[0]
                return True, "enabled"
            return False, None
        except Exception:
            return False, None
