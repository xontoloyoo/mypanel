"""Site management module for Nginx and web server virtual hosts."""

import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

from app.core.database import Database, get_db
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
        # Ensure default WAF rule file is prepared
        ensure_waf_snippet()

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
        """Generate Nginx virtual host configuration file content with WAF and security headers.

        Args:
            domain: Website domain name.
            root_path: Document root directory path.
            php_version: PHP version (e.g., '8.2', '8.1', 'none').

        Returns:
            str: Generated Nginx server block configuration.
        """
        php_block = ""
        index_files = "index.html index.htm index.php"

        if php_version and php_version.lower() != "none":
            # PHP-FPM fastcgi socket configuration
            php_sock = f"/run/php/php{php_version}-fpm.sock"
            php_block = f"""
    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{php_sock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}"""

        config = f"""server {{
    listen 80;
    listen [::]:80;

    server_name {domain} www.{domain};
    root {root_path};
    index {index_files};

    # Include Modular WAF Protection
    include /etc/nginx/waf/waf_default.conf;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    access_log /var/log/nginx/{domain}_access.log;
    error_log /var/log/nginx/{domain}_error.log;

    location / {{
        try_files $uri $uri/ =404;
    }}
{php_block}

    location ~ /\\.ht {{
        deny all;
    }}
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

        # 3. Determine web root
        target_root = root_path if root_path else os.path.join(self.webroot_base, domain)

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
            with self.db:
                self.db.execute(
                    """
                    INSERT INTO sites (domain, root_path, php_version, ssl_status)
                    VALUES (?, ?, ?, ?);
                    """,
                    (domain, target_root, php_version, 0),
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

    def list_sites(self) -> List[Dict[str, Any]]:
        """Retrieve all registered websites from database.

        Returns:
            List[Dict[str, Any]]: List of website dictionaries.
        """
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
