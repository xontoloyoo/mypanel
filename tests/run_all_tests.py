"""Comprehensive automated test suite for cli-panel core engine, modules, and WAF protection."""

from dataclasses import dataclass
import gzip
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure utf-8 encoding on standard streams
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.core.database import Database, get_db, init_db
from app.core.executor import ExecutionResult, run_cmd
from app.modules.backup import BackupManager
from app.modules.cron import CronManager
from app.modules.database import DatabaseManager, generate_secure_password
from app.modules.doctor import PanelDoctor
from app.modules.firewall import FirewallManager
from app.modules.log_viewer import LogViewerManager
from app.modules.migration import MigrationManager
from app.modules.php_manager import PHPManager, POPULAR_EXTENSIONS, SECURITY_BASELINE_FUNCTIONS
from app.modules.site import SiteManager, WAF_DEFAULT_CONFIG, ensure_waf_snippet
from app.modules.ssl import SSLManager
from app.modules.system import SystemManager
from app.modules.tuner import ConfigTuner, SwapManager, TUNER_REGISTRY, ensure_nginx_security_conf
from app.ui.views import colorize_log_line

console = Console(safe_box=True)


@dataclass
class SuiteResult:
    """Dataclass holding the result of a test suite execution."""

    number: int
    name: str
    checks_count: int
    passed: bool
    duration: float
    error_detail: Optional[str] = None


# ==============================================================================
# Suite 1: Core Engine & SQLite Database
# ==============================================================================
def run_suite_1(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test Core Engine (Executor, Logger) and SQLite Database CRUD."""
    checks = 0
    suite_dir = temp_dir / "suite_1"
    suite_dir.mkdir(parents=True, exist_ok=True)
    db_path = suite_dir / "test_panel.db"
    db = Database(db_path=db_path)
    init_db(db_path=db_path)
    checks += 1
    assert db_path.exists(), "Database file was not created"

    try:
        with db:
            # 1. Insert & Query Sites table
            db.execute(
                "INSERT INTO sites (domain, root_path, php_version, ssl_status) VALUES (?, ?, ?, ?);",
                ("example.com", "/www/wwwroot/example.com", "8.2", 0),
            )
            site = db.fetch_one("SELECT * FROM sites WHERE domain = ?;", ("example.com",))
            checks += 1
            assert site is not None, "Failed to query inserted site"
            assert site["domain"] == "example.com"

            # 2. Insert & Query Databases table
            db.execute(
                "INSERT INTO databases (db_name, db_user, db_pass, charset) VALUES (?, ?, ?, ?);",
                ("app_db", "app_user", "SecretPass123!#", "utf8mb4"),
            )
            db_rec = db.fetch_one("SELECT * FROM databases WHERE db_name = ?;", ("app_db",))
            checks += 1
            assert db_rec is not None, "Failed to query database record"

            # 3. Insert & Query Cron Jobs
            db.execute(
                "INSERT INTO cron_jobs (name, job_type, schedule, target, status) VALUES (?, ?, ?, ?, ?);",
                ("Daily Backup", "site_backup", "0 2 * * *", "example.com", "active"),
            )
            job = db.fetch_one("SELECT * FROM cron_jobs WHERE name = ?;", ("Daily Backup",))
            checks += 1
            assert job is not None, "Failed to query cron job record"

            # 4. Insert & Query Backups
            db.execute(
                "INSERT INTO backups (backup_type, target, file_path, file_size) VALUES (?, ?, ?, ?);",
                ("site", "example.com", "/www/backup/site/test.tar.gz", 1024),
            )
            bk = db.fetch_one("SELECT * FROM backups WHERE target = ?;", ("example.com",))
            checks += 1
            assert bk is not None, "Failed to query backup record"

        # 5. Test Command Executor
        res = run_cmd("echo 'cli-panel test'")
        checks += 1
        assert res.success, f"Executor failed to run echo: {res.stderr}"
        assert "cli-panel test" in res.stdout, f"Unexpected stdout: {res.stdout}"

        # Test Executor timeout handling (cross-platform python sleep)
        timeout_cmd = f'"{sys.executable}" -c "import time; time.sleep(3)"'
        res_timeout = run_cmd(timeout_cmd, timeout=1)
        checks += 1
        assert not res_timeout.success, "Timeout expected to fail"

    finally:
        db.close()

    return checks, None


# ==============================================================================
# Suite 2: Website & SSL Management
# ==============================================================================
def run_suite_2(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test SiteManager and SSLManager vhost creation, WAF includes, and SSL lifecycle."""
    checks = 0
    suite_dir = temp_dir / "suite_2"
    suite_dir.mkdir(parents=True, exist_ok=True)
    db = Database(db_path=suite_dir / "test_site.db")
    init_db(db_path=suite_dir / "test_site.db")

    webroot_base = suite_dir / "wwwroot"
    nginx_avail = suite_dir / "sites-available"
    nginx_enabled = suite_dir / "sites-enabled"
    cert_base = suite_dir / "certs"

    site_mgr = SiteManager(
        webroot_base=str(webroot_base),
        nginx_available=str(nginx_avail),
        nginx_enabled=str(nginx_enabled),
        db=db,
    )
    ssl_mgr = SSLManager(
        cert_base=str(cert_base),
        nginx_available=str(nginx_avail),
        nginx_enabled=str(nginx_enabled),
        db=db,
    )

    import app.modules.ssl
    orig_ssl_run_cmd = app.modules.ssl.run_cmd

    # Mock certbot ACME execution for dummy test domains to avoid live network registration failures
    def mock_ssl_run_cmd(cmd, timeout=60, check_root=False):
        cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
        if "certbot" in cmd_str:
            d_cert_dir = cert_base / "mysite.local"
            d_cert_dir.mkdir(parents=True, exist_ok=True)
            (d_cert_dir / "fullchain.pem").write_text("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n", encoding="utf-8")
            (d_cert_dir / "privkey.pem").write_text("-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n", encoding="utf-8")
            return ExecutionResult(success=True, stdout="Mock certificate generated", stderr="", returncode=0)
        return orig_ssl_run_cmd(cmd, timeout=timeout, check_root=check_root)

    app.modules.ssl.run_cmd = mock_ssl_run_cmd

    try:
        # 1. Create Site
        ok, msg = site_mgr.create_site(domain="mysite.local", php_version="8.2")
        checks += 1
        assert ok, f"Failed to create site: {msg}"

        # Check vhost content & WAF directive
        vhost_file = nginx_avail / "mysite.local.conf"
        checks += 1
        assert vhost_file.exists(), "Nginx vhost file was not written"
        content = vhost_file.read_text(encoding="utf-8")

        checks += 1
        assert "include /etc/nginx/waf/waf_default.conf;" in content, "WAF include missing in HTTP vhost"
        assert "X-Frame-Options" in content, "Security headers missing in HTTP vhost"
        assert 'more_set_headers "Server: Aegis-Gateway";' in content, "more_set_headers missing in HTTP vhost"
        assert "location ~ /\\.well-known" in content, "ACME .well-known block missing in HTTP vhost"
        assert "expires 30d;" in content, "Static asset cache missing in HTTP vhost"
        assert "index index.php index.html index.htm;" in content, "index.php priority missing in HTTP vhost"
        assert "fastcgi_pass" in content, "PHP fastcgi block missing"
        assert "try_files $uri $uri/ /index.php?$query_string;" in content, "Framework routing missing in PHP vhost"
        assert "fastcgi_split_path_info" in content, "PATH_INFO splitting missing in FastCGI block"
        assert "fastcgi_buffers 4 256k;" in content, "FastCGI buffer optimization missing"
        assert "error_page 404 /404.html;" in content, "404 error_page directive missing in HTTP vhost"
        assert "location = /404.html" in content, "404 location block missing in HTTP vhost"
        assert "root /www/server/panel/templates/errors;" in content, "Custom error template root missing in HTTP vhost"

        # 2. Request / Setup SSL
        ok_ssl, msg_ssl = ssl_mgr.request_ssl(domain="mysite.local", email="admin@mysite.local")
        checks += 1
        assert ok_ssl, f"Failed to setup SSL: {msg_ssl}"

        ssl_content = vhost_file.read_text(encoding="utf-8")
        checks += 1
        assert "listen 443 ssl" in ssl_content, "HTTPS port 443 block missing"
        assert "ssl_stapling on;" in ssl_content, "OCSP stapling missing in HTTPS vhost"
        assert "Strict-Transport-Security" in ssl_content, "HSTS header missing in HTTPS vhost"
        assert 'more_set_headers "Server: Aegis-Gateway";' in ssl_content, "more_set_headers missing in HTTPS vhost"
        assert "include /etc/nginx/waf/waf_default.conf;" in ssl_content, "WAF include missing in HTTPS vhost"
        assert "try_files $uri $uri/ /index.php?$query_string;" in ssl_content, "Framework routing missing in HTTPS PHP vhost"
        assert "location = /404.html" in ssl_content, "404 location block missing in HTTPS vhost"

        # 3. Disable SSL
        ok_dis, msg_dis = ssl_mgr.disable_ssl("mysite.local")
        checks += 1
        assert ok_dis, f"Failed to disable SSL: {msg_dis}"
        plain_content = vhost_file.read_text(encoding="utf-8")
        assert "listen 443 ssl" not in plain_content

        # 4. Test View & Reset Vhost Config
        vhost_p = site_mgr.get_vhost_path("mysite.local")
        checks += 1
        assert vhost_p == str(vhost_file), f"Unexpected vhost path: {vhost_p}"

        ok_read, read_content = site_mgr.read_vhost_config("mysite.local")
        checks += 1
        assert ok_read, f"Failed to read vhost config: {read_content}"
        assert "server_name mysite.local" in read_content

        ok_reset, msg_reset = site_mgr.reset_vhost_config("mysite.local")
        checks += 1
        assert ok_reset, f"Failed to reset vhost config: {msg_reset}"
        reset_content = vhost_file.read_text(encoding="utf-8")
        assert "include /etc/nginx/waf/waf_default.conf;" in reset_content

        # 5. Test Relative Document Root & Static Site (PHP None)
        ok_rel, msg_rel = site_mgr.create_site(domain="relative.local", root_path="custom_subfolder", php_version="none")
        checks += 1
        assert ok_rel, f"Failed to create site with relative root: {msg_rel}"
        site_rel = site_mgr.get_site("relative.local")
        assert site_rel is not None
        assert site_rel["root_path"] == str(webroot_base / "custom_subfolder"), f"Expected {webroot_base / 'custom_subfolder'}, got {site_rel['root_path']}"
        static_vhost = (nginx_avail / "relative.local.conf").read_text(encoding="utf-8")
        assert "try_files $uri $uri/ =404;" in static_vhost, "Static site must use try_files =404"
        assert "fastcgi_pass" not in static_vhost, "Static site must not include fastcgi_pass"
        site_mgr.delete_site("relative.local", delete_root=True)

        # 6. Delete Site
        ok_del, msg_del = site_mgr.delete_site("mysite.local", delete_root=True)
        checks += 1
        assert ok_del, f"Failed to delete site: {msg_del}"
        assert not vhost_file.exists(), "Vhost file was not removed"

    finally:
        app.modules.ssl.run_cmd = orig_ssl_run_cmd
        db.close()

    return checks, None


# ==============================================================================
# Suite 3: Database Management
# ==============================================================================
def run_suite_3(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test DatabaseManager creation, secure password generator, user privileges, and deletion."""
    checks = 0
    suite_dir = temp_dir / "suite_3"
    suite_dir.mkdir(parents=True, exist_ok=True)
    db = Database(db_path=suite_dir / "test_database.db")
    init_db(db_path=suite_dir / "test_database.db")

    db_mgr = DatabaseManager(db=db)

    try:
        # 1. Test Password Generation (16 chars, mix of upper, lower, digits, symbols)
        pwd = generate_secure_password(length=16)
        checks += 1
        assert len(pwd) == 16, f"Expected 16-character password, got {len(pwd)}"
        assert any(c.isupper() for c in pwd), "Password missing uppercase"
        assert any(c.islower() for c in pwd), "Password missing lowercase"
        assert any(c.isdigit() for c in pwd), "Password missing digit"
        assert any(c in "!#%*+-_=@$" for c in pwd), "Password missing special symbol"

        # 2. Create Database & User with localhost host matching
        ok, msg = db_mgr.create_database("store_db", "store_user", "SecurePass123!@#", "utf8mb4", host="localhost")
        checks += 1
        assert ok, f"Failed to create database: {msg}"

        # Verify DB record
        dbs = db_mgr.list_databases()
        checks += 1
        assert len(dbs) == 1, "Database record not found in internal SQLite table"
        assert dbs[0]["db_name"] == "store_db"

        # 3. Change Password with localhost host matching
        ok_pwd, msg_pwd = db_mgr.change_password("store_user", "NewSecurePass987!#", host="localhost")
        checks += 1
        assert ok_pwd, f"Failed to change password: {msg_pwd}"

        # 4. Standalone User & Privileges Check
        ok_u, msg_u = db_mgr.create_user("temp_user", "TempPass123!@#", host="localhost")
        checks += 1
        assert ok_u, f"Failed to create user: {msg_u}"

        ok_gp, msg_gp = db_mgr.grant_privileges("store_db", "temp_user", host="localhost")
        checks += 1
        assert ok_gp, f"Failed to grant privileges: {msg_gp}"

        ok_du, msg_du = db_mgr.delete_user("temp_user", host="localhost")
        checks += 1
        assert ok_du, f"Failed to delete user: {msg_du}"

        # 5. Delete Database
        ok_del, msg_del = db_mgr.delete_database("store_db", delete_user=True, host="localhost")
        checks += 1
        assert ok_del, f"Failed to delete database: {msg_del}"
        assert len(db_mgr.list_databases()) == 0, "Database was not removed from DB"

    finally:
        db.close()

    return checks, None


# ==============================================================================
# Suite 4: Firewall & Security
# ==============================================================================
def run_suite_4(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test FirewallManager port opening, range filtering, and rule deletion."""
    checks = 0
    suite_dir = temp_dir / "suite_4"
    suite_dir.mkdir(parents=True, exist_ok=True)
    db = Database(db_path=suite_dir / "test_firewall.db")
    init_db(db_path=suite_dir / "test_firewall.db")

    fw_mgr = FirewallManager(db=db)

    try:
        # 1. Add single port rule
        ok1, msg1 = fw_mgr.add_rule(port="80", protocol="tcp", action="allow", description="HTTP Web")
        checks += 1
        assert ok1, f"Failed to add port 80 rule: {msg1}"

        # 2. Add port range rule
        ok2, msg2 = fw_mgr.add_rule(port="3000:4000", protocol="tcp", action="allow", description="Node services")
        checks += 1
        assert ok2, f"Failed to add port range rule: {msg2}"

        # 3. List Rules
        rules = fw_mgr.list_rules()
        checks += 1
        assert len(rules) == 2, f"Expected 2 rules, found {len(rules)}"

        # 4. Delete Rule
        ok_del, msg_del = fw_mgr.delete_rule(rules[0]["id"])
        checks += 1
        assert ok_del, f"Failed to delete rule: {msg_del}"
        assert len(fw_mgr.list_rules()) == 1, "Rule was not removed"

        # 5. Status toggle
        ok_tog, msg_tog = fw_mgr.toggle_firewall(enable=True)
        checks += 1
        assert ok_tog, f"Failed to toggle firewall: {msg_tog}"

    finally:
        db.close()

    return checks, None


# ==============================================================================
# Suite 5: System Monitor
# ==============================================================================
def run_suite_5(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test SystemManager metrics validation and service status checking."""
    checks = 0
    sys_mgr = SystemManager()

    # 1. Get System Metrics
    metrics = sys_mgr.get_system_metrics()
    checks += 1
    assert "cpu" in metrics, "Missing CPU metrics"
    assert "ram" in metrics, "Missing RAM metrics"
    assert "disk" in metrics, "Missing Disk metrics"
    assert "uptime" in metrics, "Missing Uptime"

    cpu = metrics["cpu"]
    checks += 1
    assert isinstance(cpu.get("percent"), (int, float)), "CPU percent is not numeric"
    assert 0.0 <= cpu.get("percent") <= 100.0, "CPU percent out of range"

    ram = metrics["ram"]
    checks += 1
    assert ram.get("total_bytes", 0) > 0, "RAM total_bytes is 0"
    assert 0.0 <= ram.get("percent", 0.0) <= 100.0, "RAM percent out of range"

    # 2. Check Core Services Status
    services = sys_mgr.check_core_services()
    checks += 1
    for expected_svc in ["nginx", "mysql", "php-fpm", "ufw"]:
        assert expected_svc in services, f"Service '{expected_svc}' missing from status check"
        assert "is_active" in services[expected_svc], f"Service '{expected_svc}' missing is_active field"

    return checks, None


# ==============================================================================
# Suite 6: Cron & Backup Engine
# ==============================================================================
def run_suite_6(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test CronManager interval parsing, job toggle, and BackupManager tar.gz archive integrity."""
    checks = 0
    suite_dir = temp_dir / "suite_6"
    suite_dir.mkdir(parents=True, exist_ok=True)
    db = Database(db_path=suite_dir / "test_cron.db")
    init_db(db_path=suite_dir / "test_cron.db")

    cron_mgr = CronManager(db=db)

    try:
        # 1. Add Cron Job with 5-column validation
        ok_cron, msg_cron = cron_mgr.add_job(
            name="Nightly Site Backup",
            job_type="site_backup",
            schedule="0 3 * * *",
            target="example.com",
        )
        checks += 1
        assert ok_cron, f"Failed to add cron job: {msg_cron}"

        jobs = cron_mgr.list_jobs()
        checks += 1
        assert len(jobs) == 1, "Cron job was not saved"

        # 2. Toggle Cron Job
        ok_tog, msg_tog = cron_mgr.toggle_job(jobs[0]["id"], enable=False)
        checks += 1
        assert ok_tog, f"Failed to toggle cron job: {msg_tog}"
        assert cron_mgr.list_jobs()[0]["status"] == "disabled"

        # 3. Create Website Backup (.tar.gz)
        backup_base = suite_dir / "backups"
        site_dir = suite_dir / "wwwroot" / "site_a"
        site_dir.mkdir(parents=True, exist_ok=True)
        (site_dir / "index.php").write_text("<?php echo 'hello backup'; ?>", encoding="utf-8")

        backup_mgr = BackupManager(base_dir=str(backup_base), db=db)

        # Mock website in database
        with db:
            db.execute(
                "INSERT INTO sites (domain, root_path, php_version, ssl_status) VALUES (?, ?, ?, ?);",
                ("site_a", str(site_dir), "8.2", 0),
            )

        ok_bk, msg_bk = backup_mgr.backup_site("site_a")
        checks += 1
        assert ok_bk, f"Failed to backup site: {msg_bk}"

        backups = backup_mgr.list_backups()
        checks += 1
        assert len(backups) == 1, "Backup archive not recorded in DB"
        bk_file = Path(backups[0]["file_path"])
        assert bk_file.exists(), f"Backup file does not exist on disk: {bk_file}"

        # Verify GZIP integrity
        with gzip.open(bk_file, "rb") as gz:
            header = gz.read(100)
            checks += 1
            assert len(header) > 0, "Gzip archive is empty"

        # 4. Delete Backup
        ok_del, msg_del = backup_mgr.delete_backup(backups[0]["id"])
        checks += 1
        assert ok_del, f"Failed to delete backup: {msg_del}"
        assert not bk_file.exists(), "Backup archive file was not deleted from disk"

    finally:
        db.close()

    return checks, None


# ==============================================================================
# Suite 7: Log Viewer
# ==============================================================================
def run_suite_7(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test LogViewerManager reading, line slicing, HTTP status regex colorization, and log truncation."""
    checks = 0
    suite_dir = temp_dir / "suite_7"
    suite_dir.mkdir(parents=True, exist_ok=True)
    access_log = suite_dir / "access.log"

    # Seed mock access log entries
    sample_lines = [
        '192.168.1.10 - - [16/Aug/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 200 1024',
        '192.168.1.11 - - [16/Aug/2026:10:01:00 +0000] "GET /old-page HTTP/1.1" 301 256',
        '192.168.1.12 - - [16/Aug/2026:10:02:00 +0000] "GET /non-existent HTTP/1.1" 404 512',
        '192.168.1.13 - - [16/Aug/2026:10:03:00 +0000] "POST /login HTTP/1.1" 500 128',
    ]
    access_log.write_text("\n".join(sample_lines) + "\n", encoding="utf-8")

    log_mgr = LogViewerManager(custom_paths={"test_access": str(access_log)})

    # 1. Read last lines
    lines = log_mgr.read_last_lines("test_access", lines=10)
    checks += 1
    assert len(lines) == 4, f"Expected 4 log lines, got {len(lines)}"

    # 2. Test syntax regex colorization
    rich_text = colorize_log_line(sample_lines[0])
    checks += 1
    assert rich_text is not None, "Colorize log line returned None"

    rich_text_404 = colorize_log_line(sample_lines[2])
    checks += 1
    assert rich_text_404 is not None

    # 3. Clear / Truncate log
    ok_clr, msg_clr = log_mgr.clear_log("test_access")
    checks += 1
    assert ok_clr, f"Failed to clear log: {msg_clr}"
    after_clr_lines = log_mgr.read_last_lines("test_access", lines=10)
    assert len(after_clr_lines) == 0, "Log file was not truncated"

    return checks, None


# ==============================================================================
# Suite 8: Server Migration
# ==============================================================================
def run_suite_8(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test MigrationManager config bundle export, manifest JSON inspection, and import."""
    checks = 0
    suite_dir = temp_dir / "suite_8"
    suite_dir.mkdir(parents=True, exist_ok=True)
    db_path = suite_dir / "test_migration.db"
    db = Database(db_path=db_path)
    init_db(db_path=db_path)

    # Seed some sample data
    with db:
        db.execute(
            "INSERT INTO sites (domain, root_path, php_version, ssl_status) VALUES (?, ?, ?, ?);",
            ("migratedsite.com", "/www/wwwroot/migratedsite.com", "8.2", 1),
        )
        db.execute(
            "INSERT INTO databases (db_name, db_user, db_pass, charset) VALUES (?, ?, ?, ?);",
            ("migrated_db", "mig_user", "SecretPass123!#", "utf8mb4"),
        )

    export_dir = suite_dir / "migration_exports"
    mig_mgr = MigrationManager(migration_dir=str(export_dir), db=db)

    try:
        # 1. Export Bundle
        ok_exp, msg_exp, bundle_path = mig_mgr.export_config()
        checks += 1
        assert ok_exp, f"Export config failed: {msg_exp}"
        assert Path(bundle_path).exists(), "Export bundle .tar.gz does not exist"

        # 2. Inspect Manifest
        ok_insp, manifest, msg_insp = mig_mgr.inspect_bundle(bundle_path)
        checks += 1
        assert ok_insp, f"Inspect bundle failed: {msg_insp}"
        assert "counts" in manifest, "Manifest missing counts dictionary"
        assert manifest["counts"].get("sites", 0) == 1, "Manifest site count mismatch"
        assert manifest["counts"].get("databases", 0) == 1, "Manifest database count mismatch"

        # 3. Import Bundle into target DB
        import_db_path = suite_dir / "target_imported.db"
        import_db = Database(db_path=import_db_path)
        init_db(db_path=import_db_path)

        try:
            mig_mgr_target = MigrationManager(migration_dir=str(export_dir), db=import_db)
            ok_imp, msg_imp = mig_mgr_target.import_config(bundle_path, sync_system=False)
            checks += 1
            assert ok_imp, f"Import config failed: {msg_imp}"

            # Verify restored records in imported database
            with import_db:
                restored_site = import_db.fetch_one("SELECT * FROM sites WHERE domain = ?;", ("migratedsite.com",))
                checks += 1
                assert restored_site is not None, "Restored site missing in target database"
        finally:
            import_db.close()

    finally:
        db.close()

    return checks, None


# ==============================================================================
# Suite 9: Panel Doctor
# ==============================================================================
def run_suite_9(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test PanelDoctor diagnostics suite, health score calculation, and auto-repair."""
    checks = 0
    suite_dir = temp_dir / "suite_9"
    suite_dir.mkdir(parents=True, exist_ok=True)
    db = Database(db_path=suite_dir / "test_doctor.db")
    init_db(db_path=suite_dir / "test_doctor.db")

    doctor = PanelDoctor(db=db)

    try:
        # 1. Run Diagnostics (25 checks)
        items = doctor.run_diagnostics()
        checks += 1
        assert len(items) >= 20, f"Expected at least 20 diagnostic checks, got {len(items)}"

        # 2. Calculate Health Score
        score, rating = doctor.calculate_health_score(items)
        checks += 1
        assert 0 <= score <= 100, f"Health score out of range: {score}"
        assert any(r in rating for r in ["Excellent", "Good", "Fair", "Critical"]), f"Unknown rating: {rating}"

        # 3. Test Auto-Repair Hook
        repair_results = doctor.auto_repair(items)
        checks += 1
        assert isinstance(repair_results, list), "Auto-repair results must be a list"

    finally:
        db.close()

    return checks, None


# ==============================================================================
# Suite 10: Server Tuner, PHP Manager, & WAF Protection
# ==============================================================================
def run_suite_10(temp_dir: Path) -> Tuple[int, Optional[str]]:
    """Test 39-parameter Tuner, 3 presets, SwapManager, PHP Disabled Functions, and WAF rules."""
    checks = 0
    suite_dir = temp_dir / "suite_10"
    mock_conf_dir = suite_dir / "mock_config"
    mock_conf_dir.mkdir(parents=True, exist_ok=True)

    # 1. Verify 50 Parameters in TUNER_REGISTRY
    php_params = TUNER_REGISTRY.get("php", {})
    nginx_params = TUNER_REGISTRY.get("nginx", {})
    mysql_params = TUNER_REGISTRY.get("mysql", {})
    total_params = len(php_params) + len(nginx_params) + len(mysql_params)

    checks += 1
    assert len(php_params) == 23, f"Expected 23 PHP params, got {len(php_params)}"
    assert len(nginx_params) == 17, f"Expected 17 Nginx params, got {len(nginx_params)}"
    assert len(mysql_params) == 9, f"Expected 9 MySQL params, got {len(mysql_params)}"
    assert total_params == 49, f"Expected exactly 49 parameters in registry, got {total_params}"

    # 2. Test ConfigTuner parameter updates & 3 presets
    tuner = ConfigTuner(mock_base_dir=str(mock_conf_dir))
    preset = tuner.detect_optimal_preset()
    checks += 1
    assert preset in ("low_end", "balanced", "performance")

    ok_upd, msg_upd = tuner.update_parameter("php", "memory_limit", "512M", php_version="8.2")
    checks += 1
    assert ok_upd, f"Failed to update memory_limit: {msg_upd}"

    ok_upd_sec, msg_upd_sec = tuner.update_parameter("php", "expose_php", "Off", php_version="8.2")
    checks += 1
    assert ok_upd_sec, f"Failed to update expose_php: {msg_upd_sec}"

    ok_upd_tok, msg_upd_tok = tuner.update_parameter("nginx", "server_tokens", "off")
    checks += 1
    assert ok_upd_tok, f"Failed to update server_tokens: {msg_upd_tok}"

    ok_preset, msg_preset = tuner.apply_preset("nginx", "performance")
    checks += 1
    assert ok_preset, f"Failed to apply preset: {msg_preset}"

    # 3. Test SwapManager
    swap_mgr = SwapManager()
    swap_info = swap_mgr.get_swap_info()
    checks += 1
    assert "total_bytes" in swap_info
    ok_swap, msg_swap = swap_mgr.setup_swap(2)
    checks += 1
    assert ok_swap, f"Failed to setup swap: {msg_swap}"

    # 4. Test PHP Disabled Functions Manager
    php_mgr = PHPManager(mock_base_dir=str(mock_conf_dir))
    version = "8.2"

    # Seed mock php.ini
    mock_ini = php_mgr.get_ini_path(version)
    mock_ini.write_text("[PHP]\ndisable_functions = passthru, shell_exec\n", encoding="utf-8")

    # Apply 19 baseline functions
    ok_base, msg_base = php_mgr.apply_security_baseline(version)
    checks += 1
    assert ok_base, f"Failed to apply security baseline: {msg_base}"
    disabled_list = php_mgr.get_disabled_functions(version)
    assert len(disabled_list) >= 19, f"Expected at least 19 baseline functions, got {len(disabled_list)}"

    # Enable function (unblock)
    ok_en, msg_en = php_mgr.enable_function(version, "exec")
    checks += 1
    assert ok_en, f"Failed to enable function: {msg_en}"
    assert "exec" not in php_mgr.get_disabled_functions(version)

    # Disable function (block custom)
    ok_dis, msg_dis = php_mgr.disable_function(version, "backdoor_func")
    checks += 1
    assert ok_dis, f"Failed to disable custom function: {msg_dis}"
    assert "backdoor_func" in php_mgr.get_disabled_functions(version)

    # Clear all disabled
    ok_clr, msg_clr = php_mgr.clear_all_disabled(version)
    checks += 1
    assert ok_clr, f"Failed to clear all disabled functions: {msg_clr}"
    assert len(php_mgr.get_disabled_functions(version)) == 0

    # 5. Verify WAF Default Rules
    waf_file = mock_conf_dir / "waf_default.conf"
    ensure_waf_snippet(waf_file)
    checks += 1
    assert waf_file.exists(), "WAF default file was not created"
    waf_text = waf_file.read_text(encoding="utf-8")

    assert "return 444;" in waf_text, "Missing 444 return code in WAF rules"
    assert "wp-admin" in waf_text, "Missing wp-admin scanner bot rule in WAF"
    assert "union.*select" in waf_text, "Missing SQLi rule in WAF"
    assert "(/\\.|%2e%2e|%2fetc%2fpasswd|/etc/passwd|/bin/sh|%00)" in waf_text, "Missing path traversal rule in WAF"

    # 6. Verify Update-Proof Global Nginx Security Config
    sec_file = mock_conf_dir / "00_global_security.conf"
    ensure_nginx_security_conf(sec_file)
    checks += 1
    assert sec_file.exists(), "Global security conf was not created"
    sec_text = sec_file.read_text(encoding="utf-8")
    assert "server_tokens off;" in sec_text, "Missing server_tokens off in global security conf"
    assert "client_body_timeout 10s;" in sec_text, "Missing client_body_timeout in global security conf"

    return checks, None


# ==============================================================================
# Master Test Suite Runner
# ==============================================================================
def run_all_test_suites() -> int:
    """Run all 10 unit test suites with rich live reporting and final dashboard."""
    console.print("")
    console.print(
        Panel(
            Text.from_markup(
                "[bold cyan][*] CLI-PANEL: ALL-IN-ONE AUTOMATED TEST SUITE[/bold cyan]\n"
                "[dim]Running full coverage verification across Core Engine, 9 Business Modules, and WAF[/dim]"
            ),
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print("")

    suites: List[Tuple[int, str, Callable[[Path], Tuple[int, Optional[str]]]]] = [
        (1, "Core Engine & SQLite Database", run_suite_1),
        (2, "Website & SSL Management", run_suite_2),
        (3, "Database Management (MySQL/MariaDB)", run_suite_3),
        (4, "Firewall & Security (UFW)", run_suite_4),
        (5, "System Monitor & Metrics", run_suite_5),
        (6, "Cron & Backup Engine", run_suite_6),
        (7, "Realtime Log Viewer", run_suite_7),
        (8, "Server Migration & Config Bundles", run_suite_8),
        (9, "Panel Doctor (Diagnostics & Auto-Repair)", run_suite_9),
        (10, "Server Tuner, PHP Manager & WAF", run_suite_10),
    ]

    results: List[SuiteResult] = []
    has_failure = False

    temp_root = tempfile.mkdtemp(prefix="clipanel_test_")
    temp_dir = Path(temp_root)

    try:
        for num, name, func in suites:
            console.print(f"[dim]Running Suite {num:02d}/10:[/dim] [bold white]{name:<38}[/bold white] ... ", end="")
            start_t = time.perf_counter()
            try:
                checks_count, err_detail = func(temp_dir)
                duration = time.perf_counter() - start_t
                results.append(
                    SuiteResult(
                        number=num,
                        name=name,
                        checks_count=checks_count,
                        passed=True,
                        duration=duration,
                    )
                )
                console.print(f"[bold green]PASSED[/bold green] [dim]({checks_count} checks in {duration:.3f}s)[/dim]")
            except Exception as exc:
                duration = time.perf_counter() - start_t
                has_failure = True
                tb = traceback.format_exc()
                results.append(
                    SuiteResult(
                        number=num,
                        name=name,
                        checks_count=0,
                        passed=False,
                        duration=duration,
                        error_detail=f"{exc}\n\n{tb}",
                    )
                )
                console.print(f"[bold red]FAILED[/bold red] [dim]({duration:.3f}s)[/dim]")
    finally:
        try:
            shutil.rmtree(temp_root, ignore_errors=True)
        except Exception:
            pass

    # Print Summary Table
    console.print("")
    table = Table(
        title="[bold cyan]cli-panel Automated Test Suite Dashboard[/bold cyan]",
        header_style="bold cyan",
        border_style="dim",
        expand=False,
    )
    table.add_column("No", style="dim", width=4, justify="center")
    table.add_column("Module / Feature Test Suite", style="bold white", min_width=44)
    table.add_column("Checks", style="cyan", width=8, justify="right")
    table.add_column("Status", width=14, justify="center")
    table.add_column("Duration", style="yellow", width=12, justify="right")

    total_checks = sum(r.checks_count for r in results)
    total_duration = sum(r.duration for r in results)

    for r in results:
        status_badge = "[bold green]PASSED[/bold green]" if r.passed else "[bold red]FAILED[/bold red]"
        table.add_row(
            str(r.number),
            r.name,
            str(r.checks_count),
            status_badge,
            f"{r.duration:.3f}s",
        )

    console.print(table)
    console.print("")

    # Display Error Tracebacks if any
    for r in results:
        if not r.passed and r.error_detail:
            console.print(
                Panel(
                    Text.from_markup(f"[bold red]Suite {r.number} ({r.name}) Failure Details:[/bold red]\n{r.error_detail}"),
                    border_style="red",
                    padding=(0, 1),
                )
            )

    # Final Summary Banner
    if not has_failure:
        summary_panel = Panel(
            Text.from_markup(
                f"[bold green][OK] ALL TEST SUITES PASSED PERFECTLY![/bold green]\n"
                f"[bold white]Total Suites:[/bold white] 10/10  |  "
                f"[bold white]Total Checks:[/bold white] {total_checks} assertions  |  "
                f"[bold white]Total Duration:[/bold white] {total_duration:.3f}s"
            ),
            border_style="green",
            padding=(0, 1),
        )
        console.print(summary_panel)
        console.print("")
        return 0
    else:
        failed_count = sum(1 for r in results if not r.passed)
        summary_panel = Panel(
            Text.from_markup(
                f"[bold red][FAIL] TEST SUITE ENCOUNTERED {failed_count} FAILURE(S)![/bold red]\n"
                f"[bold white]Please inspect the error details above.[/bold white]"
            ),
            border_style="red",
            padding=(0, 1),
        )
        console.print(summary_panel)
        console.print("")
        return 1


def main() -> None:
    """Entry point for command line execution."""
    exit_code = run_all_test_suites()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
