# 🚀 CLI-Panel: Modern, Lightweight Linux Server Control Panel

> **Native Linux Server Management Engine** berbasis Python 3 & Rich TUI. Dirancang khusus untuk efisiensi tinggi pada VPS low-end (RAM 1GB–2GB) hingga server performa tinggi tanpa dependensi kompilasi berat.

---

## 📌 Fitur Utama

- ⚡ **Native APT & FHS Integration:** Menggunakan paket biner resmi OS Linux (`/usr/bin`, `/etc/`, `/var/`) — bebas kompilasi lambat ala aaPanel, update aman via `apt upgrade`.
- 🛡️ **Modular Nginx WAF Engine:** Proteksi otomatis pemutusan koneksi TCP instan (`return 444;`) untuk bot scanner (`/wp-admin`, dsb.), path traversal, SQLi/XSS, dan file sensitif (ekstensi `.json` & `.xml` tetap aman untuk API).
- ⚙️ **3-Tier Config Tuner (39 Parameter):** 1-Click Optimization Presets (Low-End $\le 1.2$GB, Balanced 2–4.5GB, Performance $>4.5$GB), interactive parameter tweak, dan direct raw config editor dengan safety linting (`nginx -t`, `php-fpm -t`).
- 🧠 **Smart Pre-Flight Installer:** Deteksi otomatis software yang sudah terpasang, instalasi hemat sumber daya *single-version* PHP (`8.2`), dan auto-setup Swap memory (`/swapfile`).
- 🔒 **PHP Hardening & Disabled Functions:** Manajemen blacklist fungsi berbahaya interaktif dengan 1-click apply 19 security baseline functions.
- 🩺 **Panel Doctor:** Self-diagnostics dengan 25 item pengecekan kesehatan server, scoring sistem (0–100%), dan auto-repair hook.
- 📦 **Zero-Loss Server Migration:** Ekspor/impor portable bundle `.tar.gz` lengkap dengan `manifest.json` dan snapshot SQLite.

---

## 📂 Struktur Direktori & Arsitektur Sistem

```text
cli-panel/
├── app/
│   ├── core/                  # Engine inti sistem
│   │   ├── database.py        # SQLite state manager (panel.db)
│   │   └── executor.py        # Subprocess runner & safe timeout handler
│   ├── modules/               # 9 Modul logika bisnis
│   │   ├── site.py            # Nginx Virtual Host & Webroot manager
│   │   ├── ssl.py             # Let's Encrypt SSL & OCSP Stapling
│   │   ├── database.py        # MariaDB/MySQL database & user manager
│   │   ├── firewall.py        # UFW firewall & port filtering manager
│   │   ├── system.py          # Real-time resource metrics & services monitor
│   │   ├── cron.py            # Linux crontab job scheduler
│   │   ├── backup.py          # Backup compressor (.tar.gz & .sql.gz)
│   │   ├── log_viewer.py      # Realtime log reader & regex syntax highlighter
│   │   ├── migration.py       # Full server migration bundle exporter/importer
│   │   ├── doctor.py          # 25-Point diagnostics & auto-repair engine
│   │   ├── tuner.py           # 39-Param Config tuner, Presets & Swap manager
│   │   └── php_manager.py     # PHP Extensions & Disabled functions manager
│   ├── ui/                    # Terminal User Interface (TUI)
│   │   ├── views.py           # Rich components, panels, tables, & dashboards
│   │   └── prompts.py         # Interactive user input wizards
│   └── main.py                # Main application entry point & router
├── data/
│   └── panel.db               # Database internal SQLite
├── scripts/
│   └── install_deps.sh        # Smart pre-flight installer & OS dependency setup
├── tests/
│   └── run_all_tests.py       # All-in-One 10-Suite Automated Test Suite
├── requirements.txt           # Python dependencies (rich, psutil, etc.)
└── README.md                  # Dokumentasi teknis proyek
```

### Standar Lokasi Sistem di Linux:

* **Webroot Situs:** `/www/wwwroot/<domain>/`
* **Log Server:** `/www/wwwlogs/` & `/var/log/nginx/`
* **Backup Directory:** `/www/backup/{site,database,migration}/`
* **WAF Snippet:** `/etc/nginx/waf/waf_default.conf`
* **Nginx Vhosts:** `/etc/nginx/sites-available/` & `/etc/nginx/sites-enabled/`
* **PHP-FPM Config:** `/etc/php/<ver>/fpm/php.ini` & `/etc/php/<ver>/fpm/pool.d/www.conf`
* **MariaDB Config:** `/etc/mysql/mariadb.conf.d/50-server.cnf`

---

## 🛠️ Panduan 9 Menu Utama

| Menu | Nama Modul | Deskripsi & Fungsionalitas |
| --- | --- | --- |
| `[1]` | **Website Management** | Tambah/hapus domain, otomatisasi Nginx vhost, multi-PHP socket routing, auto Let's Encrypt SSL, dan integrasi modul WAF. |
| `[2]` | **Database Management** | Manajemen database & user MariaDB/MySQL, generator password acak 16 karakter (aman), dan pengelolaan hak akses. |
| `[3]` | **Firewall & Security** | Buka/tutup port tunggal (misal 80, 443, 2222) atau rentang port (3000:4000) dengan filter protokol TCP/UDP via UFW. |
| `[4]` | **System Monitor** | Pemantauan live hardware (CPU %, RAM %, Disk %, Load Average, Uptime) dan status 4 core services (`nginx`, `mariadb`, `php-fpm`, `ufw`). |
| `[5]` | **Cron & Backups** | Penjadwalan tugas cron Linux, toggle ON/OFF task tanpa hapus, dan pembuatan arsip backup terkompresi `.tar.gz` / `.sql.gz`. |
| `[6]` | **Realtime Log Viewer** | Pembacaan log live-tailing (`tail -f`) & snapshot 50 baris terakhir untuk Nginx access/error, syslog, dan auth log dengan pewarnaan status HTTP. |
| `[7]` | **Server Migration** | Ekspor seluruh server menjadi satu file bundle `.tar.gz` portabel berisi manifest JSON, dump database, dan webroot untuk migrasi server instan. |
| `[8]` | **Panel Doctor** | Menjalankan 25 item audit kesehatan sistem, mendeteksi permission error/service crash, dan perbaikan otomatis (*auto-repair*). |
| `[9]` | **Server Tuning & PHP** | 3-Tier Config Tuner (39 parameter Nginx/PHP/MariaDB), auto-tune RAM, Swap Memory Manager, 1-Click PHP Extensions, dan Dedicated Disabled Functions Manager. |

---

## 🛡️ Nginx WAF & Security Rules (`waf_default.conf`)

Setiap domain yang dibuat otomatis mewarisi proteksi keamanan berikut:

1. **Sensitive File Block (`return 444;`):** Memutus koneksi instan untuk akses `.env`, `.git`, `.sql`, `.bak`, `.sh`, `.conf`, `.jar`, `.aspx`, `.cgi` (ekstensi `.json` & `.xml` tetap dibuka untuk API & sitemap).
2. **Path Traversal & RCE:** Memblokir karakter `%2e%2e`, `/etc/passwd`, `/bin/sh`, dan null byte `%00`.
3. **Scanner Drop:** Mematikan bot pencari CMS/Framework (`wp-admin`, `wp-login`, `actuator`, `geoserver`, `owa`, `ecp`, `cgi-bin`).
4. **SQLi / XSS / Injeksi PHP:** Memblokir query string mengandung `union select`, `pearcmd`, `shell_exec`, `proc_open`, dan debug session.

---

## ⚙️ Ringkasan 39 Parameter Config Tuner

| Layanan | Total Parameter | Parameter Kunci yang Dioptimasi |
| --- | --- | --- |
| **PHP Core & OPcache** | 10 | `memory_limit`, `upload_max_filesize`, `post_max_size`, `max_execution_time`, `max_input_vars`, `max_input_time`, `opcache.enable`, `opcache.memory_consumption`, `opcache.interned_strings_buffer`, `opcache.max_accelerated_files` |
| **PHP-FPM Pool** | 6 | `pm`, `pm.max_children`, `pm.start_servers`, `pm.min_spare_servers`, `pm.max_spare_servers`, `pm.max_requests` |
| **Nginx Web Server** | 13 | `worker_processes`, `worker_connections`, `multi_accept`, `sendfile`, `tcp_nopush`, `tcp_nodelay`, `keepalive_timeout`, `gzip`, `gzip_comp_level`, `client_max_body_size`, `fastcgi_buffer_size`, `fastcgi_buffers`, `fastcgi_read_timeout` |
| **MariaDB Server** | 9 | `innodb_buffer_pool_size`, `key_buffer_size`, `max_connections`, `wait_timeout`, `interactive_timeout`, `max_allowed_packet`, `innodb_flush_log_at_trx_commit`, `tmp_table_size`, `max_heap_table_size` |

---

## 📦 Instalasi & Penggunaan

### 1. Prasyarat Server

* OS: **Ubuntu 22.04 / 24.04 LTS** atau **Debian 11 / 12**
* Akses: **Root / Sudo User**

### 2. Instalasi Cepat (Smart Installer)

```bash
# Clone repository
git clone https://github.com/username/cli-panel.git /www/server/panel
cd /www/server/panel

# Berikan izin eksekusi dan jalankan installer cerdas
chmod +x scripts/install_deps.sh
sudo ./scripts/install_deps.sh
```

### 3. Menjalankan Panel

Setelah instalasi selesai, panel dapat dipanggil langsung dari direktori mana saja:

```bash
mypanel
```

Atau menjalankan self-diagnostic langsung dari CLI:

```bash
mypanel --doctor
```

---

## 🧪 Pengujian Otomatis (Test Suite)

Repositori ini dilengkapi *All-in-One Automated Test Suite* yang mencakup 10 unit suites (57 assertions):

```bash
# Masuk ke virtual environment
source .venv/bin/activate

# Jalankan seluruh rangkaian tes
python tests/run_all_tests.py
```
