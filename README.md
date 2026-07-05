# ReconForge

Penetration testing'in discovery fazı için basit ve etkili bir reconnaissance tool'u. Tek bir domain veya URL vererek otomatik olarak IP çözümü, subdomain keşfi, port taraması, teknoloji tespiti ve hassas dosya kontrolü yapar.

## Kurulum

```bash
# Repoyu klonla
git clone https://github.com/sngzege/ReconForge.git
cd ReconForge

# Python paketi olarak kur (global command olur)
pip install --user --break-system-packages -e .

# External tool'ları kur (Kali'de çoğu zaten kurulu gelir)
sudo apt install subfinder assetfinder nmap whatweb curl
```

## Kullanım

```bash
# Domain ile tarama
reconforge scan example.com

# URL ile tarama
reconforge scan https://example.com

# IP ile tarama
reconforge scan 192.168.1.1

# Çıktı dizinini belirt
reconforge scan example.com --output-dir ./results
```

## Workflow

```
INPUT (domain / URL / IP)
        │
        ▼
┌───────────────────┐
│  normalize_url    │  Input'u normalize eder (protocol, path, port temizler)
└───────┬───────────┘
        │
        ▼
┌───────────────────┐
│  dns_resolver     │  Domain → IP adresleri (IPv4 + IPv6)
└───────┬───────────┘
        │
        ├──────────────────┬──────────────────┐
        ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ subdomain_   │  │ port_scan    │  │ tech_scan    │
│ scan         │  │              │  │              │
│              │  │ nmap         │  │ whatweb      │
│ ┌──────────┐ │  │ top 100 port │  │              │
│ │subfinder │ │  │ servis       │  │ HTTPServer,  │
│ │assetfind.│ │  │ tespiti      │  │ Title,       │
│ │crt.sh    │ │  │ (-sV)        │  │ HTML5,       │
│ └──────────┘ │  │              │  │ framework'ler│
│  paralel     │  │              │  │              │
│  çalışır     │  │              │  │              │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                  │
       │                 │    ┌──────────────┐
       │                 │    │ path_probe   │
       │                 │    │              │
       │                 │    │ curl ile 29  │
       │                 │    │ hassas dosya │
       │                 │    │ kontrolü     │
       │                 │    └──────┬───────┘
       │                 │           │
       └────────┬────────┴───────────┘
                │
                ▼
        ┌───────────────┐
        │  RAPORLAMA    │
        │               │
        │ .md (birleşik)│
        │ .json (detay) │
        │ terminal (özet)│
        └───────────────┘
```

## Kullanılan Tool'lar

| Tool | Kullanım | Detay |
|------|----------|-------|
| **socket** (stdlib) | DNS çözümleme | `getaddrinfo()` ile IPv4 + IPv6 |
| **subfinder** | Subdomain keşfi | `-silent -t 10`, 15s timeout |
| **assetfinder** | Subdomain keşfi | `--subs-only`, 10s timeout |
| **crt.sh** | Subdomain keşfi | Certificate Transparency log API, 5s timeout |
| **nmap** | Port taraması | `-sV -T4 --top-ports 100 -oX -`, servis tespiti, 60s timeout |
| **whatweb** | Teknoloji tespiti | `--log-json=`, HTTPServer, Title, framework, header tespiti, 15s timeout |
| **curl** | Hassas dosya kontrolü | 29 path, 10 paralel thread, 5s timeout/path |

### Path Probe - Kontrol Edilen Dosyalar

```
/robots.txt              /sitemap.xml
/.git/config             /.git/HEAD
/.env                    /.bash_history
/.sh_history             /.htaccess
/.htpasswd               /wp-admin
/wp-login.php            /admin
/login                   /phpmyadmin
/server-status           /server-info
/.well-known/security.txt /crossdomain.xml
/clientaccesspolicy.xml  /api
/swagger.json            /openapi.json
/graphql                 /.vscode/sftp.json
/backup.zip              /db.sql
/dump.sql                /config.php
/web.config
```

## Rapor Formatları

### Markdown Raporu → Birleştirilmiş Bulgular
`output/<target>_report.md` - İnsan okuması için optimize edilmiş, tüm bulgular kategorize edilmiş:

```markdown
## Target
- **Domain:** example.com
- **IPs:** 93.184.216.34

## Subdomains (3)
- www.example.com
- api.example.com

## Open Ports (2)
| Host | Port | Service | Product |
|------|------|---------|---------|
| 93.184.216.34 | 80 | http | nginx |
| 93.184.216.34 | 443 | https | nginx |

## Technologies (3)
- **HTTPServer:** nginx
- **Title:** Example Domain

## Sensitive Paths (1)
| Status | URL | Size |
|--------|-----|------|
| 200 | https://example.com/robots.txt | 1234 bytes |
```

### JSON Raporu → Tool Bazlı Detaylı Çıktılar
`output/<target>_report.json` - Her tool'un tam çıktısı, programatik kullanım için:

```json
{
  "summary": {
    "duration_seconds": 26.22,
    "total_plugins": 6,
    "successful": 6,
    "failed": 0
  },
  "tools": {
    "normalize_url": { "status": "success", "data": "example.com", ... },
    "dns_resolver":  { "status": "success", "data": ["93.184.216.34"], ... },
    "subdomain_scan": { "status": "success", "data": ["www.example.com"], ... },
    "port_scan":     { "status": "success", "data": [{"host": "...", "port": 80}], ... },
    "tech_scan":     { "status": "success", "data": [{"type": "HTTPServer"}], ... },
    "path_probe":    { "status": "success", "data": [{"url": "...", "status_code": 200}], ... }
  }
}
```

### Terminal Çıktısı
Tarama bittiğinde terminalde birleştirilmiş özet gösterilir:

```
======================================================================
RECONFORGE DISCOVERY REPORT
======================================================================

[TARGET INFO]
  Domain: example.com
  IPs: 93.184.216.34

[SUBDOMAINS] (3 found)
  1. www.example.com
  2. api.example.com

[OPEN PORTS] (2 found)
  1. 93.184.216.34:80 (http - nginx)
  2. 93.184.216.34:443 (https - nginx)

[TECHNOLOGIES] (3 detected)
  HTTPServer: nginx
  Title: Example Domain

[SENSITIVE PATHS] (1 found)
  1. [200] https://example.com/robots.txt (1234 bytes)

======================================================================
Total duration: 26.22s
Successful plugins: 6/6
======================================================================
```

## Plugin Yapısı

| Plugin | Tool | Bağımlılık | Açıklama |
|--------|------|------------|----------|
| `normalize_url` | stdlib | - | URL/domain/IP normalize eder |
| `dns_resolver` | stdlib socket | normalize_url | Domain → IP (IPv4 + IPv6) |
| `subdomain_scan` | subfinder + assetfinder + crt.sh | normalize_url | 3 kaynaktan paralel subdomain keşfi |
| `port_scan` | nmap | dns_resolver | Top 100 port, servis/version tespiti |
| `tech_scan` | whatweb | normalize_url, dns_resolver | Web teknolojileri, sunucu, başlık tespiti |
| `path_probe` | curl | normalize_url | 29 hassas dosya/dizin kontrolü (10 paralel) |

## Proje Yapısı

```
src/reconforge/
├── cli.py                     # CLI entry point
├── core/
│   ├── config.py              # TOML + env config
│   ├── loader.py              # Plugin loader
│   ├── logging_setup.py       # Log ayarları
│   ├── pipeline.py            # Dependency-based pipeline
│   ├── plugin.py              # BasePlugin ABC
│   └── result.py              # Result data model
├── plugins/
│   ├── normalize_url.py
│   ├── dns_resolver.py
│   ├── subdomain_scan.py
│   ├── port_scan.py
│   ├── tech_scan.py
│   └── path_probe.py
└── reporting/
    ├── json_reporter.py       # Tool bazlı detaylı JSON
    ├── markdown_reporter.py   # Birleştirilmiş Markdown
    └── reporter.py            # Report orchestrator
```

## Lisans

MIT
